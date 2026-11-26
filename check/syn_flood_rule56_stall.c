/*
 * Stalled-lane test of rule 56 (run by check/check-syn-flood-rules.sh).
 *
 * The embedded C of rules/56.syn_flooding.xml is extracted to RULE_C and
 * included here. Three lanes feed it packets on disjoint per-lane streams,
 * as the engine instances of a multi-thread probe do (one calling thread
 * per instance). Lanes B and C stop receiving packets inside the 1 s
 * window — the shape of the harness ooo.pcap at thread-nb 3 — while lane A
 * goes on:
 *
 *  1. 20 SYN-ACKs of a half-open flood on 10.77.1.1:80 are queued at
 *     ~0.5 s: 2 on lane A, 9 on lane B, 9 on lane C; the streams of B and C
 *     then end. Lane A's clock passes 1 s and expires its own two — on the
 *     per-lane design alone the count stalls at 2 and the flood is lost
 *     (PR #73 review, blocking finding). Once lanes B and C have been
 *     silent for EM_SYN56_STALL_US of the shared clock AND their SYN-ACKs
 *     are 1 s + EM_SYN56_STALL_US old on it, lane A takes them out: the
 *     flood is reported once;
 *  2. the same flood of 10.77.2.2:80 is queued 3 on lane A and 17 on the
 *     stalling lanes, but lane A reports it before the stall drain runs:
 *     the 17 late expiries are the same burst (their SYN-ACK times stay
 *     within 200 ms of the counted ones) and must not raise a second
 *     alert after the first was given (the review's second finding);
 *  3. control: lane B resumes — a handshake queued then completed on its
 *     own clock must not alert.
 *
 * On fork main 004554c (one process-wide FIFO expired on the caller's
 * clock) this passes: lane A drains the shared queue itself — the very
 * behaviour whose unbounded version caused the #68 false positives.
 * On head 94a2c92 it fails: the stalled lanes' SYN-ACKs never expire.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <arpa/inet.h>

#define mmt_warn( ... ) ( fprintf( stderr, __VA_ARGS__ ), fputc( '\n', stderr ))
#define mmt_info( ... ) ( fprintf( stderr, __VA_ARGS__ ), fputc( '\n', stderr ))

#include RULE_C

static int packet( uint32_t src, uint32_t dst, int sport, int dport, int flags, uint64_t t_us ){
	struct timeval tv = { (time_t)( 3000000000 + t_us / 1000000 ), (suseconds_t)( t_us % 1000000 ) };
	return em_syn_flood_half_open( &src, &dst, sport, dport, flags, &tv );
}

/* lanes B and C: driven in steps like check/syn_flood_rule56_skew.c */
static pthread_mutex_t ctl_m  = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  ctl_cv = PTHREAD_COND_INITIALIZER;
static int ctl_step, ctl_done;

static int b_resumed = -1;

//n SYN-ACKs of victim v:80, first client port 30000 + base, at t_us + i*10 us
static void synacks( uint32_t v, uint32_t cli0, uint64_t t_us, int n ){
	int i;
	for( i = 0; i < n; i++ )
		packet( v, cli0 + i, 80, 30000 + i, 0x12, t_us + i * 10 );
}

static void *lane_b( void *arg ){
	uint32_t v = inet_addr( "10.77.1.1" ), w = inet_addr( "10.77.2.2" );
	uint32_t cli = inet_addr( "12.1.0.0" ), x = inet_addr( "10.77.9.9" );
	uint32_t clix = inet_addr( "12.9.0.0" );
	int my;
	(void) arg;
	for( my = 1; my <= 2; my++ ){
		pthread_mutex_lock( &ctl_m );
		while( ctl_step < my )
			pthread_cond_wait( &ctl_cv, &ctl_m );
		pthread_mutex_unlock( &ctl_m );
		if( my == 1 ){
			//lane B's shares of the two floods, then its stream ends inside
			//the 1 s window (it is silent for the rest of the run)
			synacks( v, cli, 500100, 9 );
			synacks( w, cli, 500200, 9 );
		}else{
			//control: lane B resumes — a handshake queued and completed on
			//its own clock must not alert
			packet( x, clix, 80, 31000, 0x12, 6000000 );
			packet( clix, x, 31000, 80, 0x10, 6000100 );
			b_resumed = packet( clix, x, 31000, 80, 0x10, 8000000 );
		}
		pthread_mutex_lock( &ctl_m );
		ctl_done ++;
		pthread_cond_broadcast( &ctl_cv );
		pthread_mutex_unlock( &ctl_m );
	}
	return NULL;
}

static void *lane_c( void *arg ){
	uint32_t v = inet_addr( "10.77.1.1" ), w = inet_addr( "10.77.2.2" );
	uint32_t cli = inet_addr( "12.2.0.0" );
	(void) arg;
	pthread_mutex_lock( &ctl_m );
	while( ctl_step < 1 )
		pthread_cond_wait( &ctl_cv, &ctl_m );
	pthread_mutex_unlock( &ctl_m );
	//lane C's shares; its stream ends here, inside the 1 s window
	synacks( v, cli, 500300, 9 );
	synacks( w, cli, 500400, 8 );
	pthread_mutex_lock( &ctl_m );
	ctl_done ++;
	pthread_cond_broadcast( &ctl_cv );
	pthread_mutex_unlock( &ctl_m );
	return NULL;
}

static void run_lanes( int step, int done ){
	pthread_mutex_lock( &ctl_m );
	ctl_step = step;
	pthread_cond_broadcast( &ctl_cv );
	while( ctl_done < done )
		pthread_cond_wait( &ctl_cv, &ctl_m );
	pthread_mutex_unlock( &ctl_m );
}

int main(){
	uint32_t v = inet_addr( "10.77.1.1" ), w = inet_addr( "10.77.2.2" );
	uint32_t cli = inet_addr( "12.0.0.0" ), other = inet_addr( "12.9.9.9" );
	pthread_t thb, thc;
	int v_early, v_alerts = 0, w_alerts = 0;

	on_load(); //the hash seed of this process
	pthread_create( &thb, NULL, lane_b, NULL );
	pthread_create( &thc, NULL, lane_c, NULL );

	//1. lane A's shares of the floods of v:80 and w:80 at its packet time ~0.5 s
	synacks( v, cli, 500000, 2 );
	synacks( w, cli, 500020, 3 );
	//lanes B and C queue their shares (18 + 17) and stop receiving packets
	run_lanes( 1, 2 );
	//lane A goes on: its own 5 SYN-ACKs expire on its own clock — w's count
	//reaches 3, v's stalls at 2
	packet( other, other, 1000, 8080, 0x02, 1600000 );
	w_alerts += packet( other, w, 40000, 80, 0x02, 1700000 ); //w's alert reports
	//lanes B and C are then silent for more than EM_SYN56_STALL_US of the
	//shared clock, but their SYN-ACKs are not yet 1 s + EM_SYN56_STALL_US old
	//on it: the bounded drain does not fire early (on fork main the shared
	//FIFO raised and reported the flood already, and this packet gives 1)
	v_early = packet( other, v, 40000, 80, 0x02, 2600000 );
	v_alerts += v_early;
	//at 3.6 s of the shared clock both bounds have passed: the calling lane
	//takes the stalled SYN-ACKs out — v's 18 raise its alert at last, w's 17
	//are the reported burst again and must not re-raise it
	packet( other, other, 1000, 8080, 0x02, 3600000 );
	v_alerts += packet( other, v, 40000, 80, 0x02, 4000000 );
	w_alerts += packet( other, w, 40000, 80, 0x02, 4100000 );
	v_alerts += packet( other, v, 40000, 80, 0x02, 6000000 );
	w_alerts += packet( other, w, 40000, 80, 0x02, 6100000 );
	printf( "  flood of v:80 reported while its stalled SYN-ACKs were still under 3 s old: %d alert(s)\n", v_early );
	printf( "  18 of 20 SYN-ACKs of v:80 on lanes that stopped at 0.5 s: %d alert(s) in all\n", v_alerts );
	printf( "  17 late expiries of the reported burst of w:80: %d alert(s) in all\n", w_alerts );

	//2. control: lane B resumes after the drain and completes a handshake
	run_lanes( 2, 3 );
	packet( other, other, 1000, 8080, 0x02, 8200000 ); //nothing pending for x:80
	printf( "  handshake completed on lane B resumed after the drain: %d alert(s)\n", b_resumed );
	//the shared clock passes the tombstone bound (1 s + EM_SYN56_STALL_US +
	//EM_SYN56_HOLD_US of age): dead lanes' provisionally counted entries are
	//recycled at last
	packet( other, other, 1000, 8080, 0x02, 12000000 );
	printf( "  pool entries still held at the end: %u\n", em_syn56_size );

	pthread_join( thb, NULL );
	pthread_join( thc, NULL );
	//the flood is still reported, and exactly once: base reaches v_alerts = 1
	//through v_early (the shared FIFO expires everything on lane A's clock),
	//the fix through the bounded stall drain, 94a2c92 misses it entirely
	return !( v_alerts == 1 && w_alerts == 1 && b_resumed == 0 && em_syn56_size == 0 );
}
