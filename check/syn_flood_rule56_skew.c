/*
 * Cross-instance clock-skew test of rule 56 (run by check/check-syn-flood-rules.sh).
 *
 * The embedded C of rules/56.syn_flooding.xml is extracted to RULE_C and
 * included here. Two lanes feed it packets, as the engine instances of a
 * multi-thread probe do (one calling thread per instance: a probe security
 * thread, a -c worker of mmt_sec_standalone, or the worker thread itself when
 * the engine runs inline). Each lane is stepped deterministically.
 *
 *  1. lane A queues the SYN-ACKs of 3 handshakes to 10.77.0.1:80; lane B's
 *     packets are then more than 1 s ahead in packet time; lane A's clients
 *     then complete their handshakes a few microseconds after their SYN-ACK.
 *     When the process-wide FIFO expired pending SYN-ACKs on the packet time
 *     of whichever instance called (fork issue #68), lane B's clock popped
 *     them before their ACK was seen: the next packet to the port reported a
 *     false alert. The count must be 0;
 *  2. control: lane A leaves the handshakes of 10.77.0.2:80 half-open (the
 *     clients never answer) — its own clock passes 1 s and the alert must
 *     still be given;
 *  3. the per-port half-open count is shared by the lanes: 2 half-open
 *     handshakes of 10.77.0.3:80 on lane A plus 1 on lane B must still alert;
 *  4. the "one alert per server port per second" limit is measured on the
 *     highest packet time any lane has seen: lane B reports the alert of its
 *     flood of 10.77.0.4:80, then lane A's own flood of the same port raises
 *     another alert — lane A's packets, behind in packet time, must not
 *     report it before 1 s of shared time has passed (when the report dedup
 *     was on the calling lane's clock, such a packet reported at once: a
 *     duplicate alert — #68), and must still report it once it has.
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

/* the lane of the second engine instance: steps 1 and 2, driven in order */
static pthread_mutex_t ctl_m  = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  ctl_cv = PTHREAD_COND_INITIALIZER;
static int ctl_step, ctl_done;

static int b_report;

static void *lane_b( void *arg ){
	uint32_t x = inet_addr( "10.200.0.1" ), y = inet_addr( "10.200.0.2" );
	uint32_t v3 = inet_addr( "10.77.0.3" ), v4 = inet_addr( "10.77.0.4" );
	uint32_t cli4 = inet_addr( "12.4.0.0" );
	int my, i;
	(void) arg;
	for( my = 1; my <= 3; my++ ){
		pthread_mutex_lock( &ctl_m );
		while( ctl_step < my )
			pthread_cond_wait( &ctl_cv, &ctl_m );
		pthread_mutex_unlock( &ctl_m );
		if( my == 1 ){
			//lane B runs more than 1 s ahead of lane A in packet time: on the
			//shared FIFO these calls expired lane A's pending SYN-ACKs at once
			for( i = 0; i < 4; i++ )
				packet( x, y, 10000 + i, 8080, 0x02, 2000000 + i * 100 );
		}else if( my == 2 ){
			//one half-open handshake of 10.77.0.3:80 queued on lane B
			//(its SYN-ACK within 200 ms of lane A's two), then expired by
			//lane B's own clock
			packet( y, v3, 44444, 80, 0x02, 20000000 );
			packet( v3, y, 80, 44444, 0x12, 20000100 );
			packet( x, y, 10000, 8080, 0x02, 26000000 );
		}else{
			//lane B's own flood of 10.77.0.4:80, at its packet time ~40 s:
			//3 half-open handshakes expired on lane B's clock, the alert
			//reported on lane B's next packet to the port
			for( i = 0; i < 3; i++ ){
				packet( cli4 + i, v4, 35000 + i, 80, 0x02, 40000000 + i * 10 );
				packet( v4, cli4 + i, 80, 35000 + i, 0x12, 40000000 + i * 10 + 1 );
			}
			packet( x, y, 10000, 8080, 0x02, 41050000 );
			b_report = packet( x, v4, 45000, 80, 0x02, 41100000 );
		}
		pthread_mutex_lock( &ctl_m );
		ctl_done = my;
		pthread_cond_broadcast( &ctl_cv );
		pthread_mutex_unlock( &ctl_m );
	}
	return NULL;
}

static void run_b( int step ){
	pthread_mutex_lock( &ctl_m );
	ctl_step = step;
	pthread_cond_broadcast( &ctl_cv );
	while( ctl_done < step )
		pthread_cond_wait( &ctl_cv, &ctl_m );
	pthread_mutex_unlock( &ctl_m );
}

//lane A: 3 handshakes to v:80, SYN-ACKs at t_us + 0,10,20 us, completing ACKs withheld
static void synacks( uint32_t v, uint32_t cli0, uint64_t t_us, int n ){
	int i;
	for( i = 0; i < n; i++ ){
		packet( cli0 + i, v, 30000 + i, 80, 0x02, t_us + i * 10 );
		packet( v, cli0 + i, 80, 30000 + i, 0x12, t_us + i * 10 + 1 );
	}
}

int main(){
	uint32_t v1 = inet_addr( "10.77.0.1" ), v2 = inet_addr( "10.77.0.2" ), v3 = inet_addr( "10.77.0.3" );
	uint32_t cli = inet_addr( "12.0.0.0" ), other = inet_addr( "12.9.9.9" );
	pthread_t th;
	int i, skewed = 0, flood = 0, shared = 0;

	on_load(); //the hash seed of this process
	pthread_create( &th, NULL, lane_b, NULL );

	//1. lane A queues 3 pending handshakes of v1:80 at its packet time ~0
	synacks( v1, cli, 100, 3 );
	//lane B runs more than 1 s ahead: only it calls the rule meanwhile
	run_b( 1 );
	//lane A's clients complete their handshakes 300 us after the SYN-ACK;
	//every packet to v1:80 reports a pending alert, these ACKs included
	for( i = 0; i < 3; i++ )
		skewed += packet( cli + i, v1, 30000 + i, 80, 0x10, 300 + i * 10 );
	//lane A goes on; at its t = 3 s a packet to v1:80 reports any pending alert
	skewed += packet( other, v1, 40000, 80, 0x02, 3000000 );
	printf( "  3 handshakes completed on lane A while lane B was 2 s ahead: %d alert(s)\n", skewed );

	//2. control on lane A alone: 3 handshakes of v2:80 left half-open
	synacks( v2, cli + 100, 10000000, 3 );
	packet( other, other, 1000, 8080, 0x02, 12000000 );      //their 1 s passes on lane A
	flood = packet( other, v2, 40000, 80, 0x02, 12100000 ); //the next packet to the port reports
	printf( "  control, 3 half-open handshakes of v2:80 on lane A: %d alert(s)\n", flood );

	//3. shared per-port count: 2 half-open on lane A + 1 on lane B, all to v3:80
	synacks( v3, cli + 200, 20000000, 2 );
	run_b( 2 );                                             //lane B's one is expired by its own clock
	packet( other, other, 1000, 8080, 0x02, 26000000 );     //lane A's two, on its own clock
	shared = packet( other, v3, 40000, 80, 0x02, 26500000 );
	printf( "  2 half-open on lane A + 1 on lane B, all to v3:80: %d alert(s)\n", shared );

	//4. report dedup on the shared clock: lane B floods v4:80 and reports its
	//alert at shared time ~41.1 s; lane A's own flood of the same port raises
	//another alert while lane A's clock is ~30 s — a packet to the port on the
	//lagging lane must not re-report (old code: now < reported_ts reported it
	//at once), and the pending alert must still report 1 s of shared time later
	uint32_t v4 = inet_addr( "10.77.0.4" );
	int dedup0, dedup1;
	run_b( 3 );                                             //lane B's flood of v4:80, alert reported
	synacks( v4, cli + 300, 30000000, 3 );
	packet( other, other, 1000, 8080, 0x02, 31050000 );     //they expire on lane A's clock: alert
	dedup0 = packet( other, v4, 40000, 80, 0x02, 31200000 );//lane A is behind: must not report
	packet( other, other, 1000, 8080, 0x02, 42200000 );     //the shared clock passes 42.1 s
	dedup1 = packet( other, v4, 40000, 80, 0x02, 42300000 );//the pending alert reports now
	printf( "  alert of a lagging lane's flood, inside the 1 s dedup: %d alert(s), after it: %d alert(s)\n",
			dedup0, dedup1 );
	printf( "  lane B's report of its own flood: %d alert(s)\n", b_report );

	pthread_join( th, NULL );
	return !( skewed == 0 && flood == 1 && shared == 1
			&& b_report == 1 && dedup0 == 0 && dedup1 == 1 );
}
