/*
 * Thread test of rule 57's SYN counter (run by check/check-syn-flood-rules.sh).
 *
 * The embedded C of rules/57.syn_flood_rate.xml is extracted to RULE_C and
 * included here. THREADS threads count SYNs to one destination, all at the
 * same time, so all in one window, THRESHOLD SYNs in total: the threshold is
 * reached exactly once. An unprotected count++ loses increments when the
 * threads race, and the alert is then missed (or given twice).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>

#define mmt_warn( ... ) ( fprintf( stderr, __VA_ARGS__ ), fputc( '\n', stderr ))
#define mmt_info( ... ) ( fprintf( stderr, __VA_ARGS__ ), fputc( '\n', stderr ))

#include RULE_C

#define THREADS   8
#define THRESHOLD 400000
#define ROUNDS    5

static uint8_t        dst[4] = { 192, 168, 1, 10 };
static struct timeval now;
static int            alerts[ THREADS ];

static void *count_syn( void *arg ){
	int id = (int)(intptr_t) arg, i;
	for( i = 0; i < THRESHOLD / THREADS; i++ )
		alerts[ id ] += em_syn_flood_rate_reached( dst, 80, &now );
	return NULL;
}

int main(){
	pthread_t th[ THREADS ];
	int r, i, total, failed = 0;
	char value[ 32 ];

	snprintf( value, sizeof( value ), "%d", THRESHOLD );
	setenv( "MMT_SEC_SYN_FLOOD_THRESHOLD", value, 1 );
	on_load();
	for( r = 0; r < ROUNDS; r++ ){
		//a new window for each round
		now.tv_sec = 1000 + 10 * r;
		memset( alerts, 0, sizeof( alerts ));
		for( i = 0; i < THREADS; i++ )
			pthread_create( &th[i], NULL, count_syn, (void *)(intptr_t) i );
		total = 0;
		for( i = 0; i < THREADS; i++ ){
			pthread_join( th[i], NULL );
			total += alerts[i];
		}
		printf( "  round %d: %d threads, %d SYN, %d alert(s)\n", r + 1, THREADS, THRESHOLD, total );
		failed |= ( total != 1 );
	}
	return failed;
}
