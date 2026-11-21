/*
 * smp_server_feed.c
 *
 * Feed one TCP connection of mmt_sec_server with reports, for
 * check/check-smp-server.sh (Montimage fork #31, E3): each connection is
 * served by a forked child running its own SMP workers, and the check sends
 * signals to the child while this client is still streaming. Retries the
 * connect until the server listens.
 *
 * A report on the wire is the 4-byte length of the report (itself included)
 * then: 1 byte of elements count, a 16-byte struct timeval, and for each
 * element proto_id (4), att_id (4), data_length (2) and the data. With
 * PROTO_ID and ATT_ID the reports carry one element of a registered
 * attribute, so the messages reach a worker's ring instead of being dropped
 * at the routing; without them an element count of 0 gives an empty
 * message_t, enough to keep the child's read loop busy.
 *
 * Usage: smp_server_feed PORT [REPORTS] [DELAY_US] [PROTO_ID ATT_ID]
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define REPORT_LEN 35 /* 4 (length) + 1 (count) + 16 (timeval) + 10 (element header) + 4 (data) */

int main( int argc, char **argv ){
	int port, count = 1000, delay_us = 20000, i, fd, len;
	uint32_t proto_id = 0, att_id = 0;
	uint8_t report[ REPORT_LEN ];
	struct sockaddr_in addr;
	struct timeval tv, start;

	if( argc < 2 || argc > 6 || ( argc > 4 && argc != 6 )){
		fprintf( stderr, "usage: %s PORT [REPORTS] [DELAY_US] [PROTO_ID ATT_ID]\n", argv[0] );
		return 2;
	}
	port = atoi( argv[1] );
	if( argc > 2 ) count    = atoi( argv[2] );
	if( argc > 3 ) delay_us = atoi( argv[3] );
	if( argc == 6 ){
		proto_id = (uint32_t) atol( argv[4] );
		att_id   = (uint32_t) atol( argv[5] );
	}

	signal( SIGPIPE, SIG_IGN );

	memset( &addr, 0, sizeof( addr ));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl( INADDR_LOOPBACK );
	addr.sin_port = htons( (uint16_t) port );

	/* wait for the listening socket, at most 10 s */
	gettimeofday( &start, NULL );
	for( ;; ){
		struct timeval now;
		fd = socket( AF_INET, SOCK_STREAM, 0 );
		if( fd < 0 ){
			perror( "socket" );
			return 1;
		}
		if( connect( fd, (struct sockaddr *) &addr, sizeof( addr )) == 0 )
			break;
		close( fd );
		gettimeofday( &now, NULL );
		if( now.tv_sec - start.tv_sec >= 10 ){
			fprintf( stderr, "cannot connect to 127.0.0.1:%d\n", port );
			return 1;
		}
		usleep( 100000 );
	}

	len = proto_id ? REPORT_LEN : 21;
	for( i = 0; i < count; i++ ){
		gettimeofday( &tv, NULL );
		memset( report, 0, sizeof( report ));
		*(uint32_t *) report = len; /* host order, as the server reads it */
		report[4] = proto_id ? 1 : 0;
		memcpy( report + 5, &tv, sizeof( tv ));
		if( proto_id ){
			*(uint32_t *)( report + 21 ) = proto_id;
			*(uint32_t *)( report + 25 ) = att_id;
			*(uint16_t *)( report + 29 ) = 4; /* data length */
			*(uint32_t *)( report + 31 ) = i;
		}
		if( write( fd, report, len ) != len )
			break; /* the child closed the connection (e.g. on a signal) */
		usleep( delay_us );
	}
	close( fd );
	return 0;
}
