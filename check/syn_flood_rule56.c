/*
 * Tests of rule 56's C (run by check/check-syn-flood-rules.sh).
 *
 * The embedded C of rules/56.syn_flooding.xml is extracted to RULE_C and
 * included here, and fed packets directly (a pcap of this size would be
 * 20 MB):
 *  1. a busy server, 10.9.9.9:443, gets 100 000 new connections in 1 s (more
 *     than the 65536 SYN-ACKs that the FIFO holds) and every client completes
 *     its handshake 0.8 s after the SYN-ACK. No handshake is half-open, so
 *     there must be no alert. Counting a pending handshake taken out of a full
 *     FIFO before its 1 s gave thousands of false alerts;
 *  2. control: a spoofed flood, 300 SYN/s for 2 s to 172.31.77.10:80 (no
 *     client answers), must be reported;
 *  3. the victim is the destination of the reported packet: after 5 spoofed
 *     half-open handshakes of 172.31.90.10:80, the server's retransmitted
 *     SYN-ACK (a packet from that port) must not be reported, and the next
 *     SYN to that port must be.
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

#define STEP_US 10   //100 000 packets per second

static int packet( uint32_t src, uint32_t dst, int sport, int dport, int flags, uint64_t t_us ){
	struct timeval tv = { (time_t)( 2000000000 + t_us / 1000000 ), (suseconds_t)( t_us % 1000000 ) };
	return em_syn_flood_half_open( &src, &dst, sport, dport, flags, &tv );
}

int main(){
	uint32_t busy = inet_addr( "10.9.9.9" ), victim = inet_addr( "172.31.77.10" ), cli;
	long i, j, alerts = 0, control = 0;
	uint64_t t;

	on_load(); //the hash seed of this process
	//1. 100 000 completed handshakes in 1 s, the ACK 0.8 s after the SYN-ACK, then 1 s of SYNs to that port
	for( i = 0; i < 280000; i++ ){
		t = (uint64_t) i * STEP_US;
		if( i < 100000 ){
			cli = htonl( 0x0C000000 + i );
			alerts += packet( cli, busy, 1024 + i % 60000, 443, 0x02, t );
			alerts += packet( busy, cli, 443, 1024 + i % 60000, 0x12, t );
		}
		j = i - 80000;
		if( j >= 0 && j < 100000 ){
			cli = htonl( 0x0C000000 + j );
			alerts += packet( cli, busy, 1024 + j % 60000, 443, 0x10, t );
		}
		//later SYNs to the busy port (that get their SYN-ACK and ACK), to report any pending alert
		if( i >= 100000 && i % 1000 == 0 ){
			cli = htonl( 0x0E000000 + i );
			alerts += packet( cli, busy, 2000, 443, 0x02, t );
			alerts += packet( busy, cli, 443, 2000, 0x12, t );
			alerts += packet( cli, busy, 2000, 443, 0x10, t + 1 );
		}
	}
	printf( "  100000 completed handshakes in 1 s, ACK 0.8 s after the SYN-ACK: %ld alert(s)\n", alerts );

	//2. control, much later: a spoofed flood
	for( i = 0; i < 600; i++ ){
		t = 100000000 + (uint64_t) i * 3333;
		cli = htonl( 0x0D000000 + i );
		control += packet( cli, victim, 30000 + i, 80, 0x02, t );
		control += packet( victim, cli, 80, 30000 + i, 0x12, t + 100 );
	}
	printf( "  control, spoofed flood of 300 SYN/s for 2 s: %ld alert(s)\n", control );

	//3. reported on a packet to the server port only
	uint32_t srv = inet_addr( "172.31.90.10" );
	int from_srv, to_srv;
	for( i = 0; i < 5; i++ ){
		t = 200000000 + (uint64_t) i * 10000;
		cli = htonl( 0x0F000000 + i );
		packet( cli, srv, 40000 + i, 80, 0x02, t );
		packet( srv, cli, 80, 40000 + i, 0x12, t + 100 );
	}
	t = 200000000 + 1500000;
	cli = htonl( 0x0F000000 );
	from_srv = packet( srv, cli, 80, 40000, 0x12, t );                     //SYN-ACK retransmission
	to_srv   = packet( htonl( 0x0F0000FF ), srv, 41000, 80, 0x02, t + 10 ); //next SYN to the port
	printf( "  5 half-open handshakes, then a packet from the server port: %d alert(s), then one to it: %d alert(s)\n",
		from_srv, to_srv );
	return !( alerts == 0 && control > 0 && from_srv == 0 && to_srv == 1 );
}
