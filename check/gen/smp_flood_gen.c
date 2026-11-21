/*
 * smp_flood_gen.c
 *
 * Generate the pcap used by the "-c 1-8" leg of check/check-smp.sh (Montimage
 * fork #31, E3): a 20 000-SYN flood in 1 s - each SYN answered by a SYN-ACK,
 * then reset by its client - followed by 1.5 s of benign completed handshakes
 * between two other hosts. On aarch64 this used to hang mmt_sec_standalone
 * `-c 1-8` on every run: a missing release fence in the SPSC ring let a
 * worker pop a stale message_t, corrupt the heap, abort, and the abort's
 * signal handler then deadlocked trying to join the workers. Written in C so
 * `make check` needs no scapy/python; the output is deterministic.
 *
 * Usage: smp_flood_gen OUT.pcap [SYN_COUNT]  (default 20000)
 */
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define T0 1795180000.0
#define PKT_LEN 54 /* Ethernet + IPv4 + TCP, no payload */

static uint8_t  CLI_MAC[6] = {0x02, 0, 0, 0, 0, 0x20};
static uint8_t  SRV_MAC[6] = {0x02, 0, 0, 0, 0, 0x10};

static uint32_t rng_state = 24;
static uint32_t rnd(void){ /* xorshift32, deterministic */
	uint32_t x = rng_state;
	x ^= x << 13; x ^= x >> 17; x ^= x << 5;
	rng_state = x;
	return x;
}

static uint32_t sum16( const uint8_t *data, size_t len ){
	uint32_t s = 0;
	for( ; len > 1; len -= 2, data += 2 )
		s += (uint16_t)(( data[0] << 8 ) | data[1]);
	if( len )
		s += (uint16_t)( data[0] << 8 );
	return s;
}

static uint16_t cksum( uint32_t s ){
	while( s >> 16 )
		s = ( s & 0xffff ) + ( s >> 16 );
	return (uint16_t) ~s;
}

static uint32_t ipaddr( const char *s ){
	unsigned a, b, c, d;
	sscanf( s, "%u.%u.%u.%u", &a, &b, &c, &d );
	return ( a << 24 ) | ( b << 16 ) | ( c << 8 ) | d;
}

/* the generated packets, sorted by timestamp before being written */
struct rec {
	int64_t  t_us;
	uint32_t order;
	uint8_t  frame[ PKT_LEN ];
};
static struct rec *recs;
static size_t    recs_count, recs_cap;

/* one Ethernet/IPv4/TCP packet, 54 bytes */
static void pkt( double t, const char *src, const char *dst, uint16_t sport,
		uint16_t dport, uint8_t flags, uint32_t seq, uint32_t ack, int to_server ){
	struct rec *r;
	uint8_t  *ip, *tcp, pseudo[12];
	uint16_t check;
	uint32_t saddr, daddr;

	if( recs_count == recs_cap ){
		recs_cap = recs_cap ? recs_cap * 2 : 1 << 16;
		recs = realloc( recs, recs_cap * sizeof( *recs ));
		if( recs == NULL ){
			perror( "realloc" );
			exit( 1 );
		}
	}
	r = &recs[ recs_count ];
	r->t_us  = (int64_t)(( t - T0 ) * 1000000 );
	r->order = recs_count;
	memset( r->frame, 0, PKT_LEN );

	memcpy( r->frame,     to_server ? SRV_MAC : CLI_MAC, 6 );
	memcpy( r->frame + 6, to_server ? CLI_MAC : SRV_MAC, 6 );
	r->frame[12] = 0x08; /* EtherType IPv4, big-endian */

	saddr = htonl( ipaddr( src ));
	daddr = htonl( ipaddr( dst ));
	ip   = r->frame + 14;
	tcp  = ip + 20;
	ip[0] = 0x45; /* v4, IHL 5 */
	ip[2] = 0; ip[3] = PKT_LEN - 14; /* total length */
	ip[6] = 0x40; /* don't fragment */
	ip[8] = 64;   /* TTL */
	ip[9] = 6;    /* TCP */
	memcpy( ip + 12, &saddr, 4 );
	memcpy( ip + 16, &daddr, 4 );
	check = cksum( sum16( ip, 20 ));
	ip[10] = check >> 8; ip[11] = check & 0xff;

	*(uint16_t *)( tcp + 0 ) = htons( sport );
	*(uint16_t *)( tcp + 2 ) = htons( dport );
	*(uint32_t *)( tcp + 4 ) = htonl( seq );
	*(uint32_t *)( tcp + 8 ) = htonl( ack );
	tcp[12] = 0x50; /* data offset 5 */
	tcp[13] = flags;
	*(uint16_t *)( tcp + 14 ) = htons( 64240 );
	/* TCP checksum over the pseudo-header and the segment */
	memcpy( pseudo, ip + 12, 8 );
	pseudo[8] = 0; pseudo[9] = 6;
	pseudo[10] = 0; pseudo[11] = 20;
	check = cksum( sum16( pseudo, 12 ) + sum16( tcp, 20 ));
	tcp[16] = check >> 8; tcp[17] = check & 0xff;

	recs_count ++;
}

static int cmp_rec( const void *a, const void *b ){
	const struct rec *ra = a, *rb = b;
	if( ra->t_us != rb->t_us )
		return ra->t_us < rb->t_us ? -1 : 1;
	return ra->order < rb->order ? -1 : 1; /* stable: keep the emission order */
}

int main( int argc, char **argv ){
	uint32_t ghdr[6], hdr[4];
	FILE *f;
	long i, count = 20000;
	int k;
	size_t n;
	uint16_t sport;
	uint32_t seq_cli, seq_srv;

	if( argc < 2 || argc > 3 ){
		fprintf( stderr, "usage: %s OUT.pcap [SYN_COUNT]\n", argv[0] );
		return 1;
	}
	if( argc == 3 )
		count = atol( argv[2] );

	/* the SYNs over 1 s to 172.31.77.10:80 from one real source; each is
	 * answered by a SYN-ACK, then reset by the client. One connection every
	 * 50 us, its 3 packets at +0, +100, +200 us: they overlap the next
	 * connections, and the stream is sorted by timestamp afterwards. */
	for( i = 0; i < count; i++ ){
		double t  = T0 + i * 0.00005;
		sport     = (uint16_t)( 1024 + rnd() % 64512 );
		seq_cli   = rnd();
		seq_srv   = rnd();
		pkt( t,         "172.31.77.20", "172.31.77.10", sport, 80, 0x02, seq_cli, 0, 1 );
		pkt( t + 0.0001, "172.31.77.10", "172.31.77.20", 80, sport, 0x12, seq_srv, seq_cli + 1, 0 );
		pkt( t + 0.0002, "172.31.77.20", "172.31.77.10", sport, 80, 0x04, seq_cli + 1, 0, 1 );
	}

	/* tail: benign completed handshakes between two other hosts, every 10 ms
	 * for 1.5 s (the flood is done, the capture must not be) */
	for( k = 0; k < 150; k++ ){
		double t  = T0 + count * 0.00005 + 0.05 + k * 0.01;
		sport     = (uint16_t)( 20000 + k );
		seq_cli   = rnd();
		seq_srv   = rnd();
		pkt( t,         "10.5.5.5", "10.6.6.6", sport, 443, 0x02, seq_cli, 0, 1 );
		pkt( t + 0.001, "10.6.6.6", "10.5.5.5", 443, sport, 0x12, seq_srv, seq_cli + 1, 0 );
		pkt( t + 0.002, "10.5.5.5", "10.6.6.6", sport, 443, 0x10, seq_cli + 1, seq_srv + 1, 1 );
	}

	qsort( recs, recs_count, sizeof( *recs ), cmp_rec );

	f = fopen( argv[1], "wb" );
	if( f == NULL ){
		perror( argv[1] );
		return 1;
	}
	/* pcap global header: magic, v2.4, GMT, snaplen, linktype Ethernet */
	ghdr[0] = 0xa1b2c3d4; ghdr[1] = ( 4 << 16 ) | 2; ghdr[2] = 0; ghdr[3] = 0;
	ghdr[4] = 65535; ghdr[5] = 1;
	fwrite( ghdr, sizeof( uint32_t ), 6, f );

	for( n = 0; n < recs_count; n++ ){
		int64_t t = T0 * 1000000 + recs[n].t_us;
		hdr[0] = (uint32_t)( t / 1000000 );
		hdr[1] = (uint32_t)( t % 1000000 );
		hdr[2] = hdr[3] = PKT_LEN;
		fwrite( hdr, sizeof( uint32_t ), 4, f );
		fwrite( recs[n].frame, 1, PKT_LEN, f );
	}
	free( recs );

	if( fclose( f )){
		perror( argv[1] );
		return 1;
	}
	return 0;
}
