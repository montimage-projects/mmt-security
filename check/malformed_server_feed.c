/*
 * malformed_server_feed.c
 *
 * Feed one UNIX-domain connection of mmt_sec_server with reports whose
 * announced lengths do not match the data that follows them, for the
 * mmt_sec_server leg of check/check-server-malformed.sh.
 *
 * A report on the wire is the 4-byte length of the report (itself
 * included) then: 1 byte of elements count, a 16-byte struct timeval, and
 * for each element proto_id (4), att_id (4), data_length (2) and the data.
 * A well-formed report carries its elements exactly: each malformed
 * report below breaks one of those invariants and must be refused without
 * stopping the server, so a valid report follows each of them, on the
 * same connection when the wire stays synchronized or on a fresh one
 * otherwise, and the run must produce one alert per valid report.
 *
 * Usage: malformed_server_feed SOCKET_PATH
 */
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

static int conn( const char *path ){
	int fd;
	struct sockaddr_un addr;
	struct timeval start, now;
	memset( &addr, 0, sizeof( addr ));
	addr.sun_family = AF_UNIX;
	strncpy( addr.sun_path, path, sizeof( addr.sun_path ) - 1 );
	gettimeofday( &start, NULL );
	for( ;; ){
		fd = socket( AF_UNIX, SOCK_STREAM, 0 );
		if( fd < 0 ){ perror( "socket" ); exit( 1 ); }
		if( connect( fd, (struct sockaddr *) &addr, sizeof( addr )) == 0 )
			return fd;
		close( fd );
		gettimeofday( &now, NULL );
		if( now.tv_sec - start.tv_sec >= 10 ){
			fprintf( stderr, "cannot connect to unix:%s\n", path );
			exit( 1 );
		}
		usleep( 100000 );
	}
}

static void put_u32( uint8_t *r, size_t *ix, uint32_t v ){
	memcpy( r + *ix, &v, 4 ); *ix += 4;
}

/* an element header only: the announced data_length does not imply that
 * this many data bytes follow */
static void put_el_hdr( uint8_t *r, size_t *ix, uint32_t p, uint32_t a, uint16_t l ){
	put_u32( r, ix, p );
	put_u32( r, ix, a );
	memcpy( r + *ix, &l, 2 ); *ix += 2;
}

static void put_el( uint8_t *r, size_t *ix, uint32_t p, uint32_t a, uint16_t l, const void *d ){
	put_el_hdr( r, ix, p, a, l );
	if( l ) memcpy( r + *ix, d, l );
	*ix += l;
}

static void patch_len( uint8_t *r, size_t ix ){
	uint32_t total = (uint32_t) ix;
	memcpy( r, &total, 4 );
}

static void send_all( int fd, const void *buf, size_t len ){
	const uint8_t *p = buf;
	while( len ){
		ssize_t n = write( fd, p, len );
		if( n <= 0 ) return;
		p += n; len -= (size_t) n;
	}
}

/* one valid report carrying the four attributes of rule 13:
 * tcp.flags == 2 && tcp.payload_len > 0 && ip.src != ip.dst */
static size_t valid_report( uint8_t *r ){
	size_t ix = 4;
	const struct timeval tv = { .tv_sec = 1700000000, .tv_usec = 123456 };
	uint8_t u8 = 2;
	uint32_t u32 = 20;
	r[ ix ++ ] = 4;
	memcpy( r + ix, &tv, sizeof( tv )); ix += sizeof( tv );
	put_el( r, &ix, 354, 6, 1, &u8 );              /* tcp.flags = SYN */
	put_el( r, &ix, 354, 27, 4, &u32 );            /* tcp.payload_len */
	put_el( r, &ix, 178, 13, 4, "\x01\x02\x03\x04" ); /* ip.src */
	put_el( r, &ix, 178, 14, 4, "\x05\x06\x07\x08" ); /* ip.dst */
	patch_len( r, ix );
	return ix;
}

int main( int argc, char **argv ){
	static uint8_t r[ 12000 ], valid[ 512 ];
	size_t ix, vl;
	uint32_t len32;
	int fd;
	const struct timeval tv = { .tv_sec = 1700000000, .tv_usec = 123456 };

	if( argc != 2 ){
		fprintf( stderr, "usage: %s SOCKET_PATH\n", argv[0] );
		return 2;
	}
	signal( SIGPIPE, SIG_IGN );
	vl = valid_report( valid );

	/* 1. an element's data_length beyond the end of the report */
	fd = conn( argv[1] );
	ix = 4;
	r[ ix ++ ] = 1;
	memcpy( r + ix, &tv, sizeof( tv )); ix += sizeof( tv );
	put_el_hdr( r, &ix, 153, 3, 32768 );           /* http.host */
	memset( r + ix, 'A', 24 ); ix += 24;
	patch_len( r, ix );
	send_all( fd, r, ix );
	send_all( fd, valid, vl );
	close( fd );

	/* 2. an element header cut short by the end of the report */
	fd = conn( argv[1] );
	ix = 4;
	r[ ix ++ ] = 3;
	memcpy( r + ix, &tv, sizeof( tv )); ix += sizeof( tv );
	put_el( r, &ix, 354, 6, 1, "\x02" );
	put_el( r, &ix, 354, 27, 4, "\x00\x00\x00\x14" );
	put_u32( r, &ix, 178 );                        /* 4 bytes of a third header */
	patch_len( r, ix );
	send_all( fd, r, ix );
	send_all( fd, valid, vl );
	close( fd );

	/* 3. an element count larger than the report */
	fd = conn( argv[1] );
	ix = 4;
	r[ ix ++ ] = 250;
	memcpy( r + ix, &tv, sizeof( tv )); ix += sizeof( tv );
	put_el( r, &ix, 354, 6, 1, "\x02" );
	patch_len( r, ix );
	send_all( fd, r, ix );
	send_all( fd, valid, vl );
	close( fd );

	/* 4. a typed attribute with a short data_length */
	fd = conn( argv[1] );
	ix = 4;
	r[ ix ++ ] = 2;
	memcpy( r + ix, &tv, sizeof( tv )); ix += sizeof( tv );
	put_el( r, &ix, 701, 4, 2, "\x05\x00" );       /* dicom.called_ae_title */
	put_el( r, &ix, 354, 6, 1, "\x02" );
	patch_len( r, ix );
	send_all( fd, r, ix );
	send_all( fd, valid, vl );
	close( fd );

	/* 5. a report length bigger than the receive buffer, then a valid
	 * report on a fresh connection */
	fd = conn( argv[1] );
	len32 = 20000;
	send_all( fd, &len32, 4 );
	send_all( fd, r, 2000 );
	close( fd );
	fd = conn( argv[1] );
	send_all( fd, valid, vl );
	close( fd );

	/* 6. a report whose sender stops before the announced length, then a
	 * valid report on a fresh connection */
	fd = conn( argv[1] );
	ix = 4;
	r[ ix ++ ] = 5;
	memcpy( r + ix, &tv, sizeof( tv )); ix += sizeof( tv );
	put_el( r, &ix, 153, 1, 4, "GET" );
	put_el( r, &ix, 178, 13, 4, "\x01\x02\x03\x04" );
	{ uint32_t t = 4 + 8000; memcpy( r, &t, 4 ); }
	send_all( fd, r, ix );
	shutdown( fd, SHUT_WR );
	close( fd );
	fd = conn( argv[1] );
	send_all( fd, valid, vl );
	close( fd );

	/* 7. a report length below its own prefix */
	fd = conn( argv[1] );
	len32 = 0;
	send_all( fd, &len32, 4 );
	send_all( fd, valid, vl );
	close( fd );

	/* 8. an element naming an attribute the engine does not know */
	fd = conn( argv[1] );
	ix = 4;
	r[ ix ++ ] = 2;
	memcpy( r + ix, &tv, sizeof( tv )); ix += sizeof( tv );
	put_el( r, &ix, 0xFFFFFFF0, 1, 4, "\x01\x02\x03\x04" );
	put_el( r, &ix, 354, 6, 1, "\x02" );
	patch_len( r, ix );
	send_all( fd, r, ix );
	send_all( fd, valid, vl );
	close( fd );

	/* each of the 8 cases above ends with one valid report */
	return 0;
}
