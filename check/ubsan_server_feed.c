/*
 * ubsan_server_feed.c
 *
 * Feed one UNIX-domain connection of mmt_sec_server with reports whose
 * fields land at odd offsets, for the mmt_sec_server leg of
 * check/check-ubsan-align.sh (fork #66).
 *
 * A report on the wire is the 4-byte length of the report (itself included)
 * then: 1 byte of elements count, a 16-byte struct timeval, and for each
 * element proto_id (4), att_id (4), data_length (2) and the data. The
 * server parses that buffer in place: the timestamp sits at index 1 and
 * each element's data sits wherever the previous elements left it, so the
 * typed reads of the scalar branches used to be misaligned accesses.
 *
 * The element sets below cover the scalar branches of
 * dpi_message_set_dpi_data (u8/u16/u32/u64, the length of a
 * mmt_binary_var_data_t, a timeval blob and a header line as raw bytes) at
 * offsets that are odd or 2/4/5 mod 8. Every report also carries the four
 * attributes of rule 13 - a single-packet rule whose events verify on one
 * message (tcp.flags == 2 && tcp.payload_len > 0, and ip.src != ip.dst) -
 * so each report produces one deterministic alert and a run's verdict CSV
 * can be diffed between builds. All values are fixed and host-ordered, as
 * the server reads them.
 *
 * Usage: ubsan_server_feed SOCKET_PATH [REPORTS]
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

/* proto id / attribute id / data length / data, packed back to back */
typedef struct {
	uint32_t proto_id;
	uint32_t att_id;
	uint16_t len;
	uint8_t  data[ 16 ];
} element_t;

static size_t build_report( uint8_t *report, const element_t *elements, size_t elements_count ){
	size_t i;
	size_t index = 4; /* the 4-byte length is patched at the end */
	uint32_t len32;
	const struct timeval tv = { .tv_sec = 1700000000, .tv_usec = 123456 };

	report[ index ++ ] = (uint8_t) elements_count;
	memcpy( report + index, &tv, sizeof( tv ));
	index += sizeof( tv );

	for( i = 0; i < elements_count; i ++ ){
		memcpy( report + index, &elements[i].proto_id, 4 );
		index += 4;
		memcpy( report + index, &elements[i].att_id, 4 );
		index += 4;
		memcpy( report + index, &elements[i].len, 2 );
		index += 2;
		memcpy( report + index, elements[i].data, elements[i].len );
		index += elements[i].len;
	}

	len32 = (uint32_t) index;
	memcpy( report, &len32, 4 );
	return index;
}

int main( int argc, char **argv ){
	const char *path;
	int count = 50, i, fd;
	struct sockaddr_un addr;
	struct timeval start, now;
	uint8_t report[ 512 ];
	size_t len;

	static const struct timeval tv = { .tv_sec = 1700000000, .tv_usec = 123456 };

	/* first report template. Element data offsets inside the server's
	 * buffer: 27, 39, 53, 71, 85, 97, 108, 134, 153, 167, 181, 195 - a u16
	 * at an odd offset, u32s at 1/3 mod 4, a u64 at 5 mod 8, a var_data
	 * length at 2 mod 4. Rule 13's attributes are all present:
	 * tcp.flags == 2, tcp.payload_len > 0, ip.src != ip.dst */
	element_t report_a[] = {
		{ 354,  2, 2, { 80, 0 }},                          /* tcp.dest_port (u16) */
		{ 354,  3, 4, { 0x44, 0x33, 0x22, 0x11 }},         /* tcp.seq_nb (u32) */
		{ 178, 23, 8, { 0x88, 0x77, 0x66, 0x55,
		               0x44, 0x33, 0x22, 0x11 }},          /* ip.ip_frag_packets_count (u64) */
		{ 354,  4, 4, { 0x88, 0x77, 0x66, 0x55 }},         /* tcp.ack_nb (u32) */
		{ 354, 15, 2, { 0x00, 0x10 }},                     /* tcp.window (u16) */
		{ 354,  6, 1, { 2 }},                              /* tcp.flags (u8) = SYN */
		{   1,  3, 16, { 0 }},                             /* meta.utime (timeval blob) */
		{ 701,  4, 9, { 5,0,0,0, 'H','E','L','L','O' }},   /* dicom.called_ae_title (mmt_binary_var_data_t) */
		{ 354, 27, 4, { 20, 0, 0, 0 }},                    /* tcp.payload_len (u32) */
		{ 178, 13, 4, { 1, 2, 3, 4 }},                     /* ip.src */
		{ 178, 14, 4, { 5, 6, 7, 8 }},                     /* ip.dst */
		{ 153,  3, 6, { 'H','O','S','T','X', 0 }},         /* http.host (header line: raw bytes) */
	};

	/* second template, another order: the same scalars land at other odd
	 * offsets. Element data offsets: 27, 39, 53, 67, 81, 92, 110, 136,
	 * 150, 164, 180, 199. Same rule-13 attributes, so it alerts too. */
	element_t report_b[] = {
		{ 354, 15, 2, { 0x00, 0x10 }},                     /* tcp.window (u16) */
		{ 178, 13, 4, { 1, 2, 3, 4 }},                     /* ip.src */
		{ 354,  4, 4, { 0x88, 0x77, 0x66, 0x55 }},         /* tcp.ack_nb (u32) */
		{ 178, 14, 4, { 5, 6, 7, 8 }},                     /* ip.dst */
		{ 354,  6, 1, { 2 }},                              /* tcp.flags (u8) = SYN */
		{ 178, 23, 8, { 0x88, 0x77, 0x66, 0x55,
		               0x44, 0x33, 0x22, 0x11 }},          /* ip.ip_frag_packets_count (u64) */
		{   1,  3, 16, { 0 }},                             /* meta.utime (timeval blob) */
		{ 354, 27, 4, { 20, 0, 0, 0 }},                    /* tcp.payload_len (u32) */
		{ 354,  3, 4, { 0x44, 0x33, 0x22, 0x11 }},         /* tcp.seq_nb (u32) */
		{ 153,  3, 6, { 'H','O','S','T','X', 0 }},         /* http.host (header line: raw bytes) */
		{ 701,  5, 9, { 5,0,0,0, 'H','E','L','L','O' }},   /* dicom.calling_ae_title (mmt_binary_var_data_t) */
		{ 354,  2, 2, { 80, 0 }},                          /* tcp.dest_port (u16) */
	};

	if( argc < 2 || argc > 3 ){
		fprintf( stderr, "usage: %s SOCKET_PATH [REPORTS]\n", argv[0] );
		return 2;
	}
	path = argv[1];
	if( argc > 2 ) count = atoi( argv[2] );

	signal( SIGPIPE, SIG_IGN );

	/* the meta.utime elements carry the same fixed timestamp */
	memcpy( report_a[6].data, &tv, sizeof( tv ));
	memcpy( report_b[6].data, &tv, sizeof( tv ));

	memset( &addr, 0, sizeof( addr ));
	addr.sun_family = AF_UNIX;
	strncpy( addr.sun_path, path, sizeof( addr.sun_path ) - 1 );

	/* wait for the listening socket, at most 10 s */
	gettimeofday( &start, NULL );
	for( ;; ){
		fd = socket( AF_UNIX, SOCK_STREAM, 0 );
		if( fd < 0 ){
			perror( "socket" );
			return 1;
		}
		if( connect( fd, (struct sockaddr *) &addr, sizeof( addr )) == 0 )
			break;
		close( fd );
		gettimeofday( &now, NULL );
		if( now.tv_sec - start.tv_sec >= 10 ){
			fprintf( stderr, "cannot connect to unix:%s\n", path );
			return 1;
		}
		usleep( 100000 );
	}

	for( i = 0; i < count; i ++ ){
		len = build_report( report,
				(i % 2 == 0)? report_a : report_b,
				(i % 2 == 0)? sizeof( report_a ) / sizeof( report_a[0] )
				            : sizeof( report_b ) / sizeof( report_b[0] ));
		if( write( fd, report, len ) != (ssize_t) len )
			break;
	}
	close( fd );
	return 0;
}
