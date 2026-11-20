/*
 * resolve_ids.c - resolve (proto, att) names to mmt-dpi ids at run time.
 *
 * Part of tools/dpi-id-stability (issue #5, A0). Linked against one
 * libmmt_core with all its plugins loaded (init_extraction), it reads
 * "proto att" pairs on stdin, one per line, and prints, tab separated:
 *     proto  att  proto_id  att_id  dpi_type
 * An unknown protocol or attribute prints "-" for the missing ids.
 * The first output line is "#dpi_version <mmt_version()>".
 *
 * Build: gcc -o resolve_ids resolve_ids.c -I/opt/mmt/dpi/include \
 *            -L/opt/mmt/dpi/lib -l:libmmt_core.so -ldl
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mmt_core.h>

int main( void ){
	char line[512], proto[256], att[256];

	init_extraction();
	printf( "#dpi_version\t%s\n", mmt_version() );

	while( fgets( line, sizeof( line ), stdin ) != NULL ){
		if( sscanf( line, "%255s %255s", proto, att ) != 2 )
			continue;
		uint32_t p_id = get_protocol_id_by_name( proto );
		if( p_id == (uint32_t) -1 || p_id == 0 ){
			printf( "%s\t%s\t-\t-\t-\n", proto, att );
			continue;
		}
		uint32_t a_id = get_attribute_id_by_protocol_id_and_attribute_name( p_id, att );
		if( a_id == (uint32_t) -1 || a_id == 0 ){
			printf( "%s\t%s\t%u\t-\t-\n", proto, att, p_id );
			continue;
		}
		long t = get_attribute_data_type( p_id, a_id );
		printf( "%s\t%s\t%u\t%u\t%ld\n", proto, att, p_id, a_id, t );
	}
	close_extraction();
	return 0;
}
