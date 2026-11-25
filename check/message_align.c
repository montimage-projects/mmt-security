/*
 * message_align.c
 *
 * Regression test for issue #64: message_t is declared __aligned (a cache
 * line, base.h) but mmt_mem_alloc() used to return data 16 bytes past the
 * malloc base - 16-byte aligned at best. Every block must now come back at
 * least _Alignof(message_t)-aligned.
 *
 * Built and run by check/check-message-align.sh, which rebuilds
 * src/lib/mmt_alloc.o and src/lib/message_t.o with
 * -fsanitize=address,undefined: on the unfixed allocator the first
 * misaligned message_t access inside create_message_t is a UBSan report
 * (halt_on_error makes it fatal), and the asserts below fail the run on
 * any misaligned block the sanitizers would not have caught.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../src/lib/message_t.h"
#include "../src/lib/mmt_security.h"


static int fails = 0;

static void check_aligned( const char *what, const message_t *msg ){
	if( msg == NULL || ((uintptr_t) msg % _Alignof( message_t )) != 0 ){
		fprintf( stderr, "FAIL: %s %p is not %zu-byte aligned\n",
				what, (const void *) msg, (size_t) _Alignof( message_t ));
		fails ++;
	}
}

int main( void ){
	message_t *msgs[ 64 ], *dup;
	const proto_attribute_t *const *atts;
	size_t atts_count;
	int i;

	/* populates proto_atts so messages get their real layout; if the
	 * scratch rules dir is empty mmt_sec_init only warns and returns 1 -
	 * create_message_t still works with 0 elements */
	mmt_sec_init( NULL );

	/* every fresh block must be aligned; a loop keeps the check meaningful
	 * even where malloc would hand out a 64-aligned base by chance */
	for( i=0; i<64; i++ ){
		msgs[i] = create_message_t();
		check_aligned( "create_message_t", msgs[i] );
	}

	/* a duplicated message keeps the same contract */
	dup = mmt_mem_force_dup( msgs[0], mmt_mem_size( msgs[0] ));
	check_aligned( "mmt_mem_dup", (message_t *) dup );
	mmt_mem_free( dup );

	/* the embedded element header inside msg->_data: write data of length
	 * 7 so the following header stays 8-aligned (issue #64 is about the
	 * message block itself, not the element headers' natural alignment) */
	atts_count = mmt_sec_get_unique_protocol_attributes( &atts );
	/* a run without rules must not pass: mmt_sec_init then registers
	 * nothing and every block below would be skipped, so the assertions of
	 * issue #66 would hold vacuously - "no rules loaded" is a failure */
	if( atts_count <= 3 ){
		fprintf( stderr, "FAIL: only %zu proto.atts after mmt_sec_init: no rules loaded\n",
				atts_count );
		fails ++;
	}
	if( atts_count > 0 ){
		const char payload[7] = "0123456";
		if( set_element_data_message_t( msgs[0], atts[0]->proto_id,
				atts[0]->att_id, payload, MMT_SEC_MSG_DATA_TYPE_BINARY, 7 ) != MSG_CONTINUE ){
			fprintf( stderr, "FAIL: set_element_data_message_t rejected a 7-byte payload\n" );
			fails ++;
		}
	}

	/* issue #66: the embedded element headers inside msg->_data must keep
	 * _Alignof(mmt_memory_t): an odd-length payload used to pack the next
	 * header at a stride of data_length+16+1, so every typed read through
	 * it - mmt_mem_size/mmt_mem_cmp, rule_verif_engine's key fold, the
	 * generated guards' double loads - was a misaligned access.
	 * Write order fixes the packing: element n's header follows the slot of
	 * element n-1. A first element of 5 bytes puts the second header at
	 * offset 22 (6 mod 8) on the unfixed stride. This unit is sanitized, so
	 * each typed access below is also a UBSan report on base. */
	if( atts_count > 3 ){
		message_t *m = msgs[1];
		const char odd[5] = "01234";      /* 5 bytes: next header 6 mod 8 on base */
		const char bin[3] = "xy\0";
		double num = 1.5;
		const message_element_t *el;
		int i;

		if( set_element_data_message_t( m, atts[0]->proto_id, atts[0]->att_id,
				odd, MMT_SEC_MSG_DATA_TYPE_BINARY, sizeof( odd )) != MSG_CONTINUE
		 || set_element_data_message_t( m, atts[1]->proto_id, atts[1]->att_id,
				&num, MMT_SEC_MSG_DATA_TYPE_NUMERIC, sizeof( num )) != MSG_CONTINUE
		 || set_element_data_message_t( m, atts[2]->proto_id, atts[2]->att_id,
				bin, MMT_SEC_MSG_DATA_TYPE_BINARY, sizeof( bin )) != MSG_CONTINUE ){
			fprintf( stderr, "FAIL: set_element_data_message_t rejected the test payloads\n" );
			fails ++;
		} else {
			for( i=0; i<3; i++ ){
				el = get_element_message_t( m, atts[i]->proto_id, atts[i]->att_id );
				if( el == NULL || ((uintptr_t) el->data % _Alignof( mmt_memory_t )) != 0 ){
					fprintf( stderr, "FAIL: data of element %d.%d (%p) is not %zu-byte aligned\n",
							atts[i]->proto_id, atts[i]->att_id,
							(const void *)( el ? el->data : NULL ),
							(size_t) _Alignof( mmt_memory_t ));
					fails ++;
					continue;
				}
				/* reads of the embedded header itself (mmt_mem_size) and a
				 * comparison of two element payloads (mmt_mem_cmp): both
				 * type-pun the mmt_memory_t header */
				if( mmt_mem_size( el->data ) == 0 ){
					fprintf( stderr, "FAIL: mmt_mem_size of element %d.%d is 0\n",
							atts[i]->proto_id, atts[i]->att_id );
					fails ++;
				}
			}
			el = get_element_message_t( m, atts[0]->proto_id, atts[0]->att_id );
			(void) mmt_mem_cmp( el->data,
					get_element_message_t( m, atts[2]->proto_id, atts[2]->att_id )->data );
			/* the generated guards read numbers as *(const double *) data:
			 * the NUMERIC element must accept the same load */
			if( *(const double *) get_element_message_t( m, atts[1]->proto_id,
					atts[1]->att_id )->data != 1.5 ){
				fprintf( stderr, "FAIL: NUMERIC element does not read back 1.5\n" );
				fails ++;
			}
		}
	}

	/* reference-counted free paths on the same block */
	mmt_mem_retains( msgs[0], 3 );               /* ref_count 4 */
	free_message_ts( msgs[0], 2 );               /* ref_count 2 */
	free_message_t( msgs[0] );                   /* ref_count 1 */
	mmt_mem_atomic_retain( msgs[0] );            /* ref_count 2 */
	free_message_t( msgs[0] );                   /* ref_count 1 */
	free_message_t( msgs[0] );                   /* ref_count 0 -> freed */

	for( i=1; i<64; i++ )
		free_message_t( msgs[i] );

	if( fails )
		fprintf( stderr, "FAIL: %d misaligned message_t block(s)\n", fails );
	return fails ? 1 : 0;
}
