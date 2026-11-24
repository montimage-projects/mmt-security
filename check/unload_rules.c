/*
 * unload_rules.c
 *
 * Reproducer and regression test for issue #58 (stale plugin_t slot on
 * unload, and the global rules set keeping pointers to unloaded rules),
 * built and run by check/check-unload-rules.sh.
 *
 * It works in a scratch directory holding rules/{1.ssh,11.ip_size,6.SYNFUL}.so
 * and staging/{26.proto_scan,9101}.so:
 *
 *  - P0: load the rules            => {1,6,11,84}
 *  - P1: unload rule 6 of 6.SYNFUL (a multi-rule plugin, which keeps rule 84)
 *                                  => {1,11,84}
 *  - P2: unload rule 1, the only rule of 1.ssh.so: the plugin is closed and
 *        its slot of plugins[] is freed then reused by a swap-with-last
 *                                  => {11,84}
 *  - P3: put 1.ssh.so back, drop 26.proto_scan.so into rules/, unload rule 84
 *        (6.SYNFUL.so is closed), then rescan: the vacated slots of plugins[]
 *        are reused to load 1.ssh.so, 26.proto_scan.so and 6.SYNFUL.so again
 *                                  => {1,6,11,26,84}
 *  - P4: unload rule 11, then load 9101.so with mmt_sec_load_plugin() into
 *        the vacated slot           => {1,6,26,84,9101}
 *  - P5: mmt_sec_init() + an engine run on the 6.SYNFUL pcap: the reloaded
 *        rules 6 and 84 must still alert.
 *
 * Before the fix, P1 already kept rule 6 in the global rules set; the reuse
 * of a vacated slot at P3 started plugin->rules_count from its stale value
 * and wrote past the freshly allocated plugin->rules array.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <pcap.h>

#include "../src/lib/plugins_engine.h"
#include "../src/lib/mmt_security.h"
#include "../src/lib/dpi_message_t.h"

/* mmt_sec_load_plugin is a public function of plugins_engine.c but is not
 * declared in plugins_engine.h */
size_t mmt_sec_load_plugin(
		size_t ( *mmt_sec_get_plugin_info ) ( const rule_info_t ** ),
		void (*on_load)(),
		void (*on_unload)() );

static int fails = 0;
static void fail( const char *phase, const char *msg ){
	fprintf( stderr, "  FAIL %s: %s\n", phase, msg );
	fails ++;
}

/* compare the sorted ids of the global rules set with the expected list
 * (load_mmt_sec_rules rescans ./rules: it returns the current set when every
 * .so there is loaded, and loads the new ones otherwise) */
static void check_ids( const char *phase, const uint32_t *expect, size_t expect_count ){
	rule_info_t const*const*arr;
	uint32_t ids[64];
	size_t n, i, j;
	int bad;
	char got[256], want[256];

	n = load_mmt_sec_rules( &arr );
	for( i=0; i<n && i<64; i++ )
		ids[i] = arr[i]->id;

	/* insertion sort */
	for( i=1; i<n && i<64; i++ ){
		uint32_t v = ids[i];
		for( j=i; j>0 && ids[j-1] > v; j-- )
			ids[j] = ids[j-1];
		ids[j] = v;
	}

	got[0] = want[0] = '\0';
	for( i=0; i<n && i<64; i++ ) snprintf( got + strlen(got), sizeof(got)-strlen(got), "%u,", ids[i] );
	for( i=0; i<expect_count; i++ ) snprintf( want + strlen(want), sizeof(want)-strlen(want), "%u,", expect[i] );

	bad = ( n != expect_count );
	for( i=0; !bad && i<n; i++ )
		if( ids[i] != expect[i] ) bad = 1;

	printf( "  %s: %zu rule(s) {%s} (expect {%s})\n", phase, n, got, want );
	if( bad || n > 64 ) fail( phase, "loaded rule ids differ" );
}

static void unload_one( const char *phase, uint32_t rule_id ){
	size_t ret = unload_mmt_sec_rules( 1, &rule_id );
	printf( "  %s: unload rule %u => %zu removed\n", phase, rule_id, ret );
	if( ret != 1 ) fail( phase, "rule not removed" );
}

static void move( const char *src, const char *dst, const char *phase ){
	if( rename( src, dst ) != 0 )
		fail( phase, "cannot move a .so file in/out of rules/" );
}

/* ---------------- the engine run (P5) ---------------- */

static size_t alerts_6 = 0, alerts_84 = 0, alerts_other = 0;
static void count_alert( const rule_info_t *rule, enum verdict_type verdict,
		uint64_t timestamp, uint64_t counter, const mmt_array_t *trace, void *user_data ){
	if( rule->id == 6 ) alerts_6 ++;
	else if( rule->id == 84 ) alerts_84 ++;
	else alerts_other ++;
}

static mmt_handler_t *dpi_handler = NULL;
static proto_attribute_t const *const*proto_atts = NULL;
static size_t proto_atts_count = 0;

/* message building as mmt_sec_standalone does it */
static int on_packet( const ipacket_t *pkt, void *args ){
	size_t i;
	message_t *msg = create_message_t();
	msg->timestamp = mmt_sec_encode_timeval( &pkt->p_hdr->ts );
	msg->counter   = pkt->packet_id;
	msg->flow_id   = get_session_id_from_packet( pkt );
	for( i=0; i<proto_atts_count; i++ )
		dpi_message_set_data( pkt, proto_atts[i]->dpi_type, msg, proto_atts[i]->proto_id, proto_atts[i]->att_id );

	if( likely( msg->elements_count )){
		mmt_sec_process( (mmt_sec_handler_t *)args, msg );
		return 0;
	}
	free_message_t( msg );
	return 1;
}

static void register_atts(){
	size_t i;
	for( i=0; i<proto_atts_count; i++ ){
		if( ! is_registered_attribute( dpi_handler, proto_atts[i]->proto_id, proto_atts[i]->att_id ))
			register_extraction_attribute( dpi_handler, proto_atts[i]->proto_id, proto_atts[i]->att_id );
		/* tcp.p_data needs tcp.payload_len, as mmt_sec_standalone registers it */
		if( proto_atts[i]->proto_id == PROTO_TCP && proto_atts[i]->att_id == PROTO_PAYLOAD )
			register_extraction_attribute( dpi_handler, PROTO_TCP, TCP_PAYLOAD_LEN );
		else if( proto_atts[i]->proto_id == PROTO_IP && proto_atts[i]->att_id == IP_OPTS )
			register_extraction_attribute( dpi_handler, PROTO_IP, IP_HEADER_LEN );
	}
}

static void engine_run( const char *pcap_path ){
	char errbuf[1024];
	const unsigned char *data;
	struct pcap_pkthdr pkthdr;
	struct pkthdr header;
	pcap_t *pcap;
	mmt_sec_handler_t *sec_handler;
	size_t alerts;

	mmt_sec_init( NULL );
	sec_handler = mmt_sec_register( 0, NULL, NULL, false, count_alert, NULL );

	init_extraction();
	dpi_handler = mmt_init_handler( DLT_EN10MB, 0, errbuf );
	if( dpi_handler == NULL ){ fail( "P5 engine", errbuf ); return; }

	proto_atts_count = mmt_sec_get_unique_protocol_attributes( &proto_atts );
	register_atts();
	register_packet_handler( dpi_handler, 1, on_packet, sec_handler );

	pcap = pcap_open_offline( pcap_path, errbuf );
	if( pcap == NULL ){ fail( "P5 engine", errbuf ); return; }
	while(( data = pcap_next( pcap, &pkthdr )) != NULL ){
		header.ts     = pkthdr.ts;
		header.caplen = pkthdr.caplen;
		header.len    = pkthdr.len;
		packet_process( dpi_handler, &header, data );
	}
	pcap_close( pcap );

	alerts = mmt_sec_unregister( sec_handler );
	printf( "  P5 engine on 6.SYNFUL.pcap: %zu alert(s): rule 6: %zu, rule 84: %zu, other: %zu\n",
			alerts, alerts_6, alerts_84, alerts_other );
	if( alerts_6 == 0 )  fail( "P5 engine", "reloaded rule 6 does not alert" );
	if( alerts_84 == 0 ) fail( "P5 engine", "reloaded rule 84 does not alert" );

	mmt_sec_close();
	mmt_close_handler( dpi_handler );
	close_extraction();
}

int main( int argc, char **argv ){
	if( argc != 2 ){
		fprintf( stderr, "usage: %s <pcap>   (cwd must hold rules/ and staging/)\n", argv[0] );
		return 2;
	}
	const char *pcap_path = argv[1];

	/* P0: the initial load */
	{ const uint32_t want[] = {1,6,11,84};
	  check_ids( "P0 load", want, 4 ); }

	/* P1: one rule out of the two of 6.SYNFUL.so */
	unload_one( "P1", 6 );
	{ const uint32_t want[] = {1,11,84};
	  check_ids( "P1 unload rule 6 of 6.SYNFUL", want, 3 ); }

	/* P2: the only rule of 1.ssh.so; the .so is moved aside first so the
	 * peek rescan does not load it again */
	move( "rules/1.ssh.so", "staging/1.ssh.so", "P2" );
	unload_one( "P2", 1 );
	{ const uint32_t want[] = {11,84};
	  check_ids( "P2 unload rule 1 (plugin closed)", want, 2 ); }

	/* P3: 1.ssh.so is back, 26.proto_scan.so arrives, rule 84 is unloaded
	 * (6.SYNFUL.so is closed); the rescan reuses the vacated slots */
	move( "staging/1.ssh.so", "rules/1.ssh.so", "P3" );
	move( "staging/26.proto_scan.so", "rules/26.proto_scan.so", "P3" );
	unload_one( "P3", 84 );
	{ const uint32_t want[] = {1,6,11,26,84};
	  check_ids( "P3 rescan into vacated slots", want, 5 ); }

	/* P4: a plugin loaded by functions fills the slot vacated by 11.ip_size */
	unload_one( "P4", 11 );
	{
		void *lib = dlopen( "staging/9101.so", RTLD_NOW );
		if( lib == NULL ){
			fail( "P4", dlerror() );
		}else{
			size_t (*info)( const rule_info_t ** ) = dlsym( lib, "mmt_sec_get_plugin_info" );
			void (*on_load)()   = dlsym( lib, "on_load" );
			void (*on_unload)() = dlsym( lib, "on_unload" );
			size_t added = info == NULL ? 0 : mmt_sec_load_plugin( info, on_load, on_unload );
			printf( "  P4: mmt_sec_load_plugin(9101.so) => %zu\n", added );
			if( added != 1 ) fail( "P4", "9101.so did not load 1 rule" );
		}
	}
	{ const uint32_t want[] = {1,6,11,26,84,9101};
	  check_ids( "P4 mmt_sec_load_plugin + rescan (reloads 11)", want, 6 ); }

	/* P5: the reloaded rules still alert on the pcap */
	engine_run( pcap_path );

	if( fails ) fprintf( stderr, "  => %d check(s) failed\n", fails );
	return fails ? 1 : 0;
}
