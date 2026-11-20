/*
 * Hash seed test of rule 57 (run by check/check-syn-flood-rules.sh).
 *
 * The embedded C of rules/57.syn_flood_rate.xml is extracted to RULE_C and
 * included here. Prints the hash seed that on_load() sets: the script checks
 * that MMT_SEC_SYN_FLOOD_HASH_SEED sets it, and that two processes without
 * it draw different seeds.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>

#define mmt_warn( ... ) ( fprintf( stderr, "WARN " __VA_ARGS__ ), fputc( '\n', stderr ))
#define mmt_info( ... ) ( fprintf( stderr, "INFO " __VA_ARGS__ ), fputc( '\n', stderr ))

#include RULE_C

int main(){
	on_load();
	printf( "%lu\n", (unsigned long) em_syn_flood_seed );
	return 0;
}
