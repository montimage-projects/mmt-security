/*
 * version.c
 *
 *  Created on: Apr 18, 2017
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@me.com>
 */
#include <stdlib.h>
#include "version.h"

//VERSION_NUMBER is given by Makefile
#ifndef VERSION_NUMBER
  #error("Not found VERSION_NUMBER")
#endif

//update this number when structure of plugin has been changed: the rule
//.so share rule_info_t (plugin_header.h), the structs of message_t.h,
//mmt_array_t.h and mmt_fsm.h, and the functions they call, with the
//engine (doc/rule-abi-stability.md).
//It must be greater than every version stamp a compile_rule of the old
//layout could have written. 1.2.21: rule_info_t.instance_keys (1.2.20 was
//stamped both before and after it). 1.2.22: the generated guards read
//the message values through mmt_sec_rule_engine_get_msg_values() and no
//longer through the rule_engine_t offset that the guards of a 1.2.21 rule
//have compiled in, so rule_engine_t left the plugin ABI and 1.2.21 rules
//are refused. VERSION in the Makefile.
//The loader also refuses rules stamped newer than this engine
//(plugins_engine.c), so a rule must be rebuilt with its engine.
#define REQUIRE_PLUGIN "1.2.22"


#define __NOW__   __DATE__ " " __TIME__

#ifdef GIT_VERSION
	//GIT_VERSION is given by Makefile
	#define MMT_SEC_VERSION  VERSION_NUMBER " (" GIT_VERSION " - " __NOW__ ")"
#else
	#define MMT_SEC_VERSION VERSION_NUMBER " (" __NOW__ ")"
	#define GIT_VERSION ""
#endif

static inline uint32_t mmt_sec_get_version_number_from_string( const char *version){
	const char *str = version;
	uint32_t val = 0;
	int percent = 100*100*100;

	do{
		val += percent * atoi( str );

		//jump over number
		while( 1 ){
			if( *str > '9' || *str < '0' )
				break;
			str ++;
		}
		//last number: do not jump over the final NUL
		if( *str == '\0' )
			break;
		//jump over .
		str ++;

		percent /= 100;

	}while( *str != '\0' && percent != 1 );

	return val;
}

const char *mmt_sec_get_version_hash(){
	return GIT_VERSION;
}

const char *mmt_sec_get_version_info(){
	return MMT_SEC_VERSION;
}

const char *mmt_sec_get_version_number(){
	return VERSION_NUMBER;
}

uint32_t mmt_sec_get_version_index(){
	return mmt_sec_get_version_number_from_string( VERSION_NUMBER );
}

const char *mmt_sec_get_required_plugin_version(){
	return REQUIRE_PLUGIN;
}

uint32_t mmt_sec_get_required_plugin_version_number(){
	return mmt_sec_get_version_number_from_string( REQUIRE_PLUGIN );
}
