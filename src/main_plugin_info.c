/*
 * main_plugin_info.c
 *
 *  Created on: Oct 10, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 *
 *  Get information of rules encoded in a binary file (.so)
 */
#include "lib/base.h"
#include "lib/mmt_log.h"
#include "lib/mmt_alloc.h"
#include "lib/plugins_engine.h"
#include "lib/rule_build_info.h"
#include <dirent.h>
#include <dlfcn.h>
#include <ctype.h>
#include <stdio_ext.h>
#include <unistd.h>

static void _usage( const char *prog ){
	fprintf( stderr, "Usage: %s [lib_file.so]\n", prog );
	fprintf( stderr, "         print the rules of lib_file.so, or of every .so in ./rules or %s\n", MMT_SEC_PLUGINS_REPOSITORY_OPT );
	fprintf( stderr, "       %s --build-info [--json] lib_file.so\n", prog );
	fprintf( stderr, "         print the build info of lib_file.so (doc/rule.md), indented or as one JSON line\n" );
	fprintf( stderr, "       %s --abi\n", prog );
	fprintf( stderr, "         print the rule ABI layout and hash of this mmt-security\n" );
}

/* get the build info of a .so: its exported function, else its ELF note. NULL if none */
static char *_get_build_info( const char *path ){
	void *lib = dlopen( path, RTLD_NOW );
	if( lib != NULL ){
		mmt_sec_get_rule_build_info_fn_t fn = (mmt_sec_get_rule_build_info_fn_t) dlsym( lib, MMT_SEC_BUILD_INFO_SYMBOL );
		if( fn != NULL )
			return strdup( fn() );
	}
	//cannot be loaded, or no symbol: read the note
	return mmt_sec_elf_read_build_note( path );
}

static void _indent( int level ){
	printf( "\n%*s", 2 * level, "" );
}

/* indent a JSON text; arrays that hold no object or array stay on one line */
static void _print_json_indented( const char *s ){
	int level = 0, inline_array = 0, in_str = 0;
	const char *p, *q;
	for( p = s; *p; p++ ){
		char c = *p;
		if( in_str ){
			putchar( c );
			if( c == '\\' && p[1] ){ putchar( *++p ); }
			else if( c == '"' ) in_str = 0;
			continue;
		}
		switch( c ){
		case '"': in_str = 1; putchar( c ); break;
		case '{':
		case '[':
			if( c == '[' && !inline_array ){
				//look for a nested container before the matching ]
				int str = 0, nested = 0;
				for( q = p + 1; *q; q++ ){
					if( str ){ if( *q == '\\' && q[1] ) q++; else if( *q == '"' ) str = 0; continue; }
					if( *q == '"' ) str = 1;
					else if( *q == '{' || *q == '[' ){ nested = 1; break; }
					else if( *q == ']' ) break;
				}
				if( !nested ){ inline_array = 1; putchar( c ); break; }
			}else if( inline_array ){ putchar( c ); break; }
			putchar( c );
			if( p[1] == '}' || p[1] == ']' ) break;
			_indent( ++level );
			break;
		case '}':
		case ']':
			if( inline_array && c == ']' ){ inline_array = 0; putchar( c ); break; }
			if( p[-1] != '{' && p[-1] != '[' ) _indent( --level );
			putchar( c );
			break;
		case ',':
			putchar( c );
			if( inline_array ) putchar( ' ' ); else _indent( level );
			break;
		case ':': printf( ": " ); break;
		default:
			if( !isspace( (unsigned char) c )) putchar( c );
		}
	}
	printf( "\n" );
}

static int _print_build_info( const char *path, bool json ){
	char *info;
	if( access( path, R_OK ) != 0 ){
		fprintf( stderr, "Cannot read %s\n", path );
		return 1;
	}
	info = _get_build_info( path );
	if( info == NULL ){
		if( json )
			printf( "null\n" );
		else
			printf( "No build info in %s: it was compiled by a compile_rule that did not record build info.\n", path );
		return 0;
	}
	if( json )
		printf( "%s\n", info );
	else
		_print_json_indented( info );
	free( info );
	return 0;
}

int main( int argc, char** argv ){
	const rule_info_t *const*rules_arr;
	size_t i, j, n;
	struct tm tm;
	bool build_info = NO, json = NO, abi = NO;
	const char *so_file = NULL;

	for( i=1; i<argc; i++ ){
		if( strcmp( argv[i], "--build-info" ) == 0 )
			build_info = YES;
		else if( strcmp( argv[i], "--json" ) == 0 )
			json = YES;
		else if( strcmp( argv[i], "--abi" ) == 0 )
			abi = YES;
		else if( strcmp( argv[i], "-h" ) == 0 || strcmp( argv[i], "--help" ) == 0 ){
			_usage( argv[0] );
			return 0;
		}else if( argv[i][0] == '-' || so_file != NULL ){
			_usage( argv[0] );
			return 1;
		}else
			so_file = argv[i];
	}

	//document output: drop what the config constructor (./mmt-security.conf)
	// may have buffered on stdout before main, so stdout holds only the result
	if( abi || build_info )
		__fpurge( stdout );

	if( abi ){
		printf( "%s\n%s\n", mmt_sec_get_rule_abi_hash(), mmt_sec_get_rule_abi_layout() );
		return 0;
	}
	if( json && !build_info ){
		_usage( argv[0] );
		return 1;
	}
	if( build_info ){
		if( so_file == NULL ){
			_usage( argv[0] );
			return 1;
		}
		return _print_build_info( so_file, json );
	}

	if( so_file == NULL )
		//load all plugins from default folder:
		// - /opt/mmt/security/rules
		// - ./rules
		n = load_mmt_sec_rules( &rules_arr );
	else{
		//load only one plugin given by argv[1]
		n = load_mmt_sec_rule( &rules_arr, so_file );
	}

	//print rules' information
	printf("Found %zu rule%s", n, n<=1? ".": "s." );

	for( i=0; i<n; i++ ){
		printf("\n%zu - Rule id: %d", (i+1), rules_arr[i]->id );
		printf("\n\t- type            : %s",  rules_arr[i]->type_string );
		printf("\n\t- events_count    : %d",  rules_arr[i]->events_count );
		printf("\n\t- variables_count : %d",  rules_arr[i]->proto_atts_count );
		printf("\n\t- variables       : " );
		for( j=0; j<rules_arr[i]->proto_atts_count; j++ )
			printf( "%s%s.%s (%d.%d)",
					j==0? "":", ",
					rules_arr[i]->proto_atts[j].proto, rules_arr[i]->proto_atts[j].att,
					rules_arr[i]->proto_atts[j].proto_id, rules_arr[i]->proto_atts[j].att_id);

		printf("\n\t- description     : %s",  rules_arr[i]->description );
		printf("\n\t- if_satisfied    : %p",  rules_arr[i]->if_satisfied );
		//printf("\n\t- create_instance : %pF",  rules_arr[i]->create_instance );
		//printf("\n\t- hash_message    : %pF",  rules_arr[i]->hash_message );
		tm = *localtime(& rules_arr[i]->version->created_date );
		printf("\n\t- version         : %s (%s - %d-%d-%d %d:%d:%d), dpi version %s",  rules_arr[i]->version->number,
				rules_arr[i]->version->hash,
				tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
				rules_arr[i]->version->dpi );
	}
	printf("\n");
	return 0;
}
