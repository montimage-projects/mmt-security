/*
 * rule_build_info_dpi.c
 *
 * The part of the rule build info (fork issue #6) that asks the installed
 * mmt-dpi: its version, whether the ids baked from src/dpi/mmt_dpi.h are the
 * ones it uses, and which DPI plugin extracts each (proto, att).
 *
 * compile_rule does not link libmmt_core: its ids come from the generated
 * header. This file therefore looks libmmt_core up at run time (dlsym, then
 * dlopen). Without it, the fields are null and compile_rule still works.
 * <mmt_core.h> is included for its types only.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mmt_core.h>

#include "rule_build_info.h"

typedef const char *(*_version_fn)( void );
typedef int (*_init_fn)( void );
typedef void (*_close_fn)( void );
typedef uint32_t (*_proto_id_fn)( const char * );
typedef uint32_t (*_att_id_fn)( uint32_t, const char * );
typedef long (*_att_type_fn)( uint32_t, uint32_t );
typedef void (*_att_iter_cb)( attribute_metadata_t *, uint32_t, void * );
typedef void (*_att_iter_fn)( uint32_t, _att_iter_cb, void * );

static void *_sym( void *lib, const char *name ){
	return dlsym( lib ? lib : RTLD_DEFAULT, name );
}

struct _find_att{
	const char *name;
	const void *fct;
};

static void _find_att_cb( attribute_metadata_t *a, uint32_t proto_id, void *arg ){
	struct _find_att *f = arg;
	if( f->fct == NULL && strcmp( a->alias, f->name ) == 0 )
		f->fct = (const void *) a->extraction_function;
}

void mmt_sec_rule_build_info_probe_dpi( const rule_build_info_id_t *ids, size_t count,
		char **version, int *ids_match, char **plugins_json ){
	void *lib = NULL;
	_version_fn  f_version;
	_init_fn     f_init;
	_close_fn    f_close;
	_proto_id_fn f_proto;
	_att_id_fn   f_att;
	_att_type_fn f_type;
	_att_iter_fn f_iter;
	char **plugins = NULL;
	size_t n_plugins = 0, i, j, len;

	*version = NULL;
	*ids_match = -1;
	*plugins_json = NULL;

	if( getenv( "MMT_SEC_BUILD_INFO_NO_DPI" ) != NULL )
		return;

	if( _sym( NULL, "init_extraction" ) == NULL ){
		lib = dlopen( "libmmt_core.so", RTLD_NOW | RTLD_GLOBAL );
		if( lib == NULL )
			lib = dlopen( "/opt/mmt/dpi/lib/libmmt_core.so", RTLD_NOW | RTLD_GLOBAL );
		if( lib == NULL )
			return;
	}
	f_version = (_version_fn)  _sym( lib, "mmt_version" );
	f_init    = (_init_fn)     _sym( lib, "init_extraction" );
	f_close   = (_close_fn)    _sym( lib, "close_extraction" );
	f_proto   = (_proto_id_fn) _sym( lib, "get_protocol_id_by_name" );
	f_att     = (_att_id_fn)   _sym( lib, "get_attribute_id_by_protocol_id_and_attribute_name" );
	f_type    = (_att_type_fn) _sym( lib, "get_attribute_data_type" );
	f_iter    = (_att_iter_fn) _sym( lib, "iterate_through_protocol_attributes" );

	if( f_version != NULL )
		*version = strdup( f_version() );
	if( f_init == NULL || f_proto == NULL || f_att == NULL || f_type == NULL || f_iter == NULL )
		goto end;

	f_init();
	*ids_match = 1;
	plugins = calloc( count + 1, sizeof( char * ));
	for( i = 0; i < count; i++ ){
		uint32_t p = f_proto( ids[i].proto );
		uint32_t a = (p == 0 || p == (uint32_t) -1) ? 0 : f_att( p, ids[i].att );
		long t = (a == 0 || a == (uint32_t) -1) ? -1 : f_type( p, a );
		struct _find_att fa = { ids[i].att, NULL };
		Dl_info info;
		const char *base;

		if( p != ids[i].proto_id || a != ids[i].att_id || t != ids[i].dpi_type )
			*ids_match = 0;
		if( a == 0 || a == (uint32_t) -1 || plugins == NULL )
			continue;
		/* the plugin that extracts this attribute; generic ones live in libmmt_core */
		f_iter( p, _find_att_cb, &fa );
		if( fa.fct == NULL || dladdr( fa.fct, &info ) == 0 || info.dli_fname == NULL )
			continue;
		base = strrchr( info.dli_fname, '/' );
		base = base ? base + 1 : info.dli_fname;
		if( strncmp( base, "libmmt_core", 11 ) == 0 || strpbrk( base, "\"\\" ) != NULL )
			continue;
		for( j = 0; j < n_plugins; j++ )
			if( strcmp( plugins[j], base ) == 0 )
				break;
		if( j == n_plugins )
			plugins[ n_plugins++ ] = strdup( base );
	}
	if( f_close != NULL )
		f_close();

	/* JSON array, sorted */
	if( plugins != NULL ){
		for( i = 0; i < n_plugins; i++ )
			for( j = i + 1; j < n_plugins; j++ )
				if( strcmp( plugins[i], plugins[j] ) > 0 ){
					char *tmp = plugins[i]; plugins[i] = plugins[j]; plugins[j] = tmp;
				}
		len = 3;
		for( i = 0; i < n_plugins; i++ )
			len += strlen( plugins[i] ) + 3;
		*plugins_json = malloc( len );
		if( *plugins_json != NULL ){
			strcpy( *plugins_json, "[" );
			for( i = 0; i < n_plugins; i++ ){
				/* names with a quote or a backslash were skipped above */
				strcat( *plugins_json, i ? ",\"" : "\"" );
				strcat( *plugins_json, plugins[i] );
				strcat( *plugins_json, "\"" );
			}
			strcat( *plugins_json, "]" );
		}
		for( i = 0; i < n_plugins; i++ )
			free( plugins[i] );
		free( plugins );
	}
end:
	/* keep #lib loaded: the plugins loaded by init_extraction may still refer to it */
	return;
}
