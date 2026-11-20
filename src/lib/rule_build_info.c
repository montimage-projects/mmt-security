/*
 * rule_build_info.c
 *
 * Build information embedded in every rule .so (fork issue #6).
 * See rule_build_info.h and doc/rule.md.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <ctype.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <elf.h>
#include <link.h>
#include <sys/utsname.h>

#include "rule_build_info.h"
#include "plugin_header.h"
#include "version.h"

/* ---------------------------------------------------------------------------
 * SHA-256 (FIPS 180-4)
 * ------------------------------------------------------------------------- */
typedef struct{
	uint32_t h[8];
	uint64_t len;
	uint8_t  buf[64];
	size_t   buf_len;
}_sha256_t;

static const uint32_t _K[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define _ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void _sha256_block( _sha256_t *s, const uint8_t *p ){
	uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;
	int i;
	for( i = 0; i < 16; i++ )
		w[i] = (uint32_t)p[4*i] << 24 | (uint32_t)p[4*i+1] << 16 | (uint32_t)p[4*i+2] << 8 | p[4*i+3];
	for( i = 16; i < 64; i++ )
		w[i] = w[i-16] + (_ROR(w[i-15], 7) ^ _ROR(w[i-15], 18) ^ (w[i-15] >> 3))
			+ w[i-7] + (_ROR(w[i-2], 17) ^ _ROR(w[i-2], 19) ^ (w[i-2] >> 10));
	a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3];
	e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];
	for( i = 0; i < 64; i++ ){
		t1 = h + (_ROR(e, 6) ^ _ROR(e, 11) ^ _ROR(e, 25)) + ((e & f) ^ (~e & g)) + _K[i] + w[i];
		t2 = (_ROR(a, 2) ^ _ROR(a, 13) ^ _ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
		h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	}
	s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
	s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

static void _sha256_init( _sha256_t *s ){
	static const uint32_t h0[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
	                                0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
	memcpy( s->h, h0, sizeof( h0 ));
	s->len = 0;
	s->buf_len = 0;
}

static void _sha256_update( _sha256_t *s, const void *data, size_t len ){
	const uint8_t *p = data;
	s->len += len;
	while( len > 0 ){
		size_t n = 64 - s->buf_len;
		if( n > len ) n = len;
		memcpy( s->buf + s->buf_len, p, n );
		s->buf_len += n; p += n; len -= n;
		if( s->buf_len == 64 ){
			_sha256_block( s, s->buf );
			s->buf_len = 0;
		}
	}
}

static void _sha256_final_hex( _sha256_t *s, char out[65] ){
	uint64_t bits = s->len * 8;
	uint8_t pad = 0x80, zero = 0, len_be[8];
	int i;
	_sha256_update( s, &pad, 1 );
	while( s->buf_len != 56 )
		_sha256_update( s, &zero, 1 );
	for( i = 0; i < 8; i++ )
		len_be[i] = (uint8_t)( bits >> (56 - 8*i) );
	_sha256_update( s, len_be, 8 );
	for( i = 0; i < 8; i++ )
		snprintf( out + 8*i, 9, "%08x", s->h[i] );
}

void mmt_sec_sha256_hex( const void *data, size_t len, char out[65] ){
	_sha256_t s;
	_sha256_init( &s );
	_sha256_update( &s, data, len );
	_sha256_final_hex( &s, out );
}

int mmt_sec_sha256_file_hex( const char *path, char out[65] ){
	char buf[4096];
	size_t n;
	_sha256_t s;
	FILE *f = fopen( path, "rb" );
	if( f == NULL )
		return -1;
	_sha256_init( &s );
	while( (n = fread( buf, 1, sizeof( buf ), f )) > 0 )
		_sha256_update( &s, buf, n );
	fclose( f );
	_sha256_final_hex( &s, out );
	return 0;
}

/* ---------------------------------------------------------------------------
 * Growing string buffer
 * ------------------------------------------------------------------------- */
typedef struct{
	char  *s;
	size_t len, cap;
}_buf_t;

static void _buf_add_n( _buf_t *b, const char *s, size_t n ){
	if( b->len + n + 1 > b->cap ){
		size_t cap = b->cap ? b->cap : 256;
		while( b->len + n + 1 > cap ) cap *= 2;
		char *p = realloc( b->s, cap );
		if( p == NULL ){
			fprintf( stderr, "Not enough memory\n" );
			abort();
		}
		b->s = p; b->cap = cap;
	}
	memcpy( b->s + b->len, s, n );
	b->len += n;
	b->s[ b->len ] = '\0';
}

static void _buf_add( _buf_t *b, const char *s ){
	_buf_add_n( b, s, strlen( s ));
}

static void _buf_printf( _buf_t *b, const char *fmt, ... ) __attribute__((format(printf, 2, 3)));
static void _buf_printf( _buf_t *b, const char *fmt, ... ){
	char tmp[512];
	va_list ap;
	va_start( ap, fmt );
	int n = vsnprintf( tmp, sizeof( tmp ), fmt, ap );
	va_end( ap );
	if( n < 0 ) return;
	if( (size_t) n < sizeof( tmp )){
		_buf_add_n( b, tmp, n );
		return;
	}
	char *big = malloc( n + 1 );
	if( big == NULL ) abort();
	va_start( ap, fmt );
	vsnprintf( big, n + 1, fmt, ap );
	va_end( ap );
	_buf_add_n( b, big, n );
	free( big );
}

/* JSON string, or null */
static void _buf_json_str( _buf_t *b, const char *s ){
	const unsigned char *p;
	char esc[8];
	if( s == NULL ){
		_buf_add( b, "null" );
		return;
	}
	_buf_add( b, "\"" );
	for( p = (const unsigned char *) s; *p; p++ ){
		switch( *p ){
		case '"':  _buf_add( b, "\\\"" ); break;
		case '\\': _buf_add( b, "\\\\" ); break;
		case '\n': _buf_add( b, "\\n" );  break;
		case '\r': _buf_add( b, "\\r" );  break;
		case '\t': _buf_add( b, "\\t" );  break;
		default:
			if( *p < 0x20 ){
				snprintf( esc, sizeof( esc ), "\\u%04x", *p );
				_buf_add( b, esc );
			}else
				_buf_add_n( b, (const char *)p, 1 );
		}
	}
	_buf_add( b, "\"" );
}

/* ---------------------------------------------------------------------------
 * Rule ABI
 * ------------------------------------------------------------------------- */
#define _F(T, f) _buf_printf( &b, "%s%s@%zu:%zu", first++ ? "," : "", #f, offsetof( T, f ), sizeof( ((T *)0)->f ))
#define _S(T)    do{ first = 0; _buf_printf( &b, "%s%s:%zu{", b.len ? ";" : "", #T, sizeof( T )); }while(0)
#define _E()     _buf_add( &b, "}" )

const char *mmt_sec_get_rule_abi_layout( void ){
	static char *layout = NULL;
	_buf_t b = {0};
	int first;
	if( layout != NULL )
		return layout;

	_S(proto_attribute_t);
	_F(proto_attribute_t, proto); _F(proto_attribute_t, att);
	_F(proto_attribute_t, proto_id); _F(proto_attribute_t, att_id);
	_F(proto_attribute_t, data_type); _F(proto_attribute_t, dpi_type);
	_E();
	_S(rule_version_info_t);
	_F(rule_version_info_t, created_date); _F(rule_version_info_t, hash);
	_F(rule_version_info_t, number); _F(rule_version_info_t, index); _F(rule_version_info_t, dpi);
	_E();
	_S(rule_info_t);
	_F(rule_info_t, id); _F(rule_info_t, type_id); _F(rule_info_t, type_string);
	_F(rule_info_t, description); _F(rule_info_t, if_satisfied); _F(rule_info_t, if_not_satisfied);
	_F(rule_info_t, proto_atts_count); _F(rule_info_t, events_count); _F(rule_info_t, proto_atts);
	_F(rule_info_t, proto_atts_events); _F(rule_info_t, excluded_filter);
	_F(rule_info_t, create_instance); _F(rule_info_t, hash_message); _F(rule_info_t, version);
	_E();
	_S(message_element_t);
	_F(message_element_t, proto_id); _F(message_element_t, att_id);
	_F(message_element_t, data_type); _F(message_element_t, data);
	_E();
	_S(message_t);
	_F(message_t, counter); _F(message_t, timestamp); _F(message_t, flow_id);
	_F(message_t, elements); _F(message_t, elements_count); _F(message_t, hash);
	_F(message_t, user_data);
	_E();
	_S(mmt_array_t);
	_F(mmt_array_t, elements_count); _F(mmt_array_t, data);
	_E();
	_buf_printf( &b, ";require_plugin:%s", mmt_sec_get_required_plugin_version() );

	layout = b.s;
	return layout;
}

const char *mmt_sec_get_rule_abi_hash( void ){
	static char hash[72] = "";
	char hex[65];
	if( hash[0] == '\0' ){
		const char *l = mmt_sec_get_rule_abi_layout();
		mmt_sec_sha256_hex( l, strlen( l ), hex );
		snprintf( hash, sizeof( hash ), "sha256:%s", hex );
	}
	return hash;
}

/* ---------------------------------------------------------------------------
 * DPI ids
 * ------------------------------------------------------------------------- */
static int _cmp_id( const void *a, const void *b ){
	const rule_build_info_id_t *x = a, *y = b;
	int r = strcmp( x->proto, y->proto );
	return r != 0 ? r : strcmp( x->att, y->att );
}

void mmt_sec_rule_ids_hash( rule_build_info_id_t *ids, size_t count, char out[72] ){
	_buf_t b = {0};
	char hex[65];
	size_t i;
	if( count > 0 )
		qsort( ids, count, sizeof( ids[0] ), _cmp_id );
	_buf_add( &b, "" );
	for( i = 0; i < count; i++ )
		_buf_printf( &b, "%s,%u,%s,%u,%d\n", ids[i].proto, ids[i].proto_id,
				ids[i].att, ids[i].att_id, ids[i].dpi_type );
	mmt_sec_sha256_hex( b.s, b.len, hex );
	snprintf( out, 72, "sha256:%s", hex );
	free( b.s );
}

/* ---------------------------------------------------------------------------
 * ELF (native class only)
 * ------------------------------------------------------------------------- */
static uint8_t *_read_file( const char *path, size_t *size ){
	FILE *f = fopen( path, "rb" );
	uint8_t *data;
	long n;
	if( f == NULL )
		return NULL;
	if( fseek( f, 0, SEEK_END ) != 0 || (n = ftell( f )) <= 0 || fseek( f, 0, SEEK_SET ) != 0 ){
		fclose( f );
		return NULL;
	}
	data = malloc( n );
	if( data != NULL && fread( data, 1, n, f ) != (size_t) n ){
		free( data );
		data = NULL;
	}
	fclose( f );
	*size = n;
	return data;
}

/* section headers of a native ELF file, or NULL */
static const ElfW(Shdr) *_elf_sections( const uint8_t *data, size_t size, size_t *count ){
	const ElfW(Ehdr) *eh = (const ElfW(Ehdr) *) data;
#if __SIZEOF_POINTER__ == 8
	const int elf_class = ELFCLASS64;
#else
	const int elf_class = ELFCLASS32;
#endif
	if( size < sizeof( *eh ) || memcmp( eh->e_ident, ELFMAG, SELFMAG ) != 0
			|| eh->e_ident[EI_CLASS] != elf_class || eh->e_shentsize != sizeof( ElfW(Shdr) )
			|| eh->e_shoff == 0 || eh->e_shoff > size
			|| (size - eh->e_shoff) / sizeof( ElfW(Shdr) ) < eh->e_shnum )
		return NULL;
	*count = eh->e_shnum;
	return (const ElfW(Shdr) *)( data + eh->e_shoff );
}

/* compare "GLIBC_2.17" and "GLIBC_2.4" numerically; -2 when b is not a GLIBC_ number */
static int _cmp_glibc( const char *a, const char *b ){
	if( strncmp( b, "GLIBC_", 6 ) != 0 || !isdigit( (unsigned char) b[6] ))
		return -2;
	if( a[0] == '\0' )
		return -1;
	a += 6; b += 6;
	while( *a || *b ){
		long x = strtol( a, (char **)&a, 10 ), y = strtol( b, (char **)&b, 10 );
		if( x != y )
			return x < y ? -1 : 1;
		if( *a == '.' ) a++;
		if( *b == '.' ) b++;
		if( !isdigit( (unsigned char) *a ) && !isdigit( (unsigned char) *b ))
			break;
	}
	return 0;
}

int mmt_sec_elf_glibc_min( const char *so_path, char *out, size_t out_size ){
	size_t size = 0, count = 0, i;
	char best[64] = "";
	uint8_t *data = _read_file( so_path, &size );
	const ElfW(Shdr) *sh;
	if( data == NULL )
		return -1;
	sh = _elf_sections( data, size, &count );
	for( i = 0; sh != NULL && i < count; i++ ){
		const ElfW(Shdr) *str;
		size_t off, n;
		if( sh[i].sh_type != SHT_GNU_verneed || sh[i].sh_link >= count )
			continue;
		str = &sh[ sh[i].sh_link ];
		if( str->sh_offset > size || str->sh_size > size - str->sh_offset
				|| sh[i].sh_offset > size || sh[i].sh_size > size - sh[i].sh_offset )
			continue;
		off = sh[i].sh_offset;
		for( n = 0; n < sh[i].sh_info; n++ ){
			const ElfW(Verneed) *vn;
			size_t aux;
			unsigned j;
			if( off + sizeof( *vn ) > sh[i].sh_offset + sh[i].sh_size )
				break;
			vn  = (const ElfW(Verneed) *)( data + off );
			aux = off + vn->vn_aux;
			for( j = 0; j < vn->vn_cnt; j++ ){
				const ElfW(Vernaux) *va;
				const char *name;
				if( aux + sizeof( *va ) > size )
					break;
				va = (const ElfW(Vernaux) *)( data + aux );
				if( va->vna_name < str->sh_size ){
					name = (const char *)( data + str->sh_offset + va->vna_name );
					if( memchr( name, '\0', str->sh_size - va->vna_name ) != NULL
							&& strlen( name ) < sizeof( best ) && _cmp_glibc( best, name ) == -1 )
						snprintf( best, sizeof( best ), "%s", name );
				}
				if( va->vna_next == 0 )
					break;
				aux += va->vna_next;
			}
			if( vn->vn_next == 0 )
				break;
			off += vn->vn_next;
		}
	}
	free( data );
	if( best[0] == '\0' )
		return -1;
	snprintf( out, out_size, "%s", best );
	return 0;
}

char *mmt_sec_elf_read_build_note( const char *so_path ){
	size_t size = 0, count = 0, i;
	uint8_t *data = _read_file( so_path, &size );
	const ElfW(Shdr) *sh;
	char *ret = NULL;
	if( data == NULL )
		return NULL;
	sh = _elf_sections( data, size, &count );
	for( i = 0; sh != NULL && i < count && ret == NULL; i++ ){
		size_t off, end;
		if( sh[i].sh_type != SHT_NOTE || sh[i].sh_offset > size || sh[i].sh_size > size - sh[i].sh_offset )
			continue;
		off = sh[i].sh_offset;
		end = off + sh[i].sh_size;
		while( off + sizeof( ElfW(Nhdr) ) <= end ){
			const ElfW(Nhdr) *nh = (const ElfW(Nhdr) *)( data + off );
			size_t name_off = off + sizeof( *nh );
			size_t desc_off = name_off + ((nh->n_namesz + 3) & ~3u);
			size_t next     = desc_off + ((nh->n_descsz + 3) & ~3u);
			if( next > end || next <= off )
				break;
			if( nh->n_type == MMT_SEC_BUILD_NOTE_TYPE && nh->n_namesz == sizeof( MMT_SEC_BUILD_NOTE_OWNER )
					&& memcmp( data + name_off, MMT_SEC_BUILD_NOTE_OWNER, sizeof( MMT_SEC_BUILD_NOTE_OWNER )) == 0 ){
				ret = strndup( (const char *)( data + desc_off ), nh->n_descsz );
				break;
			}
			off = next;
		}
	}
	free( data );
	return ret;
}

/* ---------------------------------------------------------------------------
 * Build environment
 * ------------------------------------------------------------------------- */
/* implemented in rule_build_info_dpi.c */
void mmt_sec_rule_build_info_probe_dpi( const rule_build_info_id_t *ids, size_t count,
		char **version, int *ids_match, char **plugins_json );

/* "1.10.3 (6a0afb46)" -> "6a0afb46" */
static char *_commit_of( const char *version ){
	const char *p, *q;
	if( version == NULL || (p = strchr( version, '(' )) == NULL || (q = strchr( p, ')' )) == NULL )
		return NULL;
	return strndup( p + 1, q - p - 1 );
}

static char *_os_name( void ){
	char line[512];
	FILE *f = fopen( "/etc/os-release", "r" );
	struct utsname u;
	if( f != NULL ){
		while( fgets( line, sizeof( line ), f ) != NULL )
			if( strncmp( line, "PRETTY_NAME=", 12 ) == 0 ){
				char *v = line + 12, *e;
				fclose( f );
				if( *v == '"' ) v++;
				e = v + strcspn( v, "\"\n" );
				return strndup( v, e - v );
			}
		fclose( f );
	}
	if( uname( &u ) == 0 )
		return strdup( u.sysname );
	return NULL;
}

static char *_target_triple( void ){
	char line[256];
	FILE *p = popen( "/usr/bin/gcc -dumpmachine 2>/dev/null", "r" );
	char *ret = NULL;
	if( p == NULL )
		return NULL;
	if( fgets( line, sizeof( line ), p ) != NULL ){
		line[ strcspn( line, "\r\n" ) ] = '\0';
		if( line[0] )
			ret = strdup( line );
	}
	pclose( p );
	return ret;
}

static char *_builder( void ){
	const char *v = getenv( "MMT_SEC_BUILDER" );
	char host[256], *ret;
	if( v != NULL && v[0] )
		return strdup( v );
	if( getenv( "GITHUB_ACTIONS" ) != NULL && getenv( "GITHUB_RUN_ID" ) != NULL ){
		const char *server = getenv( "GITHUB_SERVER_URL" ), *repo = getenv( "GITHUB_REPOSITORY" );
		const char *attempt = getenv( "GITHUB_RUN_ATTEMPT" );
		size_t n = 64 + strlen( server ? server : "" ) + strlen( repo ? repo : "" )
			+ strlen( getenv( "GITHUB_RUN_ID" )) + strlen( attempt ? attempt : "" );
		ret = malloc( n );
		if( ret == NULL ) return NULL;
		snprintf( ret, n, "%s/%s/actions/runs/%s%s%s", server ? server : "https://github.com",
				repo ? repo : "?", getenv( "GITHUB_RUN_ID" ), attempt ? "/attempts/" : "", attempt ? attempt : "" );
		return ret;
	}
	if( gethostname( host, sizeof( host )) != 0 )
		return NULL;
	host[ sizeof( host ) - 1 ] = '\0';
	ret = malloc( strlen( host ) + 6 );
	if( ret != NULL )
		sprintf( ret, "host:%s", host );
	return ret;
}

/* build date: SOURCE_DATE_EPOCH when set, for reproducible builds */
static void _build_date( char *out, size_t size ){
	const char *e = getenv( "SOURCE_DATE_EPOCH" );
	time_t t = ( e != NULL && e[0] ) ? (time_t) strtoll( e, NULL, 10 ) : time( NULL );
	struct tm tm;
	gmtime_r( &t, &tm );
	strftime( out, size, "%Y-%m-%dT%H:%M:%SZ", &tm );
}

char *mmt_sec_create_rule_build_info( const rule_build_options_t *opt,
		const uint32_t *rule_ids, size_t rule_count,
		rule_build_info_id_t *ids, size_t ids_count ){
	_buf_t b = {0};
	char xml_hash[65], ids_hash[72], date[32];
	char *s, *installed = NULL, *plugins = NULL;
	const char *header_version = opt ? opt->dpi_header_version : NULL;
	int ids_match = -1;
	size_t i;

	mmt_sec_rule_ids_hash( ids, ids_count, ids_hash ); /* also sorts #ids */
	mmt_sec_rule_build_info_probe_dpi( ids, ids_count, &installed, &ids_match, &plugins );

	_buf_printf( &b, "{\"schema\":%d", MMT_SEC_BUILD_INFO_SCHEMA );

	_buf_add( &b, ",\"rule_ids\":[" );
	for( i = 0; i < rule_count; i++ )
		_buf_printf( &b, "%s%u", i ? "," : "", rule_ids[i] );
	_buf_add( &b, "]" );

	_buf_add( &b, ",\"xml\":{\"file\":" );
	{
		const char *base = opt && opt->xml_file ? strrchr( opt->xml_file, '/' ) : NULL;
		_buf_json_str( &b, base ? base + 1 : ( opt ? opt->xml_file : NULL ));
	}
	_buf_add( &b, ",\"sha256\":" );
	_buf_json_str( &b, opt && opt->xml_file && mmt_sec_sha256_file_hex( opt->xml_file, xml_hash ) == 0 ? xml_hash : NULL );
	_buf_add( &b, "}" );

	_buf_add( &b, ",\"rule_abi\":{\"hash\":" );
	_buf_json_str( &b, mmt_sec_get_rule_abi_hash() );
	_buf_add( &b, ",\"plugin_version\":" );
	_buf_json_str( &b, mmt_sec_get_required_plugin_version() );
	_buf_add( &b, "}" );

	_buf_add( &b, ",\"mmt_security\":{\"version\":" );
	_buf_json_str( &b, mmt_sec_get_version_number() );
	_buf_add( &b, ",\"git\":" );
	_buf_json_str( &b, mmt_sec_get_version_hash() );
	_buf_printf( &b, ",\"index\":%u}", mmt_sec_get_version_index() );

	_buf_add( &b, ",\"dpi\":{\"ids_from\":" );
	_buf_json_str( &b, header_version );
	_buf_add( &b, ",\"ids_from_commit\":" );
	s = _commit_of( header_version );
	_buf_json_str( &b, s );
	free( s );
	_buf_add( &b, ",\"installed\":" );
	_buf_json_str( &b, installed );
	_buf_add( &b, ",\"installed_commit\":" );
	s = _commit_of( installed );
	_buf_json_str( &b, s );
	free( s );
	_buf_printf( &b, ",\"ids_match_installed\":%s", ids_match < 0 ? "null" : ids_match ? "true" : "false" );
	_buf_add( &b, ",\"ids_hash\":" );
	_buf_json_str( &b, ids_hash );
	_buf_add( &b, ",\"ids\":[" );
	for( i = 0; i < ids_count; i++ ){
		_buf_add( &b, i ? ",[" : "[" );
		_buf_json_str( &b, ids[i].proto );
		_buf_printf( &b, ",%u,", ids[i].proto_id );
		_buf_json_str( &b, ids[i].att );
		_buf_printf( &b, ",%u,%d]", ids[i].att_id, ids[i].dpi_type );
	}
	_buf_add( &b, "],\"plugins\":" );
	_buf_add( &b, plugins ? plugins : "null" );
	_buf_add( &b, "}" );

	_buf_add( &b, ",\"build\":{\"compiler\":\"" MMT_SEC_BUILD_INFO_CC_PLACEHOLDER "\",\"target\":" );
	s = _target_triple();
	_buf_json_str( &b, s );
	free( s );
	_buf_add( &b, ",\"cflags\":" );
	_buf_json_str( &b, opt ? opt->cflags : NULL );
	_buf_add( &b, ",\"glibc_min\":" );
	_buf_json_str( &b, opt ? opt->glibc_min : NULL );
	_buf_add( &b, ",\"os\":" );
	s = _os_name();
	_buf_json_str( &b, s );
	free( s );
	_buf_add( &b, ",\"builder\":" );
	s = _builder();
	_buf_json_str( &b, s );
	free( s );
	_build_date( date, sizeof( date ));
	_buf_add( &b, ",\"date\":" );
	_buf_json_str( &b, date );
	_buf_add( &b, "}}" );

	free( installed );
	free( plugins );
	return b.s;
}
