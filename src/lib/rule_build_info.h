/*
 * rule_build_info.h
 *
 * Build information embedded in every rule .so by compile_rule (fork issue #6):
 * the rule ABI, the mmt-security and mmt-dpi versions, the (proto, att) ids the
 * rule uses, the DPI plugins it needs, and the build environment.
 *
 * A generated rule exports it as a JSON string through
 *     const char *mmt_sec_get_rule_build_info( void );
 * and stores the same bytes in an ELF note (section .note.mmt.build, owner
 * "MMT", type MMT_SEC_BUILD_NOTE_TYPE), readable without loading the .so.
 * The fields are documented in doc/rule.md.
 */

#ifndef SRC_LIB_RULE_BUILD_INFO_H_
#define SRC_LIB_RULE_BUILD_INFO_H_

#include <stddef.h>
#include <stdint.h>

/** Version of the JSON layout below. Bump it when a field changes meaning. */
#define MMT_SEC_BUILD_INFO_SCHEMA  1

/** Name of the function a rule .so exports (without RULE_SUFFIX) */
#define MMT_SEC_BUILD_INFO_SYMBOL  "mmt_sec_get_rule_build_info"

/** ELF note holding the same JSON */
#define MMT_SEC_BUILD_NOTE_SECTION ".note.mmt.build"
#define MMT_SEC_BUILD_NOTE_OWNER   "MMT"
/* "MMT\1": a type no tool knows, so readelf prints it as unknown, not as NT_VERSION */
#define MMT_SEC_BUILD_NOTE_TYPE    0x4d4d5401

typedef const char *(*mmt_sec_get_rule_build_info_fn_t)( void );

/**
 * One (proto, att) used by the rules of a .so, with the ids baked into it.
 */
typedef struct rule_build_info_id_struct{
	const char *proto;
	const char *att;
	uint32_t proto_id;
	uint32_t att_id;
	int dpi_type;
}rule_build_info_id_t;

/**
 * Lowercase hex SHA-256 of a buffer. #out must hold 65 bytes.
 */
void mmt_sec_sha256_hex( const void *data, size_t len, char out[65] );

/**
 * Lowercase hex SHA-256 of a file. Returns 0 on success.
 */
int mmt_sec_sha256_file_hex( const char *path, char out[65] );

/**
 * Canonical description of the layout of the structures a rule .so shares
 * with the engine (rule_info_t, proto_attribute_t, rule_version_info_t, the
 * message_t fields read by rule code, mmt_array_t) and of the required plugin
 * version (REQUIRE_PLUGIN). Two builds whose layouts differ get different
 * strings. The string is static: do not free it.
 */
const char *mmt_sec_get_rule_abi_layout( void );

/**
 * "sha256:<hex>" of #mmt_sec_get_rule_abi_layout. Static: do not free it.
 */
const char *mmt_sec_get_rule_abi_hash( void );

/**
 * Canonical hash of the (proto, att) ids a rule .so bakes in:
 *  sort the unique pairs by (proto, att) byte-wise, write one line
 *  "proto,proto_id,att,att_id,dpi_type\n" per pair, hash the result.
 * #out receives "sha256:<hex>" and must hold 72 bytes.
 * The order of #ids does not matter; #ids is sorted in place.
 */
void mmt_sec_rule_ids_hash( rule_build_info_id_t *ids, size_t count, char out[72] );

/**
 * Highest GLIBC_x.y symbol version a shared object needs (its .gnu.version_r),
 * e.g. "GLIBC_2.17". Only native ELF files are read.
 * Returns 0 on success, -1 when the file cannot be read or needs no GLIBC_ version.
 */
int mmt_sec_elf_glibc_min( const char *so_path, char *out, size_t out_size );

/**
 * Read the JSON of the .note.mmt.build note of a shared object, without
 * loading it. Returns a malloc-ed string (free it), or NULL if there is no note.
 */
char *mmt_sec_elf_read_build_note( const char *so_path );

/**
 * Options of compile_rule that end up in the build info
 */
typedef struct rule_build_options_struct{
	const char *xml_file;   /**< rule file, its sha256 is recorded */
	const char *cflags;     /**< flags used to compile the .so, NULL when only C code is generated */
	const char *glibc_min;  /**< highest GLIBC_ version the .so needs, NULL if unknown */
	const char *dpi_header_version; /**< mmt_version() of src/dpi/mmt_dpi.h, where the ids come from */
}rule_build_options_t;

/**
 * Create the build-info JSON of a .so containing #rule_count rules.
 * The compiler is not known when the C code is generated (it is the compiler
 * that compiles that code), so the JSON contains the placeholder
 * MMT_SEC_BUILD_INFO_CC_PLACEHOLDER (inside a JSON string) that gen_code.c
 * replaces with a preprocessor macro.
 * Returns a malloc-ed string (free it).
 */
#define MMT_SEC_BUILD_INFO_CC_PLACEHOLDER "@MMT_SEC_RULE_CC@"
char *mmt_sec_create_rule_build_info( const rule_build_options_t *opt,
		const uint32_t *rule_ids, size_t rule_count,
		rule_build_info_id_t *ids, size_t ids_count );

#endif /* SRC_LIB_RULE_BUILD_INFO_H_ */
