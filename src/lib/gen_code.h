/*
 * gen_code.h
 *
 *  Created on: 4 oct. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#ifndef SRC_LIB_GEN_CODE_H_
#define SRC_LIB_GEN_CODE_H_

#include "base.h"
#include "rule.h"
#include "rule_build_info.h"

int generate_fsm( const char* file_name, rule_t *const*rules, size_t count, const char *embedded_functions );

/**
 * Same as #generate_fsm, with the options recorded in the build info of the
 * rules (fork issue #6). #build_options may be NULL.
 */
int generate_fsm_with_build_options( const char* file_name, rule_t *const*rules, size_t count,
		const char *embedded_functions, const rule_build_options_t *build_options );

/**
 * The gcc flags #compile_gen_code uses, without the input and output files
 */
void compile_gen_code_flags( char *buf, size_t size, const char *incl_dir );

int compile_gen_code( const char *lib_file, const char *code_file, const char *incl_dir );

#endif /* SRC_LIB_GEN_CODE_H_ */
