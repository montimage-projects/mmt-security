/*
 * rule_verif_engine.h
 *
 *  Created on: Oct 14, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 *
 *  Verify a rule.
 *  This manages: create/free all fsm instances of a rule.
 */

#ifndef SRC_LIB_RULE_VERIF_ENGINE_H_
#define SRC_LIB_RULE_VERIF_ENGINE_H_

#include "mmt_lib.h"
#include "plugin_header.h"
#include "mmt_fsm.h"

/*
 * rule_engine_t is opaque here: the generated rules include this header
 * (gen_code.c), so none of its fields may be visible to them, otherwise
 * its layout becomes part of the plugin ABI (doc/rule-abi-stability.md).
 * The engine's own TUs include rule_verif_engine_internal.h, which
 * defines it.
 */
typedef struct rule_engine_struct rule_engine_t;

//max number of events in a rule
//max number of instances of a rule at any moment
rule_engine_t* rule_engine_init( const rule_info_t *rule_info, size_t max_instances_count );

enum verdict_type rule_engine_process( rule_engine_t *engine, message_t *message );

void rule_engine_free( rule_engine_t *engine );

const mmt_array_t* rule_engine_get_valide_trace( const rule_engine_t *_engine );

/**
 * The data pointers of the proto.att of the rule, resolved once from the
 * message being verified (see rule_verif_engine_internal.h): element i is
 * the data of rule_info_t.proto_atts[i], or NULL when the message has no
 * value for it.
 * A generated guard reaches its current-message variables through this
 * function, with the engine of fsm_get_user_data( fsm ). It is a real
 * exported function, never inline, so that the layout of rule_engine_t
 * stays out of the rule .so: since 1.2.22 this function, not the struct,
 * is what a rule .so shares with the engine.
 * @return NULL if #engine is NULL or the rule has no proto.att
 */
const void * const *mmt_sec_rule_engine_get_msg_values( const rule_engine_t *engine );

#endif /* SRC_LIB_RULE_VERIF_ENGINE_H_ */
