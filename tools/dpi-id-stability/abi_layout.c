/*
 * abi_layout.c - print the layout of the structs a rule .so shares with the
 * engine (issue #5, A0). Compiled against src/lib of one mmt-security tag by
 * abi-layout.sh. One line per struct: name size {field@offset:size ...}
 * The same structs as mmt_sec_get_rule_abi_layout (src/lib/rule_build_info.c),
 * which describes the layout of the engine it is built in. The HAS_* macros
 * are set by abi-layout.sh from the headers of the tag.
 */
#include <stdio.h>
#include <stddef.h>
#include "plugin_header.h"
#include "mmt_fsm.h"
#include "mmt_alloc.h"
#ifdef HAS_MSG_VALUES_FIELD
#include "rule_verif_engine.h"
#endif

#define F(T, f) printf( " %s@%zu:%zu", #f, offsetof( T, f ), sizeof( ((T *)0)->f ) )
#define S(T) printf( "%s %zu", #T, sizeof( T ) )
#define E() printf( "\n" )

int main( void ){
	S(proto_attribute_t); F(proto_attribute_t, proto); F(proto_attribute_t, att);
	F(proto_attribute_t, proto_id); F(proto_attribute_t, att_id);
	F(proto_attribute_t, data_type); F(proto_attribute_t, dpi_type); E();
#ifdef HAS_VERSION_INFO
	S(rule_version_info_t); F(rule_version_info_t, created_date); F(rule_version_info_t, hash);
	F(rule_version_info_t, number); F(rule_version_info_t, index); F(rule_version_info_t, dpi); E();
#endif
	S(rule_info_t); F(rule_info_t, id); F(rule_info_t, type_id); F(rule_info_t, type_string);
	F(rule_info_t, description); F(rule_info_t, if_satisfied); F(rule_info_t, if_not_satisfied);
	F(rule_info_t, proto_atts_count); F(rule_info_t, events_count); F(rule_info_t, proto_atts);
	F(rule_info_t, proto_atts_events); F(rule_info_t, excluded_filter); F(rule_info_t, create_instance);
	F(rule_info_t, hash_message);
#ifdef HAS_VERSION_INFO
	F(rule_info_t, version);
#endif
#ifdef HAS_INSTANCE_KEYS
	F(rule_info_t, instance_keys);
#endif
	E();
	S(message_element_t); F(message_element_t, proto_id); F(message_element_t, att_id);
	F(message_element_t, data_type); F(message_element_t, data); E();
	S(message_t); F(message_t, counter); F(message_t, timestamp); F(message_t, elements);
	F(message_t, elements_count); F(message_t, hash); E();
	S(mmt_array_t); F(mmt_array_t, elements_count); F(mmt_array_t, data); E();
#ifdef HAS_INSTANCE_KEYS
	S(fsm_instance_key_component_t); F(fsm_instance_key_component_t, msg_att_index);
	F(fsm_instance_key_component_t, his_event_id); F(fsm_instance_key_component_t, his_att_index);
	F(fsm_instance_key_component_t, data_type); E();
	S(fsm_instance_key_t); F(fsm_instance_key_t, components_count); F(fsm_instance_key_t, components); E();
#endif
	S(fsm_delay_t); F(fsm_delay_t, time_min); F(fsm_delay_t, time_max);
	F(fsm_delay_t, time_min_sign); F(fsm_delay_t, time_max_sign);
	F(fsm_delay_t, counter_min); F(fsm_delay_t, counter_max);
	F(fsm_delay_t, counter_min_sign); F(fsm_delay_t, counter_max_sign); E();
	S(fsm_transition_t); F(fsm_transition_t, event_type); F(fsm_transition_t, guard);
	F(fsm_transition_t, action); F(fsm_transition_t, target_state); E();
	S(fsm_state_t); F(fsm_state_t, delay); F(fsm_state_t, is_temporary); F(fsm_state_t, description);
	F(fsm_state_t, transitions); F(fsm_state_t, transitions_count);
	F(fsm_state_t, entry_action); F(fsm_state_t, exit_action); E();
	//only the fields the inline helpers of the guards read
	S(fsm_t); F(fsm_t, execution_trace); F(fsm_t, user_data); E();
	S(mmt_memory_t); F(mmt_memory_t, ref_count); F(mmt_memory_t, size); F(mmt_memory_t, data); E();
	//what the generated guards read of rule_engine_t
#if defined HAS_MSG_VALUES_ACCESSOR
	printf( "rule_engine_t opaque mmt_sec_rule_engine_get_msg_values\n" );
#elif defined HAS_MSG_VALUES_FIELD
	S(rule_engine_t); F(rule_engine_t, msg_values); E();
#else
	printf( "rule_engine_t not read\n" );
#endif
	return 0;
}
