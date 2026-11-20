/*
 * abi_layout.c - print the layout of the structs a rule .so shares with the
 * engine (issue #5, A0). Compiled against src/lib of one mmt-security tag by
 * abi-layout.sh. One line per struct: name size {field@offset:size ...}
 */
#include <stdio.h>
#include <stddef.h>
#include "plugin_header.h"

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
	E();
	S(message_element_t); F(message_element_t, proto_id); F(message_element_t, att_id);
	F(message_element_t, data_type); F(message_element_t, data); E();
	S(message_t); F(message_t, counter); F(message_t, timestamp); F(message_t, elements);
	F(message_t, elements_count); F(message_t, hash); E();
	S(mmt_array_t); E();
	return 0;
}
