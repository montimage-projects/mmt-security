/*
 * rule_verif_engine_internal.h
 *
 * Definition of rule_engine_t, private to the engine.
 *
 * Only the engine's own translation units include this header. The code
 * that compile_rule generates must not (it includes rule_verif_engine.h,
 * where rule_engine_t is opaque): a rule .so that read a field of this
 * struct would make its layout part of the plugin ABI. A generated guard
 * reads #msg_values through mmt_sec_rule_engine_get_msg_values() instead
 * (doc/rule-abi-stability.md).
 */

#ifndef SRC_LIB_RULE_VERIF_ENGINE_INTERNAL_H_
#define SRC_LIB_RULE_VERIF_ENGINE_INTERNAL_H_

#include "rule_verif_engine.h"

struct _fsm_tran_index_struct;
struct _fsm_event_index_struct;
struct _fsm_timeout_heap_struct;

typedef struct rule_engine_struct{
	const rule_info_t *rule_info;
	//this fsm is used for execution the first event
	fsm_t *fsm_bootstrap;

	//event_id - fsm_instance: only the nodes whose event has no usable
	//instance key, or whose key cannot be computed for their fsm; keyed
	//nodes live in #event_index buckets instead
	link_node_t **fsm_by_expecting_event_id;
	//event_id - index of the keyed fsm instances awaiting that event
	struct _fsm_event_index_struct **event_index;
	//instance_id - fsm_sub_instance
	link_node_t **fsm_by_instance_id;

	//registration sequence: expecting-event nodes of a same list are
	//verified newest-first, the order the list held them in
	uint64_t next_reg_seq;
	//the timeout nodes of every live instance, ordered by fsm->time_max
	struct _fsm_timeout_heap_struct *timeout_heap;

	mmt_array_t *valid_execution_trace;

	//nubmer of events
	uint32_t events_count;

	uint32_t max_instances_size;
	//number of active instances
	uint32_t instances_count;
	//availabe id to allocate to a new fsm
	uint32_t avail_fsm_id;

	//depending on type of rule (verifying on a single packet or on multi-packets)
	//the processing will be different
	enum verdict_type (*processing_packets)( struct rule_engine_struct *, message_t *);

	/**
	 * An array of n elements having type of uint64_t.
	 * Each element represents required data for one event of the rule
	 */
	mmt_bit_t *events_hash;

	//timestamp and counter of the last message being verified timeout
	uint64_t last_msg_timestamp_timeout;
	uint64_t last_msg_counter_timeout;

	/**
	 * Expecting-event nodes marked dead while the current message is being
	 * verified, chained by _fsm_tran_index_struct.next_dead. They stay in
	 * their lists until the message is done - so the "next" pointers of
	 * the event loops remain valid across _process_a_node() - and are
	 * then unlinked and freed in one pass by _drain_dead_nodes(). It is
	 * NULL outside message processing.
	 */
	struct _fsm_tran_index_struct *dead_nodes;

	/**
	 * Once per message, before any guard runs on it, the data pointer of
	 * each proto.att of the rule is resolved from the message being
	 * verified into #msg_values. A generated guard reads its
	 * current-message variables from here (reaching the engine through
	 * fsm->user_data and mmt_sec_rule_engine_get_msg_values()) instead of re-walking message->elements for every
	 * fsm instance; history (.N) variables still fetch the per-instance
	 * trace message.
	 * #msg_values_idx[i] is the element index of proto_atts[i] in
	 * message->elements - the (proto,att)->element hash computed once at
	 * engine init, so filling is a flat array walk.
	 * Both are NULL when the rule has no proto_atts. Only the thread
	 * owning this engine reads or writes them - no synchronisation needed.
	 */
	const void **msg_values;
	uint16_t    *msg_values_idx;
} rule_engine_t __aligned;

#endif /* SRC_LIB_RULE_VERIF_ENGINE_INTERNAL_H_ */
