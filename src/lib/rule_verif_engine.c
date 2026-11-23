/*
 * rule_verif_engine.c
 *
 *  Created on: Oct 14, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */
#include "rule_verif_engine.h"
#include "prefetch.h"
#include "mmt_fsm.h"
#include "mmt_security.h"
/**
 * In the next event,
 * the #fsm will fire the #index-th transition of its current state
 */
typedef struct _fsm_tran_index_struct _fsm_tran_index_t;
typedef struct _fsm_key_bucket_struct   _fsm_key_bucket_t;
typedef struct _fsm_event_index_struct  _fsm_event_index_t;
typedef struct _fsm_timeout_entry_struct _fsm_timeout_entry_t;
typedef struct _fsm_timeout_heap_struct  _fsm_timeout_heap_t;

struct _fsm_tran_index_struct{
	uint64_t counter;     //index of the last verified message
	uint64_t seq;         //registration order: a list is verified newest-first
	size_t index;         //index of the transition of the current state of #fsm to be verified
	fsm_t *fsm;           //fsm to be verified
	uint16_t event_id;    //id of the fsm_by_expecting_event_id list holding this node
	uint8_t dead;         //1 once unregistered: unlinked and freed by _drain_dead_nodes
	_fsm_tran_index_t *next_in_fsm;  //next node registered by the same fsm (see fsm_t.reg_nodes)
	_fsm_tran_index_t *next_dead;    //next dead node in rule_engine_t.dead_nodes
	//the wrapper linking this node in its event list or key bucket;
	//NULL for a timeout node, which lives in the heap only
	link_node_t *link;
	//!= NULL: the node is in this key bucket of its event index
	_fsm_key_bucket_t *key_bucket;
	//!= NULL: the node awaits a timeout and is in rule_engine_t.timeout_heap
	_fsm_timeout_entry_t *timeout_entry;
} __aligned;

static inline _fsm_tran_index_t* _create_fsm_tran_index_t( rule_engine_t *_engine, size_t index, fsm_t *fsm, uint64_t counter, uint16_t event_id ){

	_fsm_tran_index_t *ret = mmt_mem_alloc( sizeof( _fsm_tran_index_t));
	ret->index         = index;
	ret->fsm           = fsm;
	ret->counter       = counter;
	ret->event_id      = event_id;
	ret->seq           = ++_engine->next_reg_seq;
	ret->dead          = 0;
	ret->next_in_fsm   = NULL;
	ret->next_dead     = NULL;
	ret->link          = NULL;
	ret->key_bucket    = NULL;
	ret->timeout_entry = NULL;
	return ret;
}

/**
 * Instances awaiting one event are stored in buckets of their key: a
 * message is verified only against the bucket its own key selects, plus
 * the unindexed list. Buckets chain in a slot of #slots.
 */
struct _fsm_key_bucket_struct{
	uint64_t key;
	link_node_t *head;
	_fsm_key_bucket_t *next_in_slot;
};

struct _fsm_event_index_struct{
	const fsm_instance_key_t *spec;
	//element index of each component's history attribute inside a
	//message_t, resolved once at engine init
	uint16_t *his_elem_idx;
	_fsm_key_bucket_t **slots;
	size_t slots_count;
	size_t buckets_count;
};

struct _fsm_timeout_entry_struct{
	uint64_t deadline;    //fsm->time_max when the node registered
	uint64_t seq;         //same ordering as the node
	_fsm_tran_index_t *node;
	uint8_t dead;
};

struct _fsm_timeout_heap_struct{
	//min-heap on (deadline, seq): the next expiring entry is items[0]
	_fsm_timeout_entry_t **items;
	size_t count;
	size_t size;
	//reused buffer collecting the expired entries of one message
	_fsm_timeout_entry_t **collect;
	size_t collect_size;
};

/**
 * Fold #len bytes into #h (FNV-1a). Keys are equal iff the compared
 * values are, so the byte order inside a component does not matter.
 */
static inline uint64_t _key_fold( uint64_t h, const void *data, size_t len ){
	const uint8_t *p = data;
	for( ; len > 0; len--, p++ )
		h = ( h ^ *p ) * UINT64_C(0x100000001b3);
	return h;
}

/**
 * Fold one key component value: the size of its mmt_memory_t block then
 * its bytes - the same semantics mmt_mem_cmp applies in the generated
 * guards. A NULL value can never satisfy the component's equality, so
 * the key cannot be computed.
 */
static inline int _key_fold_value( uint64_t *h, const void *data ){
	const mmt_memory_t *mem;
	if( unlikely( data == NULL ))
		return 0;
	mem = mmt_mem_revert( data );
	*h = _key_fold( *h, &mem->size, sizeof( mem->size ));
	*h = _key_fold( *h, mem->data, mem->size );
	return 1;
}

/**
 * Key of an instance awaiting the event indexed by #idx: fold the
 * values this fsm recorded in the validating message of each
 * component's history event.
 */
static inline int _compute_instance_key( const _fsm_event_index_t *idx, const fsm_t *fsm, uint64_t *key ){
	const fsm_instance_key_component_t *c = idx->spec->components;
	const fsm_instance_key_component_t * const end = c + idx->spec->components_count;
	const message_t *his;
	uint64_t h = UINT64_C(0xcbf29ce484222325);

	for( ; c < end; c++ ){
		if( unlikely( c->his_event_id >= fsm->execution_trace->elements_count ))
			return 0;
		his = fsm->execution_trace->data[ c->his_event_id ];
		if( unlikely( his == NULL ))
			return 0;
		if( unlikely( !_key_fold_value( &h, his->elements[ idx->his_elem_idx[ c - idx->spec->components ]].data )))
			return 0;
	}
	*key = h;
	return 1;
}

/**
 * Key of #engine->msg_values for the same components: the values the
 * message being verified carries for the current-message attributes.
 */
static inline int _compute_message_key( const _fsm_event_index_t *idx, const rule_engine_t *engine, uint64_t *key ){
	const fsm_instance_key_component_t *c = idx->spec->components;
	const fsm_instance_key_component_t * const end = c + idx->spec->components_count;
	uint64_t h = UINT64_C(0xcbf29ce484222325);

	for( ; c < end; c++ )
		if( unlikely( !_key_fold_value( &h, engine->msg_values[ c->msg_att_index ])))
			return 0;
	*key = h;
	return 1;
}

static inline _fsm_key_bucket_t *_bucket_find( _fsm_event_index_t *idx, uint64_t key ){
	_fsm_key_bucket_t *b;
	if( unlikely( idx->slots == NULL ))
		return NULL;
	for( b = idx->slots[ key & ( idx->slots_count - 1 )]; b != NULL; b = b->next_in_slot )
		if( b->key == key )
			return b;
	return NULL;
}

static void _table_grow( _fsm_event_index_t *idx ){
	_fsm_key_bucket_t **slots, *b, *next;
	size_t new_count = idx->slots_count == 0 ? 16 : idx->slots_count * 2;
	size_t i, slot;

	slots = mmt_mem_alloc( new_count * sizeof( _fsm_key_bucket_t * ));
	for( i=0; i<new_count; i++ )
		slots[ i ] = NULL;
	for( i=0; i<idx->slots_count; i++ )
		for( b = idx->slots[i]; b != NULL; b = next ){
			next = b->next_in_slot;
			slot = b->key & ( new_count - 1 );
			b->next_in_slot = slots[ slot ];
			slots[ slot ]   = b;
		}
	if( idx->slots != NULL )
		mmt_mem_free( idx->slots );
	idx->slots       = slots;
	idx->slots_count = new_count;
}

static _fsm_key_bucket_t *_bucket_get_or_create( _fsm_event_index_t *idx, uint64_t key ){
	_fsm_key_bucket_t *b = _bucket_find( idx, key );
	size_t slot;

	if( b != NULL )
		return b;
	if( unlikely( idx->slots_count == 0 || idx->buckets_count >= idx->slots_count ))
		_table_grow( idx );
	b = mmt_mem_alloc( sizeof( _fsm_key_bucket_t ));
	b->key  = key;
	b->head = NULL;
	slot    = key & ( idx->slots_count - 1 );
	b->next_in_slot = idx->slots[ slot ];
	idx->slots[ slot ] = b;
	idx->buckets_count++;
	return b;
}

static void _bucket_destroy( _fsm_event_index_t *idx, _fsm_key_bucket_t *b ){
	_fsm_key_bucket_t **pp = & idx->slots[ b->key & ( idx->slots_count - 1 )];
	for( ; *pp != b; pp = &(*pp)->next_in_slot )
		;
	*pp = b->next_in_slot;
	idx->buckets_count--;
	mmt_mem_force_free( b );
}

/**
 * Min-heap of timeout entries, ordered by (deadline, seq). A node whose
 * fsm reaches fsm->time_max fires the same timeout transition the event-0
 * list fired before - unexpired visits were a no-op - but finding the
 * expiring entries no longer walks every live instance per message.
 */
static inline int _entry_before( const _fsm_timeout_entry_t *a, const _fsm_timeout_entry_t *b ){
	return a->deadline < b->deadline || ( a->deadline == b->deadline && a->seq < b->seq );
}

static _fsm_timeout_heap_t *_heap_create( void ){
	_fsm_timeout_heap_t *heap = mmt_mem_alloc( sizeof( _fsm_timeout_heap_t ));
	heap->count        = 0;
	heap->size         = 16;
	heap->items        = mmt_mem_alloc( heap->size * sizeof( _fsm_timeout_entry_t * ));
	heap->collect      = NULL;
	heap->collect_size = 0;
	return heap;
}

static void _heap_push( _fsm_timeout_heap_t *heap, _fsm_timeout_entry_t *e ){
	size_t i;
	if( unlikely( heap->count == heap->size )){
		_fsm_timeout_entry_t **items = mmt_mem_alloc( heap->size * 2 * sizeof( _fsm_timeout_entry_t * ));
		memcpy( items, heap->items, heap->count * sizeof( _fsm_timeout_entry_t * ));
		mmt_mem_free( heap->items );
		heap->items  = items;
		heap->size  *= 2;
	}
	i = heap->count++;
	while( i > 0 && _entry_before( e, heap->items[ ( i - 1 ) / 2 ])){
		heap->items[ i ] = heap->items[ ( i - 1 ) / 2 ];
		i = ( i - 1 ) / 2;
	}
	heap->items[ i ] = e;
}

static _fsm_timeout_entry_t *_heap_pop( _fsm_timeout_heap_t *heap ){
	_fsm_timeout_entry_t *top, *e;
	size_t i, child;

	if( heap->count == 0 )
		return NULL;
	top = heap->items[ 0 ];
	e   = heap->items[ --heap->count ];
	i   = 0;
	for( ;; ){
		child = 2 * i + 1;
		if( child >= heap->count )
			break;
		if( child + 1 < heap->count && _entry_before( heap->items[ child + 1 ], heap->items[ child ]))
			child++;
		if( !_entry_before( heap->items[ child ], e ))
			break;
		heap->items[ i ] = heap->items[ child ];
		i = child;
	}
	if( heap->count > 0 )
		heap->items[ i ] = e;
	return top;
}

static void _register_timeout_node( rule_engine_t *_engine, _fsm_tran_index_t *fsm_ind ){
	_fsm_timeout_entry_t *e = mmt_mem_alloc( sizeof( _fsm_timeout_entry_t ));
	e->deadline = fsm_ind->fsm->time_max;
	e->seq      = fsm_ind->seq;
	e->node     = fsm_ind;
	e->dead     = 0;
	fsm_ind->timeout_entry = e;
	_heap_push( _engine->timeout_heap, e );
}

/**
 * Index the transitions of #fsm that can be fired in the next event.
 */
static inline
void _set_expecting_events_id( rule_engine_t *_engine, fsm_t *fsm, bool is_add_timeout, uint64_t counter ){
	size_t i;
	uint16_t event_id;
	const fsm_transition_t *tran;
	const fsm_state_t *state = fsm_get_current_state( fsm );
	_fsm_tran_index_t *fsm_ind;

	//from a state: 2 outgoing transitions have 2 different events
#ifdef DEBUG_MODE
	mmt_assert( _engine->events_count >= state->transitions_count,
			"Error: Number of outgoing transition must not be greater than number of events (%zu <= %d)",
			state->transitions_count, _engine->events_count );
#endif

	//for each outgoing transition, we add it to the list of expecting events
	for( i=0; i<state->transitions_count; i++ ){
		//i == 0: timeout => not always

		tran     = &( state->transitions[ i ] );
		event_id = tran->event_type;

		if( event_id == FSM_EVENT_TYPE_TIMEOUT && !is_add_timeout )
			continue;

		//if event having #event_id occurs,
		// then #fsm will fire the i-th transition from its current state
		fsm_ind = _create_fsm_tran_index_t( _engine, i, fsm, counter, event_id );

		if( event_id == FSM_EVENT_TYPE_TIMEOUT )
			//the timeout check the event-0 list applied to every visited
			//node now pops the expiring entries of the min-heap instead
			_register_timeout_node( _engine, fsm_ind );
		else{
			_fsm_event_index_t *idx = _engine->event_index[ event_id ];
			uint64_t key;
			if( idx != NULL && _compute_instance_key( idx, fsm, &key )){
				_fsm_key_bucket_t *b = _bucket_get_or_create( idx, key );
				fsm_ind->key_bucket  = b;
				fsm_ind->link        = insert_node_to_link_list( b->head, fsm_ind );
				b->head              = fsm_ind->link;
			}else{
				//no usable key for this event/fsm: the unindexed list,
				//which every dispatch of the event still walks
				fsm_ind->link = insert_node_to_link_list(
						_engine->fsm_by_expecting_event_id[ event_id], fsm_ind );
				_engine->fsm_by_expecting_event_id[ event_id ] = fsm_ind->link;
			}
		}

		//chain the node on its fsm, so _remove_fsm_from_expecting_events
		//finds every node of #fsm without scanning all the event lists
		fsm_ind->next_in_fsm = (_fsm_tran_index_t *) fsm->reg_nodes;
		fsm->reg_nodes       = fsm_ind;
	}
}

static inline enum verdict_type _get_verdict( int rule_type, enum fsm_handle_event_value result ){
	switch ( rule_type ) {
	case RULE_TYPE_TEST:
		switch( result ){
		case FSM_ERROR_STATE_REACHED:
			return VERDICT_NOT_RESPECTED;
		case FSM_FINAL_STATE_REACHED:
			return VERDICT_RESPECTED;
		default:
			return VERDICT_UNKNOWN;
		}
		break;

	case RULE_TYPE_SECURITY:
		switch( result ){
		case FSM_ERROR_STATE_REACHED:
			return VERDICT_NOT_RESPECTED;
		case FSM_FINAL_STATE_REACHED:
//			return VERDICT_RESPECTED;
			return VERDICT_UNKNOWN;
		default:
			return VERDICT_UNKNOWN;
		}
		break;
	case RULE_TYPE_ATTACK:
	case RULE_TYPE_EVASION:
		switch( result ){
		case FSM_ERROR_STATE_REACHED:
			return VERDICT_UNKNOWN; //VERDICT_NOT_DETECTED;
		case FSM_FINAL_STATE_REACHED:
			return VERDICT_DETECTED;
		default:
			return VERDICT_UNKNOWN;
		}
		break;
	default:
		mmt_halt("Error 22: Property type should be a security rule or an attack.\n");
	}//end of switch
	return VERDICT_UNKNOWN;
}




static inline
void _store_valid_execution_trace( rule_engine_t *_engine, fsm_t *fsm ){
	size_t i;
	const mmt_array_t *array = fsm_get_execution_trace( fsm );

#ifdef DEBUG_MODE
	mmt_assert( array->elements_count == _engine->events_count,
			"Error when processing rule %d: trace_size != event_count( %zu != %"PRIu32")",
			_engine->rule_info->id, array->elements_count, _engine->events_count );
#endif

	for( i=0; i<_engine->events_count; i++ ){
		//free old message
		free_message_t( _engine->valid_execution_trace->data[i] );

		//increase number of references to each message
		_engine->valid_execution_trace->data[i] = mmt_mem_atomic_retain( array->data[i] );
	}
}

/**
 * Public API
 */
const mmt_array_t* rule_engine_get_valide_trace( const rule_engine_t *engine ){
#ifdef DEBUG_MODE
	mmt_assert( engine != NULL, "engine cannot be null" );
#endif

	rule_engine_t *_engine = ( rule_engine_t *)engine;
	return _engine->valid_execution_trace;
}


/**
 * Remove all nodes referencing #fsm from the lists #fsm_by_expecting_event_id.
 * A node registered for a state becomes obsolete once the fsm moves to another
 * state: keeping it would fire its transition index against the wrong state.
 *
 * The nodes are chained on #fsm (fsm_t.reg_nodes, populated by
 * _set_expecting_events_id), so only this fsm's own nodes are visited. They
 * are marked dead, not unlinked: the event loops processing the current
 * message may still hold a pointer to one of them. _drain_dead_nodes()
 * unlinks and frees them once the message is done.
 */
static inline
void _remove_fsm_from_expecting_events( rule_engine_t *_engine, fsm_t *fsm ){
	_fsm_tran_index_t *fsm_ind = (_fsm_tran_index_t *) fsm->reg_nodes, *next;

	while( fsm_ind != NULL ){
		next = fsm_ind->next_in_fsm;

		if( !fsm_ind->dead ){
			fsm_ind->dead = 1;
			//the heap entry dies with its node: popping it frees it
			if( fsm_ind->timeout_entry != NULL )
				fsm_ind->timeout_entry->dead = 1;
			fsm_ind->next_dead = _engine->dead_nodes;
			_engine->dead_nodes = fsm_ind;
		}
		fsm_ind = next;
	}

	fsm->reg_nodes = NULL;
}

/**
 * Unlink and free every expecting-event node marked dead while the current
 * message was being verified. Runs once per message; each node unlinks in
 * O(1) as it records its event_id and the lists are doubly-linked.
 */
static inline
void _drain_dead_nodes( rule_engine_t *_engine ){
	_fsm_tran_index_t *fsm_ind = _engine->dead_nodes, *next;
	link_node_t *node;

	while( fsm_ind != NULL ){
		next = fsm_ind->next_dead;
		node = fsm_ind->link;

		//unlink the node from its expecting-event list or key bucket;
		//a timeout node has no link - the heap frees its entry
		if( node != NULL ){
			if( node->prev != NULL )
				node->prev->next = node->next;
			else if( fsm_ind->key_bucket != NULL )
				fsm_ind->key_bucket->head = node->next;
			else
				_engine->fsm_by_expecting_event_id[ fsm_ind->event_id ] = node->next;
			if( node->next != NULL )
				node->next->prev = node->prev;
			mmt_mem_force_free( node );

			//drop an emptied key bucket so its slot does not fill with
			//dead chains
			if( fsm_ind->key_bucket != NULL && fsm_ind->key_bucket->head == NULL )
				_bucket_destroy( _engine->event_index[ fsm_ind->event_id ], fsm_ind->key_bucket );
		}
		mmt_mem_force_free( fsm_ind );

		fsm_ind = next;
	}
	_engine->dead_nodes = NULL;
}

/**
 * Remove all instances (fsm) having same id with #fsm
 */
static inline
void _reset_engine_for_fsm( rule_engine_t *_engine, fsm_t *fsm ){
	link_node_t *node;
	uint16_t fsm_id = fsm_get_id( fsm );

	//mark dead the nodes of every fsm having #fsm_id: each fsm carries the
	//chain of its own nodes (fsm_t.reg_nodes), so there is no need to scan
	//all the event lists. The nodes are unlinked by _drain_dead_nodes once
	//the current message is done.
	for( node = _engine->fsm_by_instance_id[ fsm_id ]; node != NULL; node = node->next )
		_remove_fsm_from_expecting_events( _engine, (fsm_t *) node->data );

	//remove all fsm having id == #fsm_id and free them
	//TODO: refine
//	_engine->total_instances_count -= count_nodes_from_link_list( _engine->fsm_by_instance_id[ fsm_id ] );
	//mmt_assert( _engine->total_instances_count >= 0, "Cannot be negative. %s:%d", __FILE__, __LINE__ );
	free_link_list_and_data( _engine->fsm_by_instance_id[ fsm_id ], (void *)fsm_free );

	//put it to be available for the other
	_engine->fsm_by_instance_id[ fsm_id ] = NULL;

	//fsm_id become avaiable for other
	_engine->avail_fsm_id = fsm_id;
}

/**
 * Remove only one instance from
 * - (1) list of expecting events, and from
 * - (2) list of instances
 */
static inline
void _reset_engine_for_instance( rule_engine_t *_engine, fsm_t *fsm ){
	uint16_t fsm_id = fsm_get_id( fsm );

	//(1) - remove fsm from the list #fsm_by_expecting_event_id
	_remove_fsm_from_expecting_events( _engine, fsm );

	//(2) - remove fsm from the list of instances
	//TODO: refine
//	_engine->total_instances_count -= count_nodes_from_link_list( _engine->fsm_by_instance_id[ fsm_id ] );
	_engine->fsm_by_instance_id[ fsm_id ] = remove_node_from_link_list(  _engine->fsm_by_instance_id[ fsm_id ], fsm );
	if( _engine->fsm_by_instance_id[ fsm_id ] == NULL )
		_engine->avail_fsm_id = fsm_id;

	fsm_free( fsm );
}

static inline
uint16_t _find_an_available_id( rule_engine_t *_engine ){
	size_t i = _engine->avail_fsm_id;
	for( ; i<_engine->max_instances_size; i++ )
		if( _engine->fsm_by_instance_id[ i ] == NULL ){
			//remember this id being available
			_engine->avail_fsm_id = i;
			return i;
		}

	//not enough
	mmt_halt( "Not enough memory slots for fsm instances when verifying rule %d. Need to increase %s",
			_engine->rule_info->id, mmt_sec_get_config_name(MMT_SEC__CONFIG__SECURITY__MAX_INSTANCES));
	return 0;
}

static inline
enum verdict_type _process_a_node( _fsm_tran_index_t *fsm_ind, uint16_t event_id, message_t *message, rule_engine_t *_engine ){
	fsm_t *fsm = fsm_ind->fsm;
	//fire a specific transition of the current state of #node->fsm
	//the transition has index = #node->tran_index
	enum fsm_handle_event_value val;
	fsm_t *new_fsm = NULL;
	uint16_t new_fsm_id;
	enum verdict_type verdict;

	//mmt_debug( "  transition to verify: %zu", fsm_ind->index );
	val = fsm_handle_event( fsm, fsm_ind->index, message, &new_fsm );

//	mmt_debug( "Verify transition: %zu of fsm %p", fsm_ind->index, fsm );

	//if the execution of the transition having index = fsm_ind->index creates a new fsm
	if( new_fsm != NULL ){
		//a clone inherits its parent's reg_nodes: clear it before the new
		//fsm registers nodes of its own, or they would chain onto the parent
		new_fsm->reg_nodes = NULL;

		//the new fsm being created is an instance of #fsm_bootstrap
		//=> put the new one to a new class
		if( fsm == _engine->fsm_bootstrap ){
			new_fsm_id = _find_an_available_id( _engine );
			fsm_set_id( new_fsm, new_fsm_id );
		}else
			new_fsm_id = fsm_get_id( new_fsm );

		//add the new_fsm to the list of fsm(s) having the same id
		_engine->fsm_by_instance_id[ new_fsm_id  ] = insert_node_to_link_list( _engine->fsm_by_instance_id[ new_fsm_id ], new_fsm );

		//TODO: refine this
//		if( _engine->total_instances_count >= 400 ){
//			rule_engine_free( _engine );
//			mmt_halt( "Too big %s:%d", __FILE__, __LINE__ );
//			mmt_debug("Number of instances: %zu, fsm_id: %d", _engine->total_instances_count, new_fsm_id );
//		}

		fsm = new_fsm;
//		fsm_set_user_data( fsm, _engine );
	}
	else{
		if( val == FSM_STATE_CHANGED ){
			//mmt_debug( "FSM_STATE_CHANGED" );

			//#fsm moved to a new state => all nodes that were registered
			//for the transitions of its previous state become obsolete.
			//They must be removed, not only the node having #event_id:
			//a leftover node would fire its transition index against the
			//new state => wrong, or even out-of-bounds, transition.
			_remove_fsm_from_expecting_events( _engine, fsm );
		}
	}

	switch( val ){
	case FSM_STATE_CHANGED:
		//mmt_debug( "FSM_STATE_CHANGED" );
		//add to new list(s) that waiting for a new event
		//add also TIMEOUT event for the first time of an instance (fsm
		//other than fsm_bootstrap, e.g., created by _fsm_clone)
		_set_expecting_events_id( _engine, fsm, fsm != _engine->fsm_bootstrap,  message->counter );
		break;

	//a final state that is either valid state or invalid one
	//depending on rule type (ATTACK, SECURITY, EVASION, ... ) a different verdict will be given
	case FSM_FINAL_STATE_REACHED:
	case FSM_ERROR_STATE_REACHED:
		verdict = _get_verdict( _engine->rule_info->type_id, val);

		if( verdict == VERDICT_UNKNOWN ){
			//remove the current fsm from validating list
			_reset_engine_for_instance( _engine, fsm );
		}else{
			_store_valid_execution_trace( _engine, fsm );
			//remove all fsm having the same id => stop validating this fsm and its instances (the other fsm having the same id)
			_reset_engine_for_fsm( _engine, fsm );
		}
		return verdict;

	case FSM_INCONCLUSIVE_STATE_REACHED:
		_reset_engine_for_instance( _engine, fsm );
		break;

#ifdef DEBUG_MODE
	case FSM_ERR_ARG:
		mmt_halt( "FSM_ERR_ARG" );
		break;
#endif

	default:
		break;
	}

	return VERDICT_UNKNOWN;
}

/**
 * Public API
 */
enum verdict_type rule_engine_process( rule_engine_t *engine, message_t *message ){
	size_t i;
#ifdef DEBUG_MODE
	mmt_assert( engine != NULL,  "engine cannot be null" );
	mmt_assert( message != NULL, "message cannot be null" );
#endif
	//resolve once per message the data pointers of the rule's proto_atts:
	//every guard and every fsm instance then reads them from #msg_values
	//instead of re-walking message->elements. The message is only read;
	//its content does not change while being verified.
	for( i=0; i<engine->rule_info->proto_atts_count; i++ )
		engine->msg_values[i] = get_element_data_message_t( message, engine->msg_values_idx[i] );
	return engine->processing_packets( engine, message );
}


enum verdict_type _process_single_packet( rule_engine_t *engine, message_t *message ){
	enum verdict_type verdict;
	enum fsm_handle_event_value val;
	const mmt_array_t *array;
	size_t i;

	//check if message contains enough data to verify 2 consecutive events of the rule
	if( ( !mmt_bit_is_contain( &message->hash, &engine->events_hash[ 1 ]) ) ||
		! mmt_bit_is_contain( &message->hash,  &engine->events_hash[ 2 ]) ){

//		mmt_debug("Filtered out %"PRIu64" verify rule %d", message->counter, engine->rule_info->id );
		return VERDICT_UNKNOWN;
	}

//	mmt_debug("%"PRIu64" verify rule %d", message->counter, engine->rule_info->id );

	verdict = VERDICT_UNKNOWN;
	val     = fsm_handle_single_packet( engine->fsm_bootstrap, message );
	switch( val ){
	case FSM_NO_STATE_CHANGE:
		return VERDICT_UNKNOWN;

	//a final state that is either valid state or invalid one
	//depending on rule type (ATTACK, SECURITY, EVASION, ... ) a different verdict will be given
	case FSM_INCONCLUSIVE_STATE_REACHED:
	case FSM_FINAL_STATE_REACHED:
	case FSM_ERROR_STATE_REACHED:
		verdict = _get_verdict( engine->rule_info->type_id, val );

		if( verdict != VERDICT_UNKNOWN )
			_store_valid_execution_trace( engine, engine->fsm_bootstrap );

		//reset #fsm_bootstrap so it is clean for the next tests
		fsm_reset( engine->fsm_bootstrap );

		break;

	case FSM_ERR_ARG:
		mmt_halt( "FSM_ERR_ARG" );
		break;

	default:
		break;
	}

	return verdict;
}


/**
 * Pop the timeout entries expiring before #message->timestamp and verify
 * them in the order the event-0 list held: nodes were inserted at the
 * head of the list, so the list processed them newest-registered first.
 * Entries of instances that survive are pushed back for the next
 * messages; entries of dead nodes are dropped when they pop.
 */
static enum verdict_type _process_expired_timeouts( rule_engine_t *engine, message_t *message ){
	_fsm_timeout_heap_t *heap = engine->timeout_heap;
	_fsm_timeout_entry_t **expired, *e;
	_fsm_tran_index_t *fsm_ind;
	size_t n = 0, i, j;
	enum verdict_type ret = VERDICT_UNKNOWN;

	while( heap->count > 0 && heap->items[ 0 ]->deadline < message->timestamp ){
		e = _heap_pop( heap );
		if( unlikely( e->dead )){
			mmt_mem_force_free( e );
			continue;
		}
		if( unlikely( n == heap->collect_size )){
			_fsm_timeout_entry_t **collect;
			heap->collect_size = heap->collect_size == 0 ? 16 : heap->collect_size * 2;
			collect = mmt_mem_alloc( heap->collect_size * sizeof( _fsm_timeout_entry_t * ));
			if( heap->collect != NULL ){
				memcpy( collect, heap->collect, n * sizeof( _fsm_timeout_entry_t * ));
				mmt_mem_free( heap->collect );
			}
			heap->collect = collect;
		}
		heap->collect[ n++ ] = e;
	}
	if( n == 0 )
		return VERDICT_UNKNOWN;
	expired = heap->collect;

	//newest-registered first, the order the timeout list processed
	//them in; n is the number of expirations per message
	for( i=1; i<n; i++ ){
		e = expired[ i ];
		for( j=i; j>0 && expired[ j-1 ]->seq < e->seq; j-- )
			expired[ j ] = expired[ j-1 ];
		expired[ j ] = e;
	}

	for( i=0; i<n; i++ ){
		e       = expired[ i ];
		fsm_ind = e->node;

		//the processing of an earlier entry of this message may have
		//unregistered this node (#48: never touch a dead node). It is not
		//drained before the message is done, so fsm_ind is still valid;
		//_remove_fsm_from_expecting_events marked its entry dead too, and
		//no other pointer to the entry is left: free it here and only here
		//(the `e->dead || fsm_ind->dead` branch below is not reached)
		if( unlikely( fsm_ind->dead )){
			if( fsm_ind->timeout_entry == e )
				fsm_ind->timeout_entry = NULL;
			mmt_mem_force_free( e );
			continue;
		}

		if( fsm_ind->counter == message->counter ){
			//a node created while this message was being verified is not
			//processed on it - the same skip the counter performs in the
			//list walks
			e->deadline = fsm_ind->fsm->time_max;
			_heap_push( heap, e );
			continue;
		}
		fsm_ind->counter = message->counter;
		//the entry popped out of the heap; it may be re-pushed below
		fsm_ind->timeout_entry = NULL;

		ret = _process_a_node( fsm_ind, FSM_EVENT_TYPE_TIMEOUT, message, engine );

		if( e->dead || fsm_ind->dead )
			//the node was unregistered by _process_a_node: its entry
			//dies with it, and the node itself is drained
			mmt_mem_force_free( e );
		else{
			//the fsm stays in a state whose timeout did not fire (e.g. a
			//temporary or init state the expiry check skips): the list
			//walk visited the node on each next message too
			e->deadline = fsm_ind->fsm->time_max;
			fsm_ind->timeout_entry = e;
			_heap_push( heap, e );
		}
		if( ret != VERDICT_UNKNOWN ){
			//the message stops here: requeue the entries that the list
			//walk would not have reached either
			for( j=i+1; j<n; j++ )
				_heap_push( heap, expired[ j ] );
			break;
		}
	}
	return ret;
}

/**
 * First node of #list holding a node that still has to be verified on
 * the message of index #counter.
 */
static inline link_node_t *_next_candidate( link_node_t *node, uint64_t counter ){
	_fsm_tran_index_t *fsm_ind;
	while( node != NULL ){
		fsm_ind = (_fsm_tran_index_t *) node->data;
		if( !fsm_ind->dead && fsm_ind->counter != counter )
			return node;
		node = node->next;
	}
	return NULL;
}

enum verdict_type _process_multi_packets( rule_engine_t *engine, message_t *message ){
	uint8_t event_id;
	link_node_t *node, *keyed, *pick;
	_fsm_tran_index_t *fsm_ind, *keyed_ind;
	_fsm_event_index_t *idx;
	uint64_t key;
	enum verdict_type ret;

	//mmt_debug( "Verify message counter: %"PRIu64", ts: %"PRIu64, message->counter, message->timestamp );
	//mmt_debug( "===Verify Rule %d=== %zu", _engine->rule_info->id, _engine->max_events_count );

	//the event-0 list checked every instance's timeout on each message,
	//before the other events; the heap pops only the expiring entries,
	//in the same order
	ret = _process_expired_timeouts( engine, message );

	//get from hash table the list of events to be verified; event 0 is
	//the timeout one, handled above
	for( event_id=1; event_id<engine->events_count && ret == VERDICT_UNKNOWN; event_id++ ){

		//message does not contain enough data required by this event
		if( !mmt_bit_is_contain( &message->hash, &engine->events_hash[ event_id ] ))
			continue;

//		mmt_debug( "Event_id : %d", event_id );

		//the unindexed candidates, and the bucket the message's key
		//selects among the indexed ones
		node  = engine->fsm_by_expecting_event_id[ event_id ];
		keyed = NULL;
		idx   = engine->event_index[ event_id ];
		if( idx != NULL && idx->buckets_count > 0
				&& _compute_message_key( idx, engine, &key )){
			_fsm_key_bucket_t *b = _bucket_find( idx, key );
			if( b != NULL )
				keyed = b->head;
		}

		//for each instance waiting for #event_id, one pass in list order.
		//#_process_a_node never frees a node: nodes unregistered while the
		//message is processed are marked dead and removed afterwards by
		//_drain_dead_nodes, so node->next is still valid after the call.
		//Nodes inserted during processing go to the head of their list -
		//before the current position - and are created with
		//message->counter, so they are skipped this round: the same set of
		//firings as the rescan-from-head loop this replaces, without its
		//quadratic cost when a list holds many instances.
		//Both lists are newest-registered first; the merge reproduces the
		//order the single list held before keying.
		node  = _next_candidate( node,  message->counter );
		keyed = _next_candidate( keyed, message->counter );
		while( node != NULL || keyed != NULL ){
			if( keyed == NULL )
				pick = node;
			else if( node == NULL )
				pick = keyed;
			else{
				keyed_ind = (_fsm_tran_index_t *) keyed->data;
				fsm_ind   = (_fsm_tran_index_t *) node->data;
				pick = fsm_ind->seq > keyed_ind->seq ? node : keyed;
			}
			fsm_ind = (_fsm_tran_index_t *) pick->data;
			if( pick == node )
				node = _next_candidate( node->next, message->counter );
			else
				keyed = _next_candidate( keyed->next, message->counter );

			//the message will be processed by this fsm_ind
			fsm_ind->counter = message->counter;

			//get only one verdict per packet
			ret = _process_a_node( fsm_ind, event_id, message, engine );
			if( ret != VERDICT_UNKNOWN )
				break;
		}
	}

	//verify timeout event for each 10 messages or an interval of 100000 usec (0.1s)

	if( ret != VERDICT_UNKNOWN
			|| ( message->counter < engine->last_msg_counter_timeout + 10
					&& message->timestamp < engine->last_msg_timestamp_timeout + 100000 )){
		_drain_dead_nodes( engine );
		return ret;
	}

	engine->last_msg_counter_timeout   = message->counter;
	engine->last_msg_timestamp_timeout = message->timestamp;

	_drain_dead_nodes( engine );
	return ret;
}

//this is defined in mmt_security.c
#ifdef MODULE_ADD_OR_RM_RULES_RUNTIME
uint16_t _mmt_sec_hash_proto_attribute_without_lock( uint32_t proto_id, uint32_t att_id );
#endif
/**
 * Calculate hash of each event
 * This is called only one time at initiation of #_engine
 * @param _engine
 */
static inline void _calculate_hash_number( rule_engine_t *_engine ){
	int i, j, k, index;
	const rule_info_t *rule = _engine->rule_info;
	const mmt_array_t *ev;
	const proto_attribute_t *p;
	bool is_in_excluded_list;
	for( i=0; i<_engine->events_count; i++ ){
		mmt_bit_init( &_engine->events_hash[i] );
		ev = &( rule->proto_atts_events[i] );

		//for each proto.att
		for( j=0; j<ev->elements_count; j++ ){
			p = ev->data[ j ];

			is_in_excluded_list = false;
			//check whether p in the excluded list
			for( k=0; k<rule->excluded_filter[i].elements_count; k++ )
				if( p == rule->excluded_filter[i].data[ k ] ){
					is_in_excluded_list = true;
					mmt_debug("Exclude present checking of %s.%s from event %d of rule %d", p->proto, p->att, i, rule->id );
					break;
				}

			/*
			 * When a rule need to explicitly exclude some proto_att from the filter (done by hash)
			 */
			if( !is_in_excluded_list ){
#ifdef MODULE_ADD_OR_RM_RULES_RUNTIME
				index = _mmt_sec_hash_proto_attribute_without_lock( p->proto_id, p->att_id );
#else
				index = mmt_sec_hash_proto_attribute( p->proto_id, p->att_id );
#endif

				mmt_bit_set( &_engine->events_hash[i], index );
			}
		}

	}
}

/**
 * Keying preserves the exact behaviour of the event lists only while a
 * timeout fire reaches a final state - the generated rules always do:
 * fsm_handle_event then sets fsm->current_event_id before recording the
 * timeout message in the execution trace. A timeout to a non-final
 * state would instead record it under the stale current_event_id, whose
 * value depends on the visits indexing skips; in that (never emitted)
 * case the rule stays unindexed.
 */
static int _fsm_has_nonfinal_timeout( const fsm_state_t *state, const fsm_state_t **visited, size_t visited_count ){
	const fsm_transition_t *tran;
	size_t i;

	if( state == NULL )
		return false;
	for( i=0; i<visited_count; i++ )
		if( visited[ i ] == state )
			return false;
	//a state graph this deep is out of the generator's reach; treat the
	//rule as unsafe rather than guess
	if( visited_count >= 256 )
		return true;
	visited[ visited_count ] = state;

	for( i=0; i<state->transitions_count; i++ ){
		tran = & state->transitions[ i ];
		if( tran->event_type == FSM_EVENT_TYPE_TIMEOUT
				&& tran->target_state != NULL && tran->target_state->transitions_count > 0 )
			return true;
		if( _fsm_has_nonfinal_timeout( tran->target_state, visited, visited_count + 1 ))
			return true;
	}
	return false;
}

/**
 * Build the per-event index spec of #rule for #engine: NULL for the
 * timeout event 0, for events without a usable key, and for every event
 * when the rule cannot be keyed safely.
 */
static void _build_event_index( rule_engine_t *_engine, const rule_info_t *rule ){
	size_t e, j;
	_fsm_event_index_t *idx;
	const fsm_state_t *visited[ 256 ];
	const fsm_instance_key_component_t *c;
	int index;

	_engine->event_index = mmt_mem_alloc( _engine->events_count * sizeof( _fsm_event_index_t * ));
	for( e=0; e<_engine->events_count; e++ )
		_engine->event_index[ e ] = NULL;

	if( rule->instance_keys == NULL
			|| _fsm_has_nonfinal_timeout( _engine->fsm_bootstrap->init_state, visited, 0 ))
		return;

	for( e=1; e<_engine->events_count; e++ ){
		const fsm_instance_key_t *spec = &rule->instance_keys[ e ];
		if( spec->components_count == 0 )
			continue;
		idx = mmt_mem_alloc( sizeof( _fsm_event_index_t ));
		idx->spec          = spec;
		idx->his_elem_idx  = mmt_mem_alloc( spec->components_count * sizeof( uint16_t ));
		idx->slots         = NULL;
		idx->slots_count   = 0;
		idx->buckets_count = 0;
		for( j=0; j<spec->components_count; j++ ){
			c = &spec->components[ j ];
#ifdef MODULE_ADD_OR_RM_RULES_RUNTIME
			index = _mmt_sec_hash_proto_attribute_without_lock(
					rule->proto_atts[ c->his_att_index ].proto_id, rule->proto_atts[ c->his_att_index ].att_id );
#else
			index = mmt_sec_hash_proto_attribute(
					rule->proto_atts[ c->his_att_index ].proto_id, rule->proto_atts[ c->his_att_index ].att_id );
#endif
			idx->his_elem_idx[ j ] = index;
		}
		_engine->event_index[ e ] = idx;
	}
}

/**
 * Public API
 */
rule_engine_t* rule_engine_init( const rule_info_t *rule_info, size_t max_instances_count ){
	size_t i;
	mmt_assert( rule_info != NULL, "rule_info is NULL");
	rule_engine_t *_engine = mmt_mem_alloc( sizeof( rule_engine_t ));

	_engine->fsm_bootstrap      = rule_info->create_instance();
	fsm_set_id( _engine->fsm_bootstrap, 0 );

	_engine->rule_info     = rule_info;
	_engine->events_count  = rule_info->events_count + 1; //event_id start from 1 (0 is timeout)
	mmt_assert( _engine->events_count <= 64, "Cannot hold more than 64 events in a property" );
	_engine->max_instances_size = max_instances_count;
	_engine->instances_count    = 1; //fsm_bootstrap
	_engine->avail_fsm_id       = 0;
	_engine->next_reg_seq = 0;
	_engine->timeout_heap = _heap_create();

	//linked-list of fsm instances indexed by their expected event_id
	_engine->fsm_by_expecting_event_id = mmt_mem_alloc( _engine->events_count * sizeof( void *) );
	for( i=0; i<_engine->events_count; i++ )
		_engine->fsm_by_expecting_event_id[ i ] = NULL;

	//per-event instance index spec, resolved before the first
	//registration buckets nodes
	_build_event_index( _engine, rule_info );

	//add fsm_bootstrap to the list
	_set_expecting_events_id( _engine, _engine->fsm_bootstrap, NO, 0 );

	//linked-list of fsm instances
	_engine->fsm_by_instance_id = mmt_mem_alloc( _engine->max_instances_size * sizeof( void *) );
	for( i=0; i<_engine->max_instances_size; i++ )
		_engine->fsm_by_instance_id[ i ] = NULL;

	//add fsm_bootstrap to the first element of
	_engine->fsm_by_instance_id[ 0 ] = insert_node_to_link_list(_engine->fsm_by_instance_id[ 0 ], _engine->fsm_bootstrap );

	_engine->valid_execution_trace = mmt_array_init( _engine->events_count );

	_engine->events_hash = mmt_mem_alloc( sizeof( mmt_bit_t ) * _engine->events_count );
	_calculate_hash_number( _engine );
	fsm_set_user_data( _engine->fsm_bootstrap, _engine );

	//per-message workspace guards read their current-message variables
	//from (see the fields' comment in rule_verif_engine.h)
	if( rule_info->proto_atts_count == 0 ){
		_engine->msg_values     = NULL;
		_engine->msg_values_idx = NULL;
	}else{
		int index;
		_engine->msg_values     = mmt_mem_alloc( rule_info->proto_atts_count * sizeof( const void * ));
		_engine->msg_values_idx = mmt_mem_alloc( rule_info->proto_atts_count * sizeof( uint16_t ));
		for( i=0; i<rule_info->proto_atts_count; i++ ){
#ifdef MODULE_ADD_OR_RM_RULES_RUNTIME
			index = _mmt_sec_hash_proto_attribute_without_lock( rule_info->proto_atts[i].proto_id, rule_info->proto_atts[i].att_id );
#else
			index = mmt_sec_hash_proto_attribute( rule_info->proto_atts[i].proto_id, rule_info->proto_atts[i].att_id );
#endif
			_engine->msg_values_idx[i] = index;
		}
	}

	_engine->last_msg_counter_timeout = 0;
	_engine->last_msg_timestamp_timeout    = 0;
	_engine->dead_nodes                   = NULL;

	if( fsm_is_verifying_single_packet( _engine->fsm_bootstrap) ){
		_engine->processing_packets = _process_single_packet;
	}else{
		_engine->processing_packets = _process_multi_packets;
	}

	return _engine;
}


/**
 * Public API
 */
void rule_engine_free( rule_engine_t *_engine ){
	size_t i;

	__check_null( _engine, );

	//normally empty: dead nodes are drained at the end of every message;
	//unlink and free any left if the engine is dropped mid-processing
	_drain_dead_nodes( _engine );

	for( i=0; i<_engine->events_count; i++ )
		free_link_list(_engine->fsm_by_expecting_event_id[ i ], YES );

	//the indexed buckets hold nodes of the same type: free each bucket's
	//list then the index
	if( _engine->event_index != NULL ){
		size_t j;
		for( i=0; i<_engine->events_count; i++ )
			if( _engine->event_index[ i ] != NULL ){
				_fsm_event_index_t *idx = _engine->event_index[ i ];
				for( j=0; j<idx->slots_count; j++ ){
					_fsm_key_bucket_t *b = idx->slots[ j ], *next;
					for( ; b != NULL; b = next ){
						next = b->next_in_slot;
						free_link_list( b->head, YES );
						mmt_mem_force_free( b );
					}
				}
				mmt_mem_free( idx->his_elem_idx );
				mmt_mem_free( idx->slots );
				mmt_mem_free( idx );
			}
		mmt_mem_free( _engine->event_index );
	}

	//the timeout entries still in the heap reference nodes that were not
	//drained: free the entries, and the nodes a dead entry orphans
	if( _engine->timeout_heap != NULL ){
		_fsm_timeout_heap_t *heap = _engine->timeout_heap;
		for( i=0; i<heap->count; i++ ){
			if( ! heap->items[ i ]->dead )
				mmt_mem_force_free( heap->items[ i ]->node );
			mmt_mem_force_free( heap->items[ i ] );
		}
		mmt_mem_free( heap->items );
		mmt_mem_free( heap->collect );
		mmt_mem_free( heap );
	}

	mmt_mem_free( _engine->fsm_by_expecting_event_id );
	_engine->events_count = 0;

	for( i=0; i<_engine->max_instances_size; i++ )
		free_link_list_and_data( _engine->fsm_by_instance_id[ i ], (void *)fsm_free );

	mmt_mem_free( _engine->fsm_by_instance_id );
	mmt_mem_free( _engine->events_hash );
	mmt_mem_free( _engine->msg_values );
	mmt_mem_free( _engine->msg_values_idx );

	if( _engine->valid_execution_trace != NULL )
		mmt_array_free( _engine->valid_execution_trace, (void *)free_message_t );

	mmt_mem_free( _engine );
}
