/*
 * fsm_bounds.c
 *
 * Crafted states that fire the bounds checks of mmt_fsm.c (fork #48, F2),
 * built and run by check/check-fsm-bounds.sh:
 *
 * - fsm_handle_event() with a transition_index outside the transitions of
 *   the current state must return FSM_NO_STATE_CHANGE and log an mmt_error;
 * - a transition whose event_type does not fit the execution trace makes
 *   fsm->current_event_id out of range for _update_fsm(): it must return
 *   FSM_ERR_ARG and log an mmt_error.
 *
 * Both are corruption precursors: unreachable on valid input, and silent in
 * a release build before the mmt_error calls were added. The program exits
 * 0 when both fire with the expected return values; the script additionally
 * greps the output for the two log lines.
 */
#include <stdio.h>
#include "../src/lib/mmt_fsm.h"

int main( void ){
	/* one transition to a final state; its event_type (10) is deliberately
	 * outside the execution trace: fsm_init with events_count = 4 gives the
	 * trace 5 elements, so firing it makes current_event_id = 10 >= 5 */
	fsm_state_t target = { .transitions_count = 0 };
	fsm_transition_t tran = {
			.event_type    = 10,
			.guard         = NULL,
			.action        = FSM_ACTION_DO_NOTHING,
			.target_state  = &target,
	};
	fsm_state_t init = {
			.transitions       = &tran,
			.transitions_count = 1,
	};
	fsm_t *fsm = fsm_init( &init, &target, &target, &target, 4, 0 );
	fsm_t *new_fsm = NULL;
	message_t *msg = create_message_t();
	enum fsm_handle_event_value ret;
	int rc = 0;

	/* out-of-bounds transition_index: must not fire */
	ret = fsm_handle_event( fsm, 7, msg, &new_fsm );
	if( ret != FSM_NO_STATE_CHANGE || new_fsm != NULL ){
		fprintf( stderr, "oob transition_index: ret=%d, new_fsm=%p\n", ret, (void *)new_fsm );
		rc = 1;
	}

	/* valid index: the transition's event_type overflows the execution
	 * trace => _update_fsm must reject it */
	ret = fsm_handle_event( fsm, 0, msg, &new_fsm );
	if( ret != FSM_ERR_ARG || new_fsm != NULL ){
		fprintf( stderr, "oob current_event_id: ret=%d, new_fsm=%p\n", ret, (void *)new_fsm );
		rc = 1;
	}

	fsm_free( fsm );
	free_message_t( msg );
	return rc;
}
