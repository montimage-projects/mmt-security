/*
 * plugin_engine.h
 *
 *  Created on: Oct 10, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 *
 *  One may change #MMT_SEC_PLUGINS_REPOSITORY and #MMT_SEC_PLUGINS_REPOSITORY_OPT from Makefile
 */

#ifndef SRC_LIB_PLUGIN_ENGINE_H_
#define SRC_LIB_PLUGIN_ENGINE_H_

#ifndef MMT_SEC_PLUGINS_REPOSITORY
	#define MMT_SEC_PLUGINS_REPOSITORY "rules"
#endif

#ifndef INSTALL_DIR
	#define INSTALL_DIR "/opt/mmt/security"
#endif

#ifndef MMT_SEC_PLUGINS_REPOSITORY_OPT
	#define MMT_SEC_PLUGINS_REPOSITORY_OPT INSTALL_DIR "/rules"
#endif

#include "plugin_header.h"

/**
 * Loads all the plugins.
 * - Return
 * 	+ number of loaded rules
 */
size_t load_mmt_sec_rules( rule_info_t const *const** plugins_arr );

/**
 * Loads one plugin.
 * - Return
 * 	+ number of loaded rules
 * - Note: This function creates a new memory segment to store array of plugins.
 * 	==> user need to free it after using
 */
size_t load_mmt_sec_rule( rule_info_t const*const**plugins_arr, const char *plugin_path_name );

/**
 * Loads one plugin already opened by the caller, through its info function.
 * The plugin gets no path: a later rescan of the rules folder neither matches
 * nor reloads it.
 * - Return
 * 	+ number of loaded rules
 * - Note: same precondition as #unload_mmt_sec_rules below: call it only when
 * 	no mmt_sec handler (single or smp) exists, i.e. before #mmt_sec_init or
 * 	after #mmt_sec_close. The runtime path for changing the verified rules
 * 	is #mmt_sec_add_rules / #mmt_sec_remove_rules.
 */
size_t mmt_sec_load_plugin(
		size_t ( *mmt_sec_get_plugin_info ) ( const rule_info_t ** ),
		void (*on_load)(),
		void (*on_unload)() );

/**
 * Unloads rules by id: each removed rule leaves the global rules set; a
 * plugin whose last rule is removed is closed (its .so is dlclose()d) and its
 * slot is freed, then reused by a later load.
 * - Return
 * 	+ number of rules actually removed
 * - Note: this function MUST be called only when no mmt_sec handler (single
 * 	or smp) exists, i.e. before #mmt_sec_init or after #mmt_sec_close: the
 * 	handlers and the engine's own rules set cache rule_info_t and
 * 	rule_engine_t pointers into the plugins' memory, which a dlclose()d
 * 	plugin leaves dangling. The runtime path for changing the verified
 * 	rules is #mmt_sec_remove_rules / #mmt_sec_add_rules: they rebuild the
 * 	per-handler rule sets under a lock and never close a plugin.
 */
size_t unload_mmt_sec_rules( size_t count, const uint32_t* rules_id );


#endif /* SRC_LIB_PLUGIN_ENGINE_H_ */
