#include "topology.h"

/*
 * detect if the plugin should handle this entry and return the entry type
 */
int
ipa_topo_check_entry_type(Slapi_Entry *entry)
{
    int ret = TOPO_IGNORE_ENTRY;
    Slapi_DN *add_dn = NULL;
    char **ocs;

    add_dn = slapi_entry_get_sdn(entry);
    if (slapi_sdn_issuffix(add_dn,ipa_topo_get_plugin_shared_topo_dn())) {
        /* check if it is a toplogy or a segment */
        /* check if segment's left or right node is the local server*/
        int i;
        ocs = slapi_entry_attr_get_charray(entry,"objectclass");

        for (i=0; ocs && ocs[i]; i++) {
            if (strcasecmp(ocs[i],"ipaReplTopoConf") == 0) {
		ret = TOPO_CONFIG_ENTRY;
                break;
            } else if (strcasecmp(ocs[i],"ipaReplTopoSegment") == 0) {
		ret = TOPO_SEGMENT_ENTRY;
                break;
            }
        }
    } else if (slapi_sdn_isparent(ipa_topo_get_plugin_shared_hosts_dn(),add_dn)) {
        ret = TOPO_HOST_ENTRY;
    } else if (slapi_sdn_issuffix(add_dn,ipa_topo_get_domain_level_entry_dn())) {
        ret = TOPO_DOMLEVEL_ENTRY;
    }

    return ret;
}
int
ipa_topo_post_add(Slapi_PBlock *pb)
{
    int result = SLAPI_PLUGIN_SUCCESS;
    int entry_type;
    Slapi_Entry *add_entry = NULL;

    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                    "--> ipa_topo_post_add\n");

    /* 1. get entry  */
    slapi_pblock_get(pb,SLAPI_ENTRY_POST_OP,&add_entry);

    if (add_entry == NULL) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM, "no entry\n");
        return 1;
    }
    /* 2. check if it is in scope and type
     * and if plugin is active
     */
    entry_type = ipa_topo_check_entry_type(add_entry);
    if (0 == ipa_topo_get_plugin_active() &&
        entry_type != TOPO_DOMLEVEL_ENTRY) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                    "<-- ipa_topo_post_add - plugin not active\n");
        return 0;
    }
    switch (entry_type) {
    case TOPO_CONFIG_ENTRY:
        /* initialize the shared topology data for a replica */
        ipa_topo_util_suffix_init(add_entry);
        break;
    case TOPO_SEGMENT_ENTRY: {
        TopoReplicaSegment *tsegm = NULL;
        TopoReplica *tconf = ipa_topo_util_get_conf_for_segment(add_entry);
        char *status;
        if (tconf == NULL) {
            slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_post_add - config area for segment not found\n");
            break;
        }
        /* TBD check that one node is the current server and
         * that the other node is also managed by the
         * shared config.
         * If all checks pass create the replication agreement
         */
        tsegm =  ipa_topo_util_segment_from_entry(tconf, add_entry);
        status = slapi_entry_attr_get_charptr(add_entry, "ipaReplTopoSegmentStatus");
        if (status == NULL || strcasecmp(status,"autogen")) {
            ipa_topo_util_missing_agmts_add(tconf, tsegm,
                                            ipa_topo_get_plugin_hostname());
        }
        /* keep the new segment in tconf data */
        ipa_topo_cfg_segment_add(tconf, tsegm);
        /* TBD: do we know if the replica already has been initialized ?
         *        should the agreement be enabled ?
         *        For now assume everything is ok and enable
         */
        /* check if it is unidirectional and if other direction exists */
        ipa_topo_util_segment_merge(tconf, tsegm);
        slapi_ch_free_string(&status);
        break;
    }
    case TOPO_HOST_ENTRY: {
        /* we are adding a new master, there could be
         * a segment which so far was inactive since
         * the host was not managed
         */
        /* It will also add to list of managed hosts */
        ipa_topo_util_add_host(add_entry);
        break;
    }
    case TOPO_DOMLEVEL_ENTRY: {
        /* the domain level entry was just added
         * check and set the level, if plugin gets activated
         * do initialization.
         */
        char *domlevel = slapi_entry_attr_get_charptr(add_entry, "ipaDomainLevel");
        ipa_topo_set_domain_level(domlevel);
        ipa_topo_util_check_plugin_active();
        if (ipa_topo_get_plugin_active()) {
            ipa_topo_util_start(0);
        }
        slapi_ch_free_string(&domlevel);
        break;
    }
    case TOPO_IGNORE_ENTRY:
        break;
    }

    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                    "<-- ipa_topo_post_add\n");
    return result;
}
int
ipa_topo_post_mod(Slapi_PBlock *pb)
{
    int result = SLAPI_PLUGIN_SUCCESS;
    int entry_type;
    Slapi_Entry *mod_entry = NULL;
    Slapi_Entry *pre_entry = NULL;
    LDAPMod **mods;

    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                    "--> ipa_topo_post_mod\n");

    /* 1. get entry  */
    slapi_pblock_get(pb,SLAPI_ENTRY_POST_OP,&mod_entry);
    slapi_pblock_get(pb,SLAPI_ENTRY_PRE_OP,&pre_entry);
    slapi_pblock_get(pb, SLAPI_MODIFY_MODS, &mods);

    if (mod_entry == NULL || pre_entry == NULL) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM, "no entry\n");
        return (1);
    }
    /* 2. check if it is in scope */
    entry_type = ipa_topo_check_entry_type(mod_entry);
    if (0 == ipa_topo_get_plugin_active() &&
        entry_type != TOPO_DOMLEVEL_ENTRY) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                    "<-- ipa_topo_post_mod - plugin not active\n");
        return 0;
    }

    switch (entry_type) {
    case TOPO_CONFIG_ENTRY:
        ipa_topo_util_suffix_update(mod_entry, pre_entry, mods);
        break;
    case TOPO_SEGMENT_ENTRY: {
        TopoReplica *tconf = ipa_topo_util_get_conf_for_segment(mod_entry);
        TopoReplicaSegment *tsegm = NULL;
        if (tconf) tsegm = ipa_topo_util_find_segment(tconf, pre_entry);
        if (tsegm == NULL) {
            slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_post_mod - segment to be modified does not exist\n");
            break;
        }
        ipa_topo_util_segment_update(tconf, tsegm, mods,ipa_topo_get_plugin_hostname());
        ipa_topo_util_existing_agmts_update(tconf, tsegm, mods,
                                            ipa_topo_get_plugin_hostname());
        /* also update local segment in tconf */
        break;
        }
    case TOPO_DOMLEVEL_ENTRY: {
        /* the domain level entry was just modified
         * check and set the level, if plugin gets activated
         * do initialization.
         */
        char *domlevel = slapi_entry_attr_get_charptr(mod_entry, "ipaDomainLevel");
        int already_active = ipa_topo_get_plugin_active();
        ipa_topo_set_domain_level(domlevel);
        ipa_topo_util_check_plugin_active();
        if (!already_active && ipa_topo_get_plugin_active()) {
            ipa_topo_util_start(0);
        }
        slapi_ch_free_string(&domlevel);
        break;
    }
    case TOPO_HOST_ENTRY: {
        /* check i host needs to be added to the managed hosts
         * and if segments need to be created */
        ipa_topo_util_update_host(mod_entry, mods);
        break;
    }
    case TOPO_IGNORE_ENTRY:
        break;
    }
    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                    "<-- ipa_topo_post_mod\n");
    return result;
}
int
ipa_topo_post_del(Slapi_PBlock *pb)
{
    int result = SLAPI_PLUGIN_SUCCESS;
    int entry_type;
    Slapi_Entry *del_entry = NULL;

    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                    "--> ipa_topo_post_del\n");

    /* 0. prevent operation on tombstones */
    if (ipa_topo_util_is_tombstone_op(pb)) return 0;

    /* 1. get entry  */
    slapi_pblock_get(pb,SLAPI_ENTRY_PRE_OP,&del_entry);

    if (del_entry == NULL) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM, "no entry\n");
        return 1;
    }
    /* 2. check if it is in scope */
    entry_type = ipa_topo_check_entry_type(del_entry);
    if (0 == ipa_topo_get_plugin_active() &&
        entry_type != TOPO_DOMLEVEL_ENTRY) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                    "<-- ipa_topo_post_del - plugin not active\n");
        return 0;
    }
    switch (entry_type) {
    case TOPO_CONFIG_ENTRY:
        break;
    case TOPO_SEGMENT_ENTRY: {
        /* check if corresponding agreement exists and delete */
        TopoReplica *tconf = ipa_topo_util_get_conf_for_segment(del_entry);
        TopoReplicaSegment *tsegm = NULL;
        int obsolete_segment;
        Slapi_Value *obsolete_sv;

        if (tconf) tsegm = ipa_topo_util_find_segment(tconf, del_entry);
        if (tsegm == NULL) {
            slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "segment to be deleted does not exist\n");
            break;
        }

        obsolete_sv = slapi_value_new_string(SEGMENT_OBSOLETE_STR);
        obsolete_segment = slapi_entry_attr_has_syntax_value(del_entry, "ipaReplTopoSegmentStatus", obsolete_sv);
        slapi_value_free(&obsolete_sv);
        if (!obsolete_segment) {
            /* obsoleted segments are a result of merge, do not remove repl agmt */
            ipa_topo_util_existing_agmts_del(tconf, tsegm,
                                         ipa_topo_get_plugin_hostname());
        }
        /* also remove segment from local topo conf */
        ipa_topo_cfg_segment_del(tconf, tsegm);
        break;
        }
    case TOPO_DOMLEVEL_ENTRY: {
        /* the domain level entry was just deleted
         * this should not happen, but it is identical
         * to setting domlevel to 0
         * log an error and inactivate plugin
         */
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                       "postop_del: domainlevel entry deleted - "
                       "plugin will be inactivated \n");
        break;
    }
    case TOPO_HOST_ENTRY:
        /* deleting an host entry means that the host becomes
         * unmanaged, probably because a replica is removed.
         * remove all marked replication agreements connecting
         * this host.
         */
        ipa_topo_util_delete_host(del_entry);
        ipa_topo_cfg_host_del(del_entry);
        ipa_topo_util_cleanruv(del_entry);
        break;
    case TOPO_IGNORE_ENTRY:
        break;
    }

    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                    "<-- ipa_topo_post_del\n");
    return result;
}
