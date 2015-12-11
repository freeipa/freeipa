
#include "topology.h"

char *ipa_topo_plugin_hostname;
char *ipa_topo_plugin_shared_config_base;
int ipa_topo_plugin_activated;

static Slapi_PluginDesc pdesc = { PLUGIN_NAME, PLUGIN_VENDOR, PLUGIN_VERSION,
                                  IPA_TOPO_PLUGIN_SUBSYSTEM };

static int ipa_topo_start(Slapi_PBlock * pb);
static int ipa_topo_close(Slapi_PBlock * pb);
static int ipa_topo_preop_init(Slapi_PBlock *pb);
static int ipa_topo_postop_init(Slapi_PBlock *pb);
static int ipa_topo_internal_postop_init(Slapi_PBlock *pb);
static int ipa_topo_rootdse_init(Slapi_PBlock *pb);
static int ipa_topo_rootdse_search(Slapi_PBlock *pb, Slapi_Entry* e,
                              Slapi_Entry* entryAfter, int *returncode,
                              char *returntext, void *arg);
void ipa_topo_be_state_change(void *handle, char *be_name,
                              int old_be_state, int new_be_state);

int ipa_topo_init(Slapi_PBlock *pb)
{
    int rc = 0;
    void *ipa_topo_plugin_identity = NULL;

    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                    "--> ipa_topo_init\n");

    /**
     * Store the plugin identity for later use.
     * Used for internal operations
     */

    slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &ipa_topo_plugin_identity);
    ipa_topo_set_plugin_id(ipa_topo_plugin_identity);

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01) != 0
        || slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN, (void *)ipa_topo_start) != 0
        || slapi_pblock_set(pb, SLAPI_PLUGIN_CLOSE_FN, (void *)ipa_topo_close) != 0
        || slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *) &pdesc) != 0) {
        slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "ipa_topo_init: failed to register plugin\n");
        rc = 1;
    }

    if (rc == 0) {
        char *plugin_type = "bepreoperation";
        if (slapi_register_plugin(plugin_type, 1, "ipa_topo_init",
                                  ipa_topo_preop_init, IPA_TOPO_PREOP_DESC,
                                  NULL, ipa_topo_get_plugin_id())) {
            slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_init: failed to register preop plugin\n");
            rc = 1;
        }
    }

    if (rc == 0) {
        char *plugin_type = "postoperation";
        if (slapi_register_plugin(plugin_type, 1, "ipa_topo_init",
                                  ipa_topo_postop_init, IPA_TOPO_POSTOP_DESC,
                                  NULL, ipa_topo_get_plugin_id())) {
            slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_init: failed to register postop plugin\n");
            rc = 1;
        }
    }
    if (rc == 0) {
        char *plugin_type = "internalpostoperation";
        if (slapi_register_plugin(plugin_type, 1, "ipa_topo_internal_init",
                                  ipa_topo_internal_postop_init,
                                  IPA_TOPO_INTERNAL_POSTOP_DESC,
                                  NULL, ipa_topo_get_plugin_id())) {
            slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_init: failed to register internal postop plugin\n");
            rc = 1;
        }
    }

    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                    "<-- ipa_topo_init\n");
    return(rc);
}

static int
ipa_topo_preop_init(Slapi_PBlock *pb)
{
    int rc;

    rc = slapi_pblock_set(pb, SLAPI_PLUGIN_BE_PRE_MODIFY_FN,
                          (void *)ipa_topo_pre_mod);
    rc |= slapi_pblock_set(pb, SLAPI_PLUGIN_BE_PRE_MODRDN_FN,
                          (void *)ipa_topo_pre_modrdn);
    rc |= slapi_pblock_set(pb, SLAPI_PLUGIN_BE_PRE_ADD_FN,
                          (void *)ipa_topo_pre_add);
    rc |= slapi_pblock_set(pb, SLAPI_PLUGIN_BE_PRE_DELETE_FN,
                          (void *)ipa_topo_pre_del);

    return(rc);

}

static int
ipa_topo_postop_init(Slapi_PBlock *pb)
{
    int rc;
    rc = slapi_pblock_set(pb, SLAPI_PLUGIN_POST_ADD_FN,
                          (void *)ipa_topo_post_add);
    rc |= slapi_pblock_set(pb, SLAPI_PLUGIN_POST_DELETE_FN,
                           (void *)ipa_topo_post_del);
    rc |= slapi_pblock_set(pb, SLAPI_PLUGIN_POST_MODIFY_FN,
                           (void *)ipa_topo_post_mod);
    return(rc);
}

static int
ipa_topo_internal_postop_init(Slapi_PBlock *pb)
{
    int rc;
    rc = slapi_pblock_set(pb, SLAPI_PLUGIN_INTERNAL_POST_ADD_FN,
                          (void *)ipa_topo_post_add);
    rc |= slapi_pblock_set(pb, SLAPI_PLUGIN_INTERNAL_POST_DELETE_FN,
                           (void *)ipa_topo_post_del);
    return(rc);
}

int
ipa_topo_setup_managed_servers(void)
{
    int rc = 0;

    /* initially only read the entries below cn=masters
     * and build the list of hostnames
     */
    rc = ipa_topo_util_setup_servers();

    return rc;
}
void
ipa_topo_queue_apply_shared_config(time_t event_time, void *arg)
{
    ipa_topo_apply_shared_config();
}
int
ipa_topo_apply_shared_config(void)
{
    int i = 0;
    int rc = 0;
    char **shared_replica_root = NULL;
    TopoReplica *replica_config = NULL;

    while (0 == ipa_topo_acquire_startup_inprogress()) {
        DS_Sleep(1);
    }

    shared_replica_root = ipa_topo_get_plugin_replica_root();
    while (rc == 0 && shared_replica_root[i]) {
        /* get replica onfig entry from shared tree */
        replica_config = ipa_topo_util_get_replica_conf(shared_replica_root[i]);
        if (NULL == replica_config) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "cannot find replica entry for: %s\n", shared_replica_root[i]);
        } else {
            rc = ipa_topo_apply_shared_replica_config(replica_config);
        }
        i++;
    }
    /* initialize the list of managed servers */
    rc = ipa_topo_setup_managed_servers();

    if (ipa_topo_get_post_init()) {
        /* this server has just been initialized, we reset the init
         * flag in the segments which triggered this init
         */
        i = 0;
        while(shared_replica_root[i]) {
            ipa_topo_util_reset_init(shared_replica_root[i]);
            i++;
        }
        ipa_topo_set_post_init(0);
    }

    ipa_topo_release_startup_inprogress();
    return (rc);
}

int
ipa_topo_apply_shared_replica_config(TopoReplica *replica_config)
{
    TopoReplicaSegmentList *replica_segments = NULL;
    int rc = 0;

    if (replica_config) {
        /* get all segments for the replica from the shared config */
        replica_segments = ipa_topo_util_get_replica_segments(replica_config);
        /* get all replication agreements for replica root */
        rc = ipa_topo_util_update_agmt_list(replica_config, replica_segments);
    }
    return (rc);
}

static int
ipa_topo_start(Slapi_PBlock * pb)
{
    int rc = 0;

    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
        "--> ipa_topo_start\n");

    /* expose info about the plugin via rootdse */
    rc = ipa_topo_rootdse_init(pb);

    /* register callback to handle state changes of backends,
     * required to check changes in domain level after online initialization
     */
    slapi_register_backend_state_change((void *)ipa_topo_be_state_change,
                                         ipa_topo_be_state_change);

    /* init plugin config data from the plugin entry in cn=config */
    rc = ipa_topo_init_plugin_config(pb);
    if (rc != 0) {
        slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "unable to get configuration\n");
        return (rc);
    }

    if (0 == ipa_topo_get_plugin_active()) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "plugin not activated, waiting for increase of domain level\n");
        return rc;
    }

    rc = ipa_topo_util_start(1);
    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
        "<-- ipa_topo_start\n");
    return (rc);
}

static int
ipa_topo_close(Slapi_PBlock * pb)
{

    ipa_topo_set_plugin_active(0);
    slapi_config_remove_callback(SLAPI_OPERATION_SEARCH, DSE_FLAG_PREOP,
            "", LDAP_SCOPE_BASE, "(objectclass=*)", ipa_topo_rootdse_search);
    slapi_unregister_backend_state_change((void *)ipa_topo_be_state_change);
    ipa_topo_free_plugin_config();
    return 0;
}
static int
ipa_topo_rootdse_init(Slapi_PBlock *pb)
{
    int rc = SLAPI_PLUGIN_FAILURE;

    if (slapi_config_register_callback_plugin(SLAPI_OPERATION_SEARCH,
                                        DSE_FLAG_PREOP | DSE_FLAG_PLUGIN,
                                        "", LDAP_SCOPE_BASE, "(objectclass=*)",
                                        ipa_topo_rootdse_search, NULL, pb)) {
        rc = SLAPI_PLUGIN_SUCCESS;
    }

    return rc;
}

static int
ipa_topo_rootdse_search(Slapi_PBlock *pb, Slapi_Entry* e, Slapi_Entry* entryAfter,
                   int *returncode, char *returntext, void *arg)
{

    char *version = slapi_ch_smprintf("%d.%d", ipa_topo_get_plugin_version_major(),
                                               ipa_topo_get_plugin_version_minor());
    slapi_entry_attr_set_charptr(e, "ipaTopologyPluginVersion", version);
    if (ipa_topo_get_plugin_active()) {
        slapi_entry_attr_set_charptr(e, "ipaTopologyIsManaged", "on");
    } else {
        slapi_entry_attr_set_charptr(e, "ipaTopologyIsManaged", "off");
    }

    /* we expose temporarily the domain level in this function, should
     * finally be handled in a plugin managing the domain level
     */
    char *level = slapi_ch_smprintf("%d", ipa_topo_get_domain_level());
    slapi_entry_attr_set_charptr(e, "ipaDomainLevel", level);
    slapi_ch_free_string(&version);
    slapi_ch_free_string(&level);
    return SLAPI_DSE_CALLBACK_OK;
}
void
ipa_topo_be_state_change(void *handle, char *be_name,
                              int old_be_state, int new_be_state)
{
    Slapi_Backend *be=NULL;
    const char *be_suffix;

    /* check if different backends require different actions */
    be = slapi_be_select_by_instance_name(be_name);
    be_suffix = slapi_sdn_get_dn(slapi_be_getsuffix(be, 0));
    if (0 == ipa_topo_cfg_plugin_suffix_is_managed(be_suffix)) {
        /* nothing to do */
        return;
    }

    if (new_be_state == SLAPI_BE_STATE_ON) {
        /* backend came back online - check change in domain level */
        slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "ipa_topo_be_state_change - "
                        "backend %s is coming online; "
                        "checking domain level and init shared topology\n",
                        be_name);
        ipa_topo_util_set_domain_level();
        ipa_topo_util_check_plugin_active();
        if (ipa_topo_get_plugin_active()) {
            ipa_topo_set_post_init(1);
            ipa_topo_util_start(1);
        }
    } else if (new_be_state == SLAPI_BE_STATE_OFFLINE) {
        /* backend is about to be taken down - inactivate plugin */
        slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "ipa_topo_be_state_change"
                        "backend %s is going offline; inactivate plugin\n", be_name);
    } else if (new_be_state == SLAPI_BE_STATE_DELETE) {
        /* backend is about to be removed - disable replication */
        if (old_be_state == SLAPI_BE_STATE_ON) {
             slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_be_state_change"
                            "backend %s is about to be deleted; inactivate plugin\n", be_name);
        }
    }
}
