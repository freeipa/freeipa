#include "topology.h"


int
ipa_topo_util_modify(Slapi_DN *entrySDN, Slapi_Mods *smods)
{
    int rc = 0;
    Slapi_PBlock *mod_pb;
    LDAPMod **mods;

    mod_pb = slapi_pblock_new();
    slapi_pblock_init(mod_pb);

    mods = (slapi_mods_get_ldapmods_passout(smods));
    slapi_modify_internal_set_pb_ext(mod_pb, entrySDN, mods, NULL, NULL,
                                     ipa_topo_get_plugin_id(), 0);
    slapi_modify_internal_pb(mod_pb);
    slapi_pblock_get(mod_pb, SLAPI_PLUGIN_INTOP_RESULT, &rc);
    slapi_pblock_destroy(mod_pb);
    if (rc != 0)
    {
        slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "ipa_topo_util_modify: "
                        "failed to modify entry (%s): error %d\n", slapi_sdn_get_dn(entrySDN), rc);
    }
    return rc;

}

Slapi_Entry *
ipa_topo_util_get_entry (char *dn)
{
    int rc = 0;
    Slapi_Entry *res_entry = NULL;
    Slapi_Entry **entries;
    Slapi_PBlock *pb = NULL;

    pb = slapi_pblock_new();

    slapi_search_internal_set_pb(pb, dn, LDAP_SCOPE_BASE,
                                 "objectclass=*", NULL, 0, NULL, NULL,
                                 ipa_topo_get_plugin_id(), 0);
    slapi_search_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &rc);
    if (rc != 0)
    {
        slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "ipa_topo_util_get_entry: "
                        "unable to read entry (%s): error %d\n", dn, rc);
    } else {
        slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &entries);
        if (NULL == entries || NULL == entries[0]) {
            slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_util_get_entry: entry not found: %s\n", dn);
        } else {
            res_entry = slapi_entry_dup(entries[0]);
        }
    }
    slapi_free_search_results_internal(pb);
    slapi_pblock_destroy(pb);
    return res_entry;
}

/*
 * the plugin needs to determine if segments in the shared topology
 * affect the instance it is running in. There are many ways to determine
 * this "pluginhost":
 * - get the machines hostname
 * - define hostname in plugin conf
 * - use nsslapd-localhost from cn=config
 * - ...
 * This first version will use the nsslapd-localhost
 */
char *
ipa_topo_util_get_pluginhost(void)
{
    int rc = 0;
    Slapi_Entry **entries;
    Slapi_PBlock *pb = NULL;
    char *host = NULL;
    char *host_attrs[] = {"nsslapd-localhost", NULL};

    pb = slapi_pblock_new();

    slapi_search_internal_set_pb(pb, "cn=config", LDAP_SCOPE_BASE,
        "objectclass=*", host_attrs, 0, NULL, NULL,
        ipa_topo_get_plugin_id(), 0);
    slapi_search_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &rc);
    if (rc != 0)
    {
        slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "ipa_topo_util_get_localhost: "
                        "unable to read server configuration: error %d\n", rc);
    } else {
        slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &entries);
        if (NULL == entries || NULL == entries[0]) {
            slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_util_get_localhost: server configuration missing\n");
        } else {
            host = slapi_entry_attr_get_charptr(entries[0], "nsslapd-localhost");
        }
    }

    slapi_free_search_results_internal(pb);
    slapi_pblock_destroy(pb);
    return host;
}

void
ipa_topo_util_check_plugin_active(void)
{
    if (ipa_topo_get_min_domain_level() <= ipa_topo_get_domain_level()) {
        ipa_topo_set_plugin_active(1);
    } else {
        ipa_topo_set_plugin_active(0);
    }
}

void
ipa_topo_util_set_domain_level(void)
{
    int rc = 0;
    Slapi_Entry **entries;
    Slapi_PBlock *pb = NULL;

    pb = slapi_pblock_new();
    slapi_search_internal_set_pb(pb, ipa_topo_get_domain_level_entry(),
                                  LDAP_SCOPE_BASE,
                                  "objectclass=*", NULL, 0, NULL, NULL,
                                  ipa_topo_get_plugin_id(), 0);
    slapi_search_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &rc);
    if (rc != 0)
    {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "ipa_topo_util_set_domain_level: "
                        "failed to lookup domain level entry: error %d\n", rc);
    } else {
        slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &entries);
        if (NULL == entries || NULL == entries[0]) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_util_set_domain_level: domain level"
                            " entry does not exist, use default domain level of 0\n");
            ipa_topo_set_domain_level(NULL);
        } else {
            char *domlevel = slapi_entry_attr_get_charptr(entries[0], "ipaDomainLevel");
            ipa_topo_set_domain_level(domlevel);
            slapi_ch_free_string(&domlevel);
        }
    }
    slapi_free_search_results_internal(pb);
    slapi_pblock_destroy(pb);
}

TopoReplica *
ipa_topo_util_get_replica_conf(char *repl_root)
{
    int rc = 0;
    Slapi_Entry **entries;
    Slapi_PBlock *pb = NULL;
    char *filter;
    TopoReplica *topoRepl = NULL;

    pb = slapi_pblock_new();
    filter = slapi_ch_smprintf("(ipaReplTopoConfRoot=%s)",repl_root);
    slapi_search_internal_set_pb(pb, ipa_topo_get_plugin_shared_topo(),
                                  LDAP_SCOPE_ONELEVEL,
                                  filter, NULL, 0, NULL, NULL,
                                  ipa_topo_get_plugin_id(), 0);
    slapi_search_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &rc);
    if (rc != 0)
    {
        slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "ipa_topo_util_get_replica_conf: "
                        "no replica configuration found: error %d\n", rc);
    } else {
        slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &entries);
        if (NULL == entries || NULL == entries[0]) {
            slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_util_get_replica_conf: "
                            "server configuration missing\n");
        } else {
            topoRepl = ipa_topo_util_replica_init(entries[0]);
        }
    }
    slapi_ch_free_string(&filter);
    slapi_free_search_results_internal(pb);
    slapi_pblock_destroy(pb);

    if (0 == topoRepl) {
        slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "ipa_topo_util_get_replica_conf: "
                        "cannot create replica\n");
    } else if (0 != ipa_topo_cfg_replica_add(topoRepl)) {
        slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "ipa_topo_util_get_replica_conf: "
                        "replica already exists\n");
        ipa_topo_cfg_replica_free(topoRepl);
        topoRepl = NULL;
    }

    return topoRepl;
}

TopoReplicaSegmentList *
ipa_topo_util_get_replica_segments(TopoReplica *replica)
{
    TopoReplicaSegment *repl_segment = NULL;
    int rc = 0;
    Slapi_Entry **entries;
    Slapi_PBlock *pb = NULL;
    char *filter;

    pb = slapi_pblock_new();
    filter = "objectclass=*";
    slapi_search_internal_set_pb(pb, replica->shared_config_base,
                                 LDAP_SCOPE_ONELEVEL, filter, NULL, 0, NULL, NULL,
                                 ipa_topo_get_plugin_id(), 0);
    slapi_search_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &rc);
    if (rc != 0)
    {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "ipa_topo_util_get_replica_segments: "
                        "no replica configuration found: error %d\n", rc);
    } else {
        slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &entries);
        if (NULL == entries || NULL == entries[0]) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_util_get_replica_segments: no segments found\n");
        } else {
            /* get number of segments and allocate */
            int i = 0;
            for (i=0;entries[i];i++) {
                repl_segment = ipa_topo_util_segment_from_entry(replica, entries[i]);
                ipa_topo_cfg_segment_add(replica, repl_segment);
            }
        }
    }
    slapi_free_search_results_internal(pb);
    slapi_pblock_destroy(pb);
    return replica->repl_segments;
}

int
ipa_topo_util_setup_servers(void)
{
    int rc = 0;
    Slapi_Entry **entries;
    Slapi_PBlock *pb = NULL;
    char *filter;

    pb = slapi_pblock_new();
    filter = "objectclass=*";
    slapi_search_internal_set_pb(pb,ipa_topo_get_plugin_shared_hosts(),
                                  LDAP_SCOPE_ONELEVEL,
                                  filter, NULL, 0, NULL, NULL,
                                  ipa_topo_get_plugin_id(), 0);
    slapi_search_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &rc);
    if (rc == LDAP_NO_SUCH_OBJECT) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "ipa_topo_util_setup_servers: "
                        "search for servers failed (continuing): error %d\n", rc);
        /* masters not yet configured, continue plugin startup */
        rc = 0;
    } else if (rc != 0) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "ipa_topo_util_setup_servers: "
                        "search for servers failed: error %d\n", rc);
    } else {
        slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &entries);
        if (NULL == entries || NULL == entries[0]) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_util_setup_servers: no servers found\n");
        } else {
            int i = 0;
            for (i=0;entries[i];i++) {
                ipa_topo_util_init_hosts(entries[i]);
            }
        }
    }
    slapi_free_search_results_internal(pb);
    slapi_pblock_destroy(pb);
    return rc;

}

TopoReplicaAgmt *
ipa_topo_util_agmt_from_entry(Slapi_Entry *entry, char *replRoot, char *fromHost,
                              char *toHost, char *direction)
{
    TopoReplicaAgmt *agmt = NULL;
    char **mattrs = NULL;
    char *mattr = NULL;
    char *mval = NULL;
    int i;

    agmt = (TopoReplicaAgmt *) slapi_ch_calloc(1,sizeof(TopoReplicaAgmt));
    agmt->origin = slapi_ch_strdup(fromHost);
    agmt->target = slapi_ch_strdup(toHost);
    agmt->repl_root = slapi_ch_strdup(replRoot);

    /* use std agmt rdn, it may be updated when matching real agmt is found */
    agmt->rdn = ipa_topo_agmt_std_rdn(toHost);

    mattrs = ipa_topo_get_plugin_managed_attrs();
    for (i=0; mattrs[i]; i++) {
        mattr = slapi_ch_smprintf("%s;%s",mattrs[i],direction);
        mval = slapi_entry_attr_get_charptr(entry,mattr);
        slapi_ch_free_string(&mattr);
        if (mval == 0) {
            mval = slapi_entry_attr_get_charptr(entry,mattrs[i]);
        }
        if (mval) {
            ipa_topo_util_set_segm_attr(agmt, mattrs[i], mval);
        }
    }
    return agmt;
}

int
ipa_topo_util_segm_dir(char *direction)
{
    int dir = -1;
    if (strcasecmp(direction,SEGMENT_DIR_BOTH) == 0){
        dir = SEGMENT_BIDIRECTIONAL;
    } else if (strcasecmp(direction,SEGMENT_DIR_LEFT_ORIGIN) == 0) {
        dir = SEGMENT_LEFT_RIGHT;
    } else if (strcasecmp(direction,SEGMENT_DIR_RIGHT_ORIGIN) == 0) {
        dir = SEGMENT_RIGHT_LEFT;
    }
    return dir;
}

TopoReplicaSegment *
ipa_topo_util_find_segment(TopoReplica *conf, Slapi_Entry *entry)
{
    char *leftHost;
    char *rightHost;
    char *direction;
    TopoReplicaSegment *segment = NULL;

    leftHost = slapi_entry_attr_get_charptr(entry,"ipaReplTopoSegmentLeftNode");
    rightHost = slapi_entry_attr_get_charptr(entry,"ipaReplTopoSegmentRightNode");
    direction = slapi_entry_attr_get_charptr(entry,"ipaReplTopoSegmentDirection");

    segment = ipa_topo_cfg_segment_find(conf->repl_root, leftHost, rightHost, ipa_topo_util_segm_dir(direction));

    slapi_ch_free((void **)&leftHost);
    slapi_ch_free((void **)&rightHost);
    slapi_ch_free((void **)&direction);
    return segment;
}

TopoReplicaSegment *
ipa_topo_util_segment_from_entry(TopoReplica *conf, Slapi_Entry *entry)
{
    char *leftHost;
    char *rightHost;
    char *direction;
    char *name;
    char *state;

    TopoReplicaSegment *segment = NULL;
    segment = (TopoReplicaSegment *) slapi_ch_calloc(1,sizeof(TopoReplicaSegment));
    leftHost = slapi_entry_attr_get_charptr(entry,"ipaReplTopoSegmentLeftNode");
    rightHost = slapi_entry_attr_get_charptr(entry,"ipaReplTopoSegmentRightNode");
    direction =  slapi_entry_attr_get_charptr(entry,"ipaReplTopoSegmentDirection");
    name = slapi_entry_attr_get_charptr(entry,"cn");
    if (strcasecmp(direction,SEGMENT_DIR_BOTH) == 0){
        segment->direct = SEGMENT_BIDIRECTIONAL;
        segment->left = ipa_topo_util_agmt_from_entry(entry,conf->repl_root,
                                                      leftHost,rightHost, "left");
        segment->right = ipa_topo_util_agmt_from_entry(entry,conf->repl_root,
                                                       rightHost,leftHost, "right");
    } else if (strcasecmp(direction,SEGMENT_DIR_LEFT_ORIGIN) == 0) {
        segment->direct = SEGMENT_LEFT_RIGHT;
        segment->left = ipa_topo_util_agmt_from_entry(entry,conf->repl_root,
                                                      leftHost,rightHost, "left");
    } else if (strcasecmp(direction,SEGMENT_DIR_RIGHT_ORIGIN) == 0) {
        segment->direct = SEGMENT_RIGHT_LEFT;
        segment->right = ipa_topo_util_agmt_from_entry(entry,conf->repl_root,
                                                       rightHost,leftHost, "right");
    }
    state =  slapi_entry_attr_get_charptr(entry,"ipaReplTopoSegmentStatus");
    if (state && 0 == strcasecmp(state, SEGMENT_OBSOLETE_STR)) {
        /* state obsolete was set during merge */
        segment->state = SEGMENT_OBSOLETE;
    } else if (state && 0 == strcasecmp(state, SEGMENT_REMOVED_STR)) {
        /* state removed was set during host delete */
        segment->state = SEGMENT_REMOVED;
    } else {
        segment->state = 0;
    }
    segment->from = leftHost;
    segment->to = rightHost;
    segment->name = name;
    slapi_ch_free((void **)&direction);
    slapi_ch_free((void **)&state);

    return segment;
}

TopoReplicaSegment *
ipa_topo_util_segm_from_agmt(Slapi_Entry *repl_agmt)
{
    TopoReplicaSegment *segment = NULL;
    TopoReplicaAgmt *agmt = NULL;
    segment = (TopoReplicaSegment *) slapi_ch_calloc(1,sizeof(TopoReplicaSegment));
    agmt = (TopoReplicaAgmt *) slapi_ch_calloc(1,sizeof(TopoReplicaAgmt));
    segment->from = slapi_ch_strdup(ipa_topo_get_plugin_hostname());
    segment->to = slapi_entry_attr_get_charptr(repl_agmt, "nsds5replicahost");
    segment->direct = SEGMENT_LEFT_RIGHT;
    segment->state = SEGMENT_AUTOGEN;
    segment->name = slapi_ch_smprintf("%s-to-%s", segment->from, segment->to);
    segment->left = agmt;
    segment->right = NULL;

    agmt->origin = slapi_ch_strdup(segment->from);
    agmt->target = slapi_ch_strdup(segment->to);
    agmt->rdn = slapi_entry_attr_get_charptr(repl_agmt, "cn");
    agmt->repl_timeout = slapi_entry_attr_get_charptr(repl_agmt, "nsds5replicatimeout");
    agmt->repl_root = slapi_entry_attr_get_charptr(repl_agmt, "nsds5replicaroot");

    agmt->repl_attrs = slapi_entry_attr_get_charptr(repl_agmt, "nsDS5ReplicatedAttributeList");
    agmt->strip_attrs = slapi_entry_attr_get_charptr(repl_agmt, "nsds5ReplicaStripAttrs");
    agmt->total_attrs = slapi_entry_attr_get_charptr(repl_agmt, "nsDS5ReplicatedAttributeListTotal");
    agmt->repl_bind_dn = slapi_entry_attr_get_charptr(repl_agmt, "nsds5replicabinddn");
    agmt->repl_bind_cred = slapi_entry_attr_get_charptr(repl_agmt, "nsds5replicacredentials");
    agmt->repl_transport = slapi_entry_attr_get_charptr(repl_agmt, "nsds5replicatransportinfo");
    agmt->repl_bind_method = slapi_entry_attr_get_charptr(repl_agmt, "nsds5replicabindmethod");

    return segment;

}

TopoReplica *
ipa_topo_util_get_conf_for_segment(Slapi_Entry *segment_entry)
{
    /* we have a segment entry and need to determine the corresponding
     * replica conf, to get the replica root */
    TopoReplica *tconf = NULL;
    char *parent = slapi_dn_parent(slapi_entry_get_dn_const(segment_entry));

    Slapi_Entry *conf = ipa_topo_util_get_entry(parent);
    if (conf) {
        tconf = ipa_topo_util_conf_from_entry(conf);
        slapi_entry_free(conf);
    }

    return tconf;
}

TopoReplica *
ipa_topo_util_replica_init(Slapi_Entry *conf)
{
    TopoReplica *topoRepl = NULL;
    topoRepl = ipa_topo_cfg_replica_new();
    if (topoRepl) {
        topoRepl->shared_config_base = slapi_ch_strdup(slapi_entry_get_dn_const(conf));
        topoRepl->repl_root = slapi_entry_attr_get_charptr(conf,"ipaReplTopoConfRoot");
        topoRepl->repl_attrs = slapi_entry_attr_get_charptr(conf, "nsDS5ReplicatedAttributeList");
        topoRepl->strip_attrs = slapi_entry_attr_get_charptr(conf, "nsds5ReplicaStripAttrs");
        topoRepl->total_attrs = slapi_entry_attr_get_charptr(conf, "nsDS5ReplicatedAttributeListTotal");
    }
    return topoRepl;
}

TopoReplica *
ipa_topo_util_conf_from_entry(Slapi_Entry *entry)
{
    TopoReplica *conf = NULL;
    char *repl_root = NULL;

    repl_root = slapi_entry_attr_get_charptr(entry,"ipaReplTopoConfRoot");
    if (NULL == repl_root) return NULL;

    conf = ipa_topo_cfg_replica_find(repl_root, 1);
    if (conf) {
        slapi_ch_free((void **)&repl_root);
        return conf;
    } else {
        conf = (TopoReplica *) slapi_ch_calloc(1,sizeof(TopoReplica));
        conf->repl_root = repl_root;
        /* TBD read defined managed attrs as defaults */
        return conf;
    }
}
void
ipa_topo_util_segm_modify (TopoReplica *tconf,
                               TopoReplicaSegment *tsegm,
                               Slapi_Mods *smods)
{
    char *dn = NULL;

    dn = ipa_topo_segment_dn(tconf, tsegm->name);

    if (dn  == NULL) return;

    if (slapi_mods_get_num_mods(smods) > 0) {
        Slapi_DN *sdn = slapi_sdn_new_normdn_byref(dn);
        ipa_topo_util_modify(sdn, smods);
        slapi_sdn_free(&sdn);
    }

    slapi_ch_free_string(&dn);
}

void
ipa_topo_util_remove_init_attr(TopoReplica *repl_conf, TopoReplicaAgmt *topo_agmt)
{
    TopoReplicaSegmentList *seglist = repl_conf->repl_segments;
    TopoReplicaSegment *segment = NULL;
    char *dirattr = NULL;

    while (seglist) {
        segment = seglist->segm;
        if (segment->left == topo_agmt) {
            dirattr = "nsds5beginreplicarefresh;left";
            break;
        } else if (segment->right == topo_agmt) {
            dirattr = "nsds5beginreplicarefresh;right";
            break;
        } else {
            segment = NULL;
        }
        seglist = seglist->next;
    }
    if (segment) {
        Slapi_Mods *smods = slapi_mods_new();
        slapi_mods_add_string(smods, LDAP_MOD_DELETE,
                              dirattr, "");
        ipa_topo_util_segm_modify (repl_conf, segment, smods);
        slapi_mods_free(&smods);
    }
}

void
ipa_topo_util_set_agmt_rdn(TopoReplicaAgmt *topo_agmt, Slapi_Entry *repl_agmt)
{
    const Slapi_DN *agmt_dn = slapi_entry_get_sdn_const(repl_agmt);
    Slapi_RDN *agmt_rdn = slapi_rdn_new();
    slapi_sdn_get_rdn(agmt_dn, agmt_rdn);
    const char *agmt_rdn_str  = slapi_rdn_get_rdn(agmt_rdn);
    if (strcasecmp(agmt_rdn_str, topo_agmt->rdn)) {
        slapi_ch_free_string(&topo_agmt->rdn);
        topo_agmt->rdn = slapi_ch_strdup(agmt_rdn_str);
    }
    slapi_rdn_free(&agmt_rdn);
}

int
ipa_topo_util_update_agmt_rdn(TopoReplica *conf, TopoReplicaAgmt *agmt,
                              char *toHost)
{
    int rc = 0;
    Slapi_PBlock *pb = NULL;
    Slapi_Entry **entries = NULL;
    char *filter;

    pb = slapi_pblock_new();
    filter = slapi_ch_smprintf("(&(objectclass=nsds5replicationagreement)"
                               "(nsds5replicaroot=%s)(nsds5replicahost=%s))",
                               conf->repl_root, toHost);
    slapi_search_internal_set_pb(pb, "cn=config", LDAP_SCOPE_SUB,
                                 filter, NULL, 0, NULL, NULL,
                                 ipa_topo_get_plugin_id(), 0);
    slapi_search_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &rc);
    if (rc == 0) {
        slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &entries);
    }

    if (NULL == entries || NULL == entries[0]) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_util_update_agmt_rdn: "
                            "no agreements found\n");
    } else {
        ipa_topo_util_set_agmt_rdn(agmt, entries[0]);
    }

    slapi_free_search_results_internal(pb);
    slapi_ch_free_string(&filter);
    slapi_pblock_destroy(pb);
    return rc;
}

int
ipa_topo_util_update_agmt_list(TopoReplica *conf, TopoReplicaSegmentList *repl_segments)
{
    int rc = 0;
    int i;
    int nentries;
    Slapi_Entry **entries = NULL;
    Slapi_Entry *repl_agmt;
    Slapi_PBlock *pb = NULL;
    char *filter;

    /* find all replication agreements */

    pb = slapi_pblock_new();
    filter = slapi_ch_smprintf("(&(objectclass=nsds5replicationagreement)(nsds5replicaroot=%s))",
                               conf->repl_root);
    slapi_search_internal_set_pb(pb, "cn=config", LDAP_SCOPE_SUB,
                                 filter, NULL, 0, NULL, NULL,
                                 ipa_topo_get_plugin_id(), 0);
    slapi_search_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &rc);
    if (rc != 0)
    {
        slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "ipa_topo_util_update_agmts_list: "
                        "cannot read replication agreeements: error %d\n", rc);
        goto error_return;
    } else {
        slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &entries);
        if (NULL == entries || NULL == entries[0]) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_util_update_agmts_list: "
                            "no agreements found\n");
            goto update_only;
        }
    }

    /* for each agreement find segment */
    nentries = 0;
    repl_agmt = entries[0];
    while (repl_agmt) {
        char *targetHost;
        TopoReplicaAgmt *topo_agmt;
        TopoReplicaSegment *topo_segm;

        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "ipa_topo_util_update_agmts_list: processing agreement: %s\n",
                        slapi_entry_get_dn_const(repl_agmt));

        targetHost = slapi_entry_attr_get_charptr(repl_agmt,"nsDS5ReplicaHost");
        if(!targetHost){
            slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_util_update_agmts: "
                             "cannot read targethost: error %d\n", rc);
            continue;
        }
        topo_agmt = ipa_topo_util_find_segment_agmt(conf->repl_segments,
                                                    ipa_topo_get_plugin_hostname(),
                                                    targetHost);
        if (topo_agmt) {
            /* compare rdns, use rdn of existing agreement */
            ipa_topo_util_set_agmt_rdn(topo_agmt, repl_agmt);

            /* update agreement params which are different in the segment*/
            char *segm_attr_val;
            char *agmt_attr_val;
            Slapi_Mods *smods = slapi_mods_new();
            char **mattrs = ipa_topo_get_plugin_managed_attrs();
            for (i=0; mattrs[i]; i++) {
                segm_attr_val = ipa_topo_util_get_segm_attr(topo_agmt,mattrs[i]);
                if (segm_attr_val) {
                    if (0 == strcasecmp(mattrs[i], "nsds5BeginReplicaRefresh")) {
                        /* we have to remove this attr from the segment, this is
                         * processed on a server, which is the supplier side of
                         * an agreement.
                         */
                        ipa_topo_util_remove_init_attr(conf, topo_agmt);
                        continue;
                    }
                    agmt_attr_val =  slapi_entry_attr_get_charptr(repl_agmt,mattrs[i]);
                    if (agmt_attr_val == NULL ||
                        strcasecmp(agmt_attr_val,segm_attr_val)) {
                        /* value does not exist in agmt or
                         * is different from segment: replace
                         */
                        slapi_mods_add_string(smods,
                                              LDAP_MOD_REPLACE,
                                              mattrs[i],
                                              segm_attr_val);
                    }

                }
            }
            if (slapi_mods_get_num_mods(smods) > 0) {
                ipa_topo_util_modify((Slapi_DN *)slapi_entry_get_sdn_const(repl_agmt),
                                     smods);
            }
            slapi_mods_free(&smods);
        } else {
            if (ipa_topo_util_agmt_is_marked(repl_agmt)) {
                /* agreement is marked and no segment exists, delete agreement */
                ipa_topo_agmt_del_dn((char *)slapi_sdn_get_dn(slapi_entry_get_sdn_const(repl_agmt)));
            } else {
                /* generate segment from agreement */
                topo_segm = ipa_topo_util_segm_from_agmt(repl_agmt);
                rc = ipa_topo_util_segment_write(conf, topo_segm);
                if ( rc != 0) {
                    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                                    "ipa_topo_util_update_agmts_list: "
                                    "failed to write segment: error %d\n", rc);
                }
                rc = ipa_topo_util_agmt_mark(conf, repl_agmt, topo_segm);
                if (rc != 0) {
                    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                                   "ipa_topo_util_update_agmt_list: "
                                   "failed to mark agreement for host %s: error %d\n", targetHost, rc);
                }
                /* segment has been added in postop of segment write,
                 * prevent adding an agreement again
                 */
                ipa_topo_cfg_segment_set_visited(conf, topo_segm);
            }
        }

        repl_agmt = entries[++nentries];
    }
    slapi_free_search_results_internal(pb);

update_only:
    /* check if segments not covered by agreement exist
     * add agreeement
     */
    ipa_topo_util_missing_agmts_add_list(conf, conf->repl_segments,
                                    ipa_topo_get_plugin_hostname());

error_return:
    slapi_ch_free_string(&filter);
    slapi_pblock_destroy(pb);
    return rc;
}

TopoReplicaAgmt *
ipa_topo_util_find_segment_agmt(TopoReplicaSegmentList *repl_segments,
                                char *fromHost, char *toHost)
{
    TopoReplicaAgmt *agmt = NULL;
    TopoReplicaAgmt *agmtfound = NULL;
    TopoReplicaSegmentList *segment = repl_segments;

    while (segment) {
        if (segment->visited) {
            segment = segment->next;
            continue;
        }
        agmt = segment->segm->left;
        if (agmt && (0 == strcasecmp(agmt->origin, fromHost)) &&
                (0 == strcasecmp(agmt->target, toHost))) {
            agmtfound = agmt;
            break;
        }
        agmt = segment->segm->right;
        if (agmt && (0 == strcasecmp(agmt->origin, fromHost)) &&
                (0 == strcasecmp(agmt->target, toHost))) {
            agmtfound = agmt;
            break;
        }
        segment = segment->next;
    }
    if (segment) {
        segment->visited = 1;
    }
    return agmtfound;
}

void
ipa_topo_util_missing_agmts_add_list(TopoReplica *repl_conf,
                                     TopoReplicaSegmentList *repl_segments,
                                     char *fromHost)
{
    TopoReplicaSegmentList *segment = repl_segments;

    while (segment) {
        if (segment->visited) {
            segment->visited = 0;
            segment = segment->next;
            continue;
        }
        ipa_topo_util_missing_agmts_add(repl_conf, segment->segm, fromHost);
        segment = segment->next;
    }
}

void
ipa_topo_util_missing_agmts_add(TopoReplica *repl_conf,
                                TopoReplicaSegment *segment,
                                char *fromHost)
{
        if (0 == strcasecmp(segment->from, fromHost)) {
            if (segment->left) {
                ipa_topo_agmt_new(segment->to,repl_conf, segment->left);
            }
        } else if (0 == strcasecmp(segment->to, fromHost)) {
            if (segment->right) {
                ipa_topo_agmt_new(segment->from,repl_conf, segment->right);
            }
        }
}

void
ipa_topo_util_existing_agmts_del_list(TopoReplica *repl_conf,
                                 TopoReplicaSegmentList *repl_segments,
                                 char *fromHost)
{
    TopoReplicaSegmentList *segment = repl_segments;

    while (segment) {
        if (segment->visited) {
            segment->visited = 0;
            segment = segment->next;
            continue;
        }
        ipa_topo_util_existing_agmts_del(repl_conf, segment->segm,fromHost);
        segment = segment->next;
    }
}

void
ipa_topo_util_existing_agmts_del(TopoReplica *repl_conf,
                                 TopoReplicaSegment *segment,
                                 char *fromHost)
{
        if (0 == strcasecmp(segment->from, fromHost)) {
            if (segment->left) {
                ipa_topo_agmt_del(segment->to,repl_conf, segment->left);
            }
        } else if (0 == strcasecmp(segment->to, fromHost)) {
            if (segment->right) {
                ipa_topo_agmt_del(segment->from,repl_conf, segment->right);
            }
        }
}

void
ipa_topo_util_existing_agmts_update_list(TopoReplica *repl_conf,
                                    TopoReplicaSegmentList *repl_segments,
                                    LDAPMod **mods ,char *fromHost)
{
    TopoReplicaSegmentList *segment = repl_segments;

    while (segment) {
        if (segment->visited) {
            segment->visited = 0;
            segment = segment->next;
            continue;
        }
        ipa_topo_util_existing_agmts_update(repl_conf, segment->segm, mods, fromHost);
        segment = segment->next;
    }
}

void
ipa_topo_util_existing_agmts_update(TopoReplica *repl_conf,
                                    TopoReplicaSegment *segment,
                                    LDAPMod **mods ,char *fromHost)
{
    TopoReplicaAgmt *l_agmt = NULL;
    TopoReplicaAgmt *r_agmt = NULL;
        l_agmt = segment->left;
        r_agmt = segment->right;
        if (l_agmt && r_agmt) {
            if (0 == strcasecmp(l_agmt->origin, fromHost)) {
                ipa_topo_agmt_mod(repl_conf, l_agmt, mods, "left");
            } else if (0 == strcasecmp(r_agmt->origin, fromHost)) {
                ipa_topo_agmt_mod(repl_conf, r_agmt, mods, "right");
            }
        }
}

void
ipa_topo_util_segment_update(TopoReplica *repl_conf,
                                    TopoReplicaSegment *segment,
                                    LDAPMod **mods ,char *fromHost)
{
    int i;
    for (i = 0; (mods != NULL) && (mods[i] != NULL); i++) {
        switch (mods[i]->mod_op & ~LDAP_MOD_BVALUES) {
        case LDAP_MOD_DELETE:
            break;
        case LDAP_MOD_ADD:
        case LDAP_MOD_REPLACE:
            if (0 == strcasecmp(mods[i]->mod_type,"ipaReplTopoSegmentDirection")) {
                if (0 == strcasecmp(mods[i]->mod_bvalues[0]->bv_val,"both")) {
                    TopoReplicaSegment *ex_segm;
                    if (segment->direct == SEGMENT_LEFT_RIGHT) {
                        ex_segm = ipa_topo_cfg_replica_segment_find(repl_conf, segment->from, segment->to,
                                                    SEGMENT_RIGHT_LEFT, 1);
                        if (ex_segm) {
                            segment->right = ipa_topo_cfg_agmt_dup(ex_segm->left?ex_segm->left:ex_segm->right);
                        } else {
                            segment->right = ipa_topo_cfg_agmt_dup_reverse(segment->left);
                            if(0 == strcasecmp(fromHost,segment->right->origin)) {
                                ipa_topo_util_update_agmt_rdn(repl_conf, segment->right, segment->right->target);
                            }
                        }
                    } else if (segment->direct == SEGMENT_RIGHT_LEFT) {
                        ex_segm = ipa_topo_cfg_replica_segment_find(repl_conf, segment->from, segment->to,
                                                    SEGMENT_LEFT_RIGHT, 1);
                        if (ex_segm) {
                            segment->left = ipa_topo_cfg_agmt_dup(ex_segm->left?ex_segm->left:ex_segm->right);
                        } else {
                            segment->left = ipa_topo_cfg_agmt_dup_reverse(segment->right);
                            if(0 == strcasecmp(fromHost,segment->left->origin)) {
                                ipa_topo_util_update_agmt_rdn(repl_conf, segment->left, segment->left->target);
                            }
                        }
                    }
                    segment->direct = SEGMENT_BIDIRECTIONAL;
                } else {
                    /* only onedirectionl --> bidirectional handled so far */
                    slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                                    "ipa_topo_util_segment_update: no downgrade of direction\n");
                }
            } else if (0 == strcasecmp(mods[i]->mod_type,"ipaReplTopoSegmentStatus")) {
                if (0 == strcasecmp(mods[i]->mod_bvalues[0]->bv_val,SEGMENT_OBSOLETE_STR)) {
                    segment->state = SEGMENT_OBSOLETE;
                } else if (0 == strcasecmp(mods[i]->mod_bvalues[0]->bv_val,SEGMENT_AUTOGEN_STR)) {
                    segment->state = SEGMENT_AUTOGEN;
                }
            }
            break;
        }
    }
}

char *
ipa_topo_util_get_segm_attr(TopoReplicaAgmt *agmt, char *attr_type)
{
    char *attr = NULL;
    if (strcasecmp(attr_type, "nsds5ReplicaEnabled") == 0) {
        attr = agmt->enabled;
    } else if (strcasecmp(attr_type, "nsds5ReplicaStripAttrs") == 0){
        attr = agmt->strip_attrs;
    } else if (strcasecmp(attr_type, "nsds5ReplicatedAttributeList") == 0){
        attr = agmt->repl_attrs;
    } else if (strcasecmp(attr_type, "nsDS5ReplicatedAttributeListTotal") == 0) {
        attr = agmt->total_attrs;
    } else if (strcasecmp(attr_type, "nsds5BeginReplicaRefresh") == 0){
        attr = agmt->repl_refresh;
    } else if (strcasecmp(attr_type, "nsds5replicaTimeout") == 0) {
        attr = agmt->repl_timeout;
    } else if (strcasecmp(attr_type, "nsds5ReplicaEnabled") == 0) {
        attr = agmt->enabled;
    } else if (strcasecmp(attr_type, "nsds5replicaSessionPauseTime") == 0) {
        attr = agmt->repl_pause;
    } else if (strcasecmp(attr_type, "nsds5replicabinddn") == 0) {
        attr = agmt->repl_bind_dn;
    } else if (strcasecmp(attr_type, "nsds5replicacredentials") == 0) {
        attr = agmt->repl_bind_cred;
    } else if (strcasecmp(attr_type, "nsds5replicatransportinfo") == 0) {
        attr = agmt->repl_transport;
    } else if (strcasecmp(attr_type, "nsds5replicabindmethod") == 0) {
        attr = agmt->repl_bind_method;
    }
    return attr;
}

void
ipa_topo_util_set_segm_attr(TopoReplicaAgmt *agmt, char *attr_type, char *attr_val)
{
    if (strcasecmp(attr_type, "nsds5ReplicaEnabled") == 0) {
        agmt->enabled = attr_val;
    } else if (strcasecmp(attr_type, "nsds5ReplicaStripAttrs") == 0){
        agmt->strip_attrs = attr_val;
    } else if (strcasecmp(attr_type, "nsds5ReplicatedAttributeList") == 0){
        agmt->repl_attrs = attr_val;
    } else if (strcasecmp(attr_type, "nsDS5ReplicatedAttributeListTotal") == 0) {
        agmt->total_attrs = attr_val;
    } else if (strcasecmp(attr_type, "nsds5BeginReplicaRefresh") == 0){
        agmt->repl_refresh = attr_val;
    } else if (strcasecmp(attr_type, "nsds5replicaTimeout") == 0) {
        agmt->repl_timeout = attr_val;
    } else if (strcasecmp(attr_type, "nsds5ReplicaEnabled") == 0) {
        agmt->enabled = attr_val;
    } else if (strcasecmp(attr_type, "nsds5replicaSessionPauseTime") == 0) {
        agmt->repl_pause = attr_val;
    } else if (strcasecmp(attr_type, "nsds5replicabinddn") == 0) {
        agmt->repl_bind_dn = attr_val;
    } else if (strcasecmp(attr_type, "nsds5replicacredentials") == 0) {
        agmt->repl_bind_cred = attr_val;
    } else if (strcasecmp(attr_type, "nsds5replicatransportinfo") == 0) {
        agmt->repl_transport = attr_val;
    } else if (strcasecmp(attr_type, "nsds5replicabindmethod") == 0) {
        agmt->repl_bind_method = attr_val;
    }
}

/* check if the entry is a standard replication agreement (ignore winsync)
 * and if the replication suffix is in the list of managed replication roots.
 * This qualifies the entry as a candidate, further checks have to be done.
 */
int
ipa_topo_util_entry_is_candidate(Slapi_Entry *e)
{
    char **ocs;
    char *oc = NULL;
    char *repl_root;
    char **shared_root;
    int rc = 0;
    int i;

    ocs = slapi_entry_attr_get_charray(e,"objectclass");

    for (i=0; ocs && ocs[i]; i++) {
        if (strcasecmp(ocs[i],"nsds5ReplicationAgreement") == 0) {
            oc = ocs[i];
            break;
        }
    }

    if (oc) {
        repl_root = slapi_entry_attr_get_charptr(e,"nsDS5ReplicaRoot");
        shared_root = ipa_topo_get_plugin_replica_root();
        for (i=0; shared_root && shared_root[i]; i++) {
            if (strcasecmp(repl_root,shared_root[i]) == 0) {
                rc = 1;
                break;
            }
        }
        slapi_ch_free((void **) &repl_root);
    }
    slapi_ch_array_free(ocs);
    return rc;
}

int
ipa_topo_util_target_is_managed(Slapi_Entry *e)
{
    char *targethost;
    char *repl_root;
    TopoReplica *replica;
    int ret = 0;

    /* first check: is the entry managed alreday by the topology plugin */
    /* at the moment only replication agreements are managed */
    if (ipa_topo_util_agmt_is_marked(e)) return 1;

    /* next check: is the replcation agreement targeting a meanged server
     * deny agreements to an managed server
     * allow other agreements
     */
    targethost = slapi_entry_attr_get_charptr(e,"nsDS5ReplicaHost");
    repl_root = slapi_entry_attr_get_charptr(e,"nsDS5ReplicaRoot");
    replica = ipa_topo_cfg_replica_find(repl_root,1);
    if (targethost && replica &&
        ipa_topo_cfg_host_find(replica, targethost, 1) &&
        ipa_topo_cfg_host_find(replica, ipa_topo_get_plugin_hostname(), 1)) {
        ret = 1;
    }
    slapi_ch_free_string(&targethost);
    slapi_ch_free_string(&repl_root);

    return ret;

}

int ipa_topo_util_segment_is_managed(TopoReplica *tconf, TopoReplicaSegment *tsegm)
{
    int ret = 0;

    if (ipa_topo_cfg_host_find(tconf, tsegm->from, 1) &&
        ipa_topo_cfg_host_find(tconf, tsegm->to, 1)) {
        ret = 1;
    }
    return ret;
}

void
ipa_topo_util_segm_update (TopoReplica *tconf,
                               TopoReplicaSegment *tsegm,
                               int property)
{
    char *dn = NULL;
    Slapi_Mods *smods;

    dn = ipa_topo_segment_dn(tconf, tsegm->name);

    if (dn  == NULL) return;

    /* apply mods to entry */
    smods = slapi_mods_new();
    switch (property) {
    case SEGMENT_BIDIRECTIONAL:
        tsegm->direct = SEGMENT_BIDIRECTIONAL;
        slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                          "ipaReplTopoSegmentDirection", "both");
        break;
    case SEGMENT_LEFT_RIGHT:
        tsegm->direct = SEGMENT_LEFT_RIGHT;
        slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                          "ipaReplTopoSegmentDirection", "left-right");
        break;
    case SEGMENT_RIGHT_LEFT:
        tsegm->direct = SEGMENT_RIGHT_LEFT;
        slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                          "ipaReplTopoSegmentDirection", "right-left");
        break;
    case SEGMENT_OBSOLETE:
        tsegm->state = SEGMENT_OBSOLETE;
        slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                          "ipaReplTopoSegmentStatus", SEGMENT_OBSOLETE_STR);
        break;
    case SEGMENT_REMOVED:
        tsegm->state = SEGMENT_OBSOLETE;
        slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                          "ipaReplTopoSegmentStatus", SEGMENT_REMOVED_STR);
        break;
    }
    if (slapi_mods_get_num_mods(smods) > 0) {
        Slapi_DN *sdn = slapi_sdn_new_normdn_byref(dn);
        ipa_topo_util_modify(sdn, smods);
        slapi_sdn_free(&sdn);
    }

    slapi_mods_free(&smods);
    slapi_ch_free_string(&dn);

}

void
ipa_topo_util_segm_remove(TopoReplica *tconf,
                         TopoReplicaSegment *tsegm)
{
    Slapi_PBlock *pb;
    char *dn = NULL;
    int ret;

    /* remove it from the database */
    dn = ipa_topo_segment_dn(tconf, tsegm->name);
    if (dn  == NULL) return;

    pb = slapi_pblock_new();
    slapi_delete_internal_set_pb(pb, dn, NULL, NULL,
                                 ipa_topo_get_plugin_id(), 0);

    slapi_delete_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);
    slapi_pblock_destroy(pb);

    slapi_ch_free_string(&dn);

    /* removed from the internal data struct in the delete postop */
    /* ipa_topo_cfg_segment_del(tconf, tsegm); */
}

/* for merging segments the result should be the same on any server
 * an deliberate decision is to compare hostnames to get a preference
 */
static int
ipa_topo_util_segm_order(TopoReplicaSegment *l, TopoReplicaSegment *r)
{
    return strcasecmp(l->from, r->from);
}

void
ipa_topo_util_segment_do_merge(TopoReplica *tconf,
                               TopoReplicaSegment *ex_segm, TopoReplicaSegment *tsegm)
{
    /* we are merging two one directional segments, tehy can have been created in 
     * several ways and we need to find the agreeemnt to copy 
     */
    if (NULL == tsegm->right) {
        if(ex_segm->left) {
            tsegm->right = ipa_topo_cfg_agmt_dup(ex_segm->left);
        } else {
            tsegm->right = ipa_topo_cfg_agmt_dup(ex_segm->right);
        }
    } else {
        if(ex_segm->left) {
            tsegm->left = ipa_topo_cfg_agmt_dup(ex_segm->left);
        } else {
            tsegm->left = ipa_topo_cfg_agmt_dup(ex_segm->right);
        }
    }
    ipa_topo_util_segm_update(tconf,ex_segm, SEGMENT_OBSOLETE);
    ipa_topo_util_segm_remove(tconf, ex_segm);
    ipa_topo_util_segm_update(tconf,tsegm, SEGMENT_BIDIRECTIONAL);
}


void
ipa_topo_util_segment_merge(TopoReplica *tconf,
                                 TopoReplicaSegment *tsegm)
{
    TopoReplicaSegment *ex_segm;

    if (tsegm->direct == SEGMENT_BIDIRECTIONAL) return;

    if (strcasecmp(tsegm->from,ipa_topo_get_plugin_hostname()) &&
        strcasecmp(tsegm->to,ipa_topo_get_plugin_hostname())) {
        /* merging is only done on one of the endpoints of the segm */
        return;
    }

    if (tsegm->direct == SEGMENT_LEFT_RIGHT) {
        ex_segm = ipa_topo_cfg_replica_segment_find(tconf, tsegm->from, tsegm->to,
                                                    SEGMENT_RIGHT_LEFT, 1 /*lock*/);
    } else {
        ex_segm = ipa_topo_cfg_replica_segment_find(tconf, tsegm->from, tsegm->to,
                                                    SEGMENT_LEFT_RIGHT, 1 /*lock*/);
    }
    if (ex_segm == NULL) return;

    /* to avoid conflicts merging has to be done only once and
     * so there is a preference which segment survives and on
     * which server it will be done
     */
    if (ipa_topo_util_segm_order(ex_segm, tsegm) > 0) {
        if (0 == strcasecmp(tsegm->from,ipa_topo_get_plugin_hostname())) {
            ipa_topo_util_segment_do_merge(tconf, ex_segm, tsegm);
        }
    } else {
        if (0 == strcasecmp(ex_segm->from,ipa_topo_get_plugin_hostname())) {
            ipa_topo_util_segment_do_merge(tconf, tsegm, ex_segm);
        }
    }

}
int
ipa_topo_util_segment_write(TopoReplica *tconf, TopoReplicaSegment *tsegm)
{
    Slapi_Entry *e = NULL;
    Slapi_PBlock *pb;
    char *dn = NULL;
    Slapi_DN *sdn = NULL;
    int ret = 0;
    /* Set up the new segment entry */
    dn = ipa_topo_segment_dn(tconf, tsegm->name);
    if (dn  == NULL) return -1;
    sdn = slapi_sdn_new_normdn_byref(dn);

    e = slapi_entry_alloc();
    /* the entry now owns the dup'd dn */
    slapi_entry_init_ext(e, sdn, NULL); /* sdn is copied into e */
    slapi_sdn_free(&sdn);

    slapi_entry_add_string(e, SLAPI_ATTR_OBJECTCLASS, "iparepltoposegment");
    slapi_entry_add_string(e, "cn",tsegm->name);
    slapi_entry_add_string(e, "iparepltoposegmentleftnode",tsegm->from);
    slapi_entry_add_string(e, "iparepltoposegmentrightnode",tsegm->to);
    slapi_entry_add_string(e, "iparepltoposegmentdirection", "left-right");
    /* write other attributes of the segment if present */
    if (tsegm->state == SEGMENT_AUTOGEN) {
        slapi_entry_add_string(e, "iparepltoposegmentstatus", "autogen");
    }

    pb = slapi_pblock_new();
    slapi_pblock_init(pb);

    /* e will be consumed by slapi_add_internal() */
    slapi_add_entry_internal_set_pb(pb, e, NULL, ipa_topo_get_plugin_id(), 0);
    slapi_add_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);
    slapi_pblock_destroy(pb);

    return ret;

}
/*
 * to distinguish replication agreements created by the topology plugin
 * and agreemens created by admins or legacy tools a "marker" objectclass is used.
 * Witheout extending the schema the description attribute is used and a
 * specific value is added:
 * - when a segment is created from an agreement an so put under control of
 * the plugin:
 *    "ipaReplTopoManagedAgreementState: managed agreement - controlled by topology plugin"
 * - when an agreement is created from a segment:
 *    "ipaReplTopoManagedAgreementState: managed agreement - generated by topology plugin"
 */
int
ipa_topo_util_agmt_mark(TopoReplica *tconf, Slapi_Entry *repl_agmt,
                        TopoReplicaSegment *tsegm)
{
    int ret = 0;

    Slapi_Mods *smods = slapi_mods_new();
    slapi_mods_add_string(smods, LDAP_MOD_ADD, "objectclass",
                          "ipaReplTopoManagedAgreement");
    slapi_mods_add_string(smods, LDAP_MOD_ADD, "ipaReplTopoManagedAgreementState",
                          "managed agreement - controlled by topology plugin");
    if (slapi_mods_get_num_mods(smods) > 0) {
        ret = ipa_topo_util_modify(
                  (Slapi_DN *)slapi_entry_get_sdn_const(repl_agmt), smods);
    }
    slapi_mods_free(&smods);

    return ret;
}

int
ipa_topo_util_agmt_is_marked(Slapi_Entry *repl_agmt)
{
    int ret = 0;
    int i;
    char **descs;

    descs = slapi_entry_attr_get_charray(repl_agmt, "objectclass");
    for (i=0; descs &&descs[i]; i++) {
        if (strcasecmp(descs[i],"ipaReplTopoManagedAgreement") == 0) {
            ret = 1;
            break;
        }
    }
    slapi_ch_array_free(descs);
    return ret;
}

void
ipa_topo_util_update_segments_for_host(TopoReplica *conf, char *hostname)
{
    int rc = 0;
    int nentries;
    Slapi_Entry **entries;
    Slapi_Entry *repl_agmt;
    Slapi_PBlock *pb = NULL;
    char *filter;

    /* find all replication agreements to the new host entry
     * Since the host was not yet managed new segments ghave to be
     * created
     */

    pb = slapi_pblock_new();
    filter = slapi_ch_smprintf("(&(objectclass=nsds5replicationagreement)(nsds5replicahost=%s)(nsds5replicaroot=%s))",
                               hostname, conf->repl_root);
    slapi_search_internal_set_pb(pb, "cn=config", LDAP_SCOPE_SUB,
                                 filter, NULL, 0, NULL, NULL,
                                 ipa_topo_get_plugin_id(), 0);
    slapi_search_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &rc);
    if (rc != 0)
    {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "ipa_topo_util_update_segments_for_host: "
                        "no replication agreeements for host %s: error %d\n",
                        hostname, rc);
        return;
    } else {
        slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &entries);
        if (NULL == entries || NULL == entries[0]) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_util_update_segments_for_host: "
                            "no agrements found\n");
            return;
        }
    }

    /* for each agreement find segment */
    nentries = 0;
    repl_agmt = entries[0];
    while (repl_agmt) {
        TopoReplicaSegment *topo_segm = NULL;
        TopoReplicaAgmt *topo_agmt = NULL;

        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "ipa_topo_util_update_segments_for_host: "
                        "processing agreement: %s\n",
                        slapi_entry_get_dn_const(repl_agmt));

        /* generate segment from agreement */
        topo_segm = ipa_topo_util_segm_from_agmt(repl_agmt);
        rc = ipa_topo_util_segment_write(conf, topo_segm);
        if (rc != 0) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_util_update_segments_for_host: "
                            "failed to write segment for host %s: error %d\n",
                            hostname, rc);
        }
        rc = ipa_topo_util_agmt_mark(conf, repl_agmt, topo_segm);
        if (rc != 0) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_util_update_segments_for_host: "
                            "failed to mark agreement for host %s: error %d\n",
                             hostname, rc);
        }
        /* segment has been recreated and added during postp of segment_write
         * but the correct agreement rdn was lost, set it now */
        topo_agmt = ipa_topo_util_find_segment_agmt(conf->repl_segments,
                                                    ipa_topo_get_plugin_hostname(),
                                                    hostname);
        if (topo_agmt) {
            ipa_topo_util_set_agmt_rdn(topo_agmt, repl_agmt);
        }
        repl_agmt = entries[++nentries];

    }

    slapi_free_search_results_internal(pb);
    slapi_pblock_destroy(pb);

}

void
ipa_topo_util_disable_repl_from_host(char *repl_root, char *delhost)
{
    char *principal = ipa_topo_util_get_ldap_principal(repl_root, delhost);
    if (principal) {
        ipa_topo_util_disable_repl_for_principal(repl_root, principal);
        slapi_ch_free_string(&principal);
    } else {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_util_disable_repl_from_host: "
                            "failed to get ldap principal for host: %s \n",
                             delhost);
    }
}

void
ipa_topo_util_delete_segments_for_host(char *repl_root, char *delhost)
{
    TopoReplicaSegment *segm = NULL;
    TopoReplica *tconf = ipa_topo_cfg_replica_find(repl_root, 1);
    int check_reverse = 1;

    if (NULL == tconf) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_util_delete_segments_for_host: "
                            "failed to get replica object for suffix: %s \n",
                             repl_root);
        return;
    }

    /* first check if a segment originating at localhost exists */
    segm = ipa_topo_cfg_segment_find(repl_root, ipa_topo_get_plugin_hostname(),
                                     delhost, SEGMENT_LEFT_RIGHT);
    if (segm) {
        /* mark segment as removable, bypass connectivity check when replicated */
        if (segm->direct == SEGMENT_BIDIRECTIONAL) check_reverse = 0;
        ipa_topo_util_segm_update(tconf,segm, SEGMENT_REMOVED);
        /* delete segment */
        /* the replication agreement will be deleted in the postop_del*/
        ipa_topo_util_segm_remove(tconf, segm);
    }
    /* check if one directional segment in reverse direction exists */
    if (check_reverse) {
        segm = ipa_topo_cfg_segment_find(repl_root, delhost,
                                         ipa_topo_get_plugin_hostname(), SEGMENT_LEFT_RIGHT);
        if (segm) {
            ipa_topo_util_segm_update(tconf,segm, SEGMENT_REMOVED);
            /* mark and delete, no repl agmt on this server */
            ipa_topo_util_segm_remove(tconf, segm);
        }
    }

    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                    "ipa_topo_util_delete_segments_for_host <-- done\n");
}

void
ipa_topo_util_init_hosts(Slapi_Entry *hostentry)
{
    char *newhost;
    char **repl_root = NULL;
    TopoReplica *replica = NULL;
    int i;

    newhost = slapi_entry_attr_get_charptr(hostentry,"cn");
    if (newhost == NULL) return;

    repl_root = slapi_entry_attr_get_charray(hostentry,"ipaReplTopoManagedSuffix");
    if (repl_root == NULL || *repl_root == NULL) return;

    for (i=0; repl_root[i];i++) {
        replica = ipa_topo_cfg_replica_find(repl_root[i], 1);
        if (replica == NULL) continue;

        ipa_topo_cfg_host_add(replica, newhost);
    }

    slapi_ch_array_free(repl_root);
    slapi_ch_free_string(&newhost);
    return;
}

void
ipa_topo_util_add_managed_host(char *suffix, char *addhost)
{
    TopoReplica *conf = ipa_topo_cfg_replica_find(suffix,1);
    if (conf) {
        ipa_topo_cfg_host_add(conf, addhost);
        ipa_topo_util_update_segments_for_host(conf, addhost);
    }
}

void
ipa_topo_util_add_host(Slapi_Entry *hostentry)
{
    char* addhost = NULL;
    char **suffixes = NULL;
    int i=0;
    addhost = slapi_entry_attr_get_charptr(hostentry,"cn");
    suffixes = slapi_entry_attr_get_charray(hostentry,"ipaReplTopoManagedSuffix");
    while (suffixes && suffixes[i]) {
        ipa_topo_util_add_managed_host(suffixes[i], addhost);
        i++;
    }
    slapi_ch_free_string(&addhost);
    slapi_ch_array_free(suffixes);
}


void
ipa_topo_util_update_host(Slapi_Entry *hostentry, LDAPMod **mods)
{
    char* modhost = NULL;
    int i, j;

    modhost = slapi_entry_attr_get_charptr(hostentry,"cn");
    for (i = 0; (mods != NULL) && (mods[i] != NULL); i++) {
        if (0 == strcasecmp(mods[i]->mod_type, "ipaReplTopoManagedSuffix")) {
            switch (mods[i]->mod_op & ~LDAP_MOD_BVALUES) {
            case LDAP_MOD_DELETE:
                /*  preop check ensures we have valuses */
                if (NULL == mods[i]->mod_bvalues || NULL == mods[i]->mod_bvalues[0]) {
                }
                break;
            case LDAP_MOD_ADD:
                for (j = 0; mods[i]->mod_bvalues[j] != NULL; j++) {
                    ipa_topo_util_add_managed_host(mods[i]->mod_bvalues[j]->bv_val, modhost);
                }
                break;
            case LDAP_MOD_REPLACE:
                break;
            }
        }
    }
    slapi_ch_free_string(&modhost);
}

void
ipa_topo_util_delete_host(Slapi_Entry *hostentry)
{
    char* delhost = NULL;

    delhost = slapi_entry_attr_get_charptr(hostentry,"cn");
        /* if the deleted host is the current host, do not
         * delete the segments, deleting segments will trigger
         * removal of replication agreements and it cannot be
         * ensured that the deletion of the host will reach
         * other servers in the replica before.
         * So wait until the delete is received on the other
         * servers and the deletion of segments is received.
         */
    if (0 == strcasecmp(delhost,ipa_topo_get_plugin_hostname())) {
        return;
    } else {
        /* find all segments connecting the local master to the
         * deleted master.
         * - mark the segments as no longer managed
         * - delete the segments
         * - if the segment originates at the local host
         *   remove the corresponding replication agreement
         */
        int i = 0;
        char **shared_root = ipa_topo_get_plugin_replica_root();

        while (shared_root[i]) {
            ipa_topo_util_disable_repl_from_host(shared_root[i], delhost);
            ipa_topo_util_delete_segments_for_host(shared_root[i], delhost);
            i++;
        }
    }

}

int
ipa_topo_util_start(int delay)
{
    /* main routine to synchronize data in the shared tree and
     * config data. It will be called:
     * - at startup of the server
     * - if the domain level increases above the plugin version
     *   and the plugin becomes active
     * - after a backup state change, eg after online initialization
     *   when there is no guarantee that data in the shared tree
     *   and plugin data still match.
     *
     * the parameter delay controls if the operation is performed
     * immediately or after some delay. This delay is necessary
     * during startup because the plugins only become active after
     * all plugins have been started and modifications would not be
     * logged in the changelog and replicated
     */

    time_t now;
    int rc = 0;
    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
        "--> ipa_topo_util_start - deleay: %d\n",delay);

    ipa_topo_init_shared_config();

    /* initialize the config data from the shared tree and apply to
     * the managed data under cn=config
     */
    if (delay) {
        time(&now);
        if (!slapi_eq_once(ipa_topo_queue_apply_shared_config,NULL,now +
            ipa_topo_get_plugin_startup_delay())) {
            slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "unable to queue configuration update\n");
            return -1;
        }
    } else {
        rc = ipa_topo_apply_shared_config();
    }
    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
        "<-- ipa_topo_util_start\n");
    return rc;
}

char *
ipa_topo_util_get_ldap_principal(char *repl_root, char *hostname)
{
    int rc = 0;
    Slapi_Entry **entries = NULL;
    Slapi_PBlock *pb = NULL;
    char *filter;
    char *dn = NULL;

    filter = slapi_ch_smprintf("krbprincipalname=ldap/%s*",hostname);
    pb = slapi_pblock_new();

    slapi_search_internal_set_pb(pb, repl_root, LDAP_SCOPE_SUBTREE,
                                 filter, NULL, 0, NULL, NULL,
                                 ipa_topo_get_plugin_id(), 0);
    slapi_search_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &rc);
    if (rc != 0)
    {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "ipa_topo_util_get_ldap_principal: "
                        "unable to search for entry (%s): error %d\n", filter, rc);
    } else {
        slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &entries);
        if (NULL == entries || NULL == entries[0]) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_util_get_ldap_principal: entry not found: (%s)\n", filter);
        } else {
            dn = slapi_ch_strdup(slapi_entry_get_dn(entries[0]));
        }
    }
    slapi_free_search_results_internal(pb);
    slapi_pblock_destroy(pb);
    slapi_ch_free_string(&filter);
    return dn;
}

void
ipa_topo_util_disable_repl_for_principal(char *repl_root, char *principal)
{
    Slapi_DN *sdn;
    char *filter;
    Slapi_PBlock *pb;
    Slapi_Entry **entries;
    Slapi_Mods *smods;
    int ret;

    /* to disable replication for a user/principal it ahs to be removed from the
     * allowed bind dns in the replica object and from the bind dn group
     */

    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "--> ipa_topo_util_disable_repl_for_principal\n");
    /* find replica object */
    pb = slapi_pblock_new();
    filter = slapi_ch_smprintf("(&(objectclass=nsds5replica)(nsds5replicaroot=%s))", repl_root);
    slapi_search_internal_set_pb(pb, "cn=config", LDAP_SCOPE_SUB,
                                 filter, NULL, 0, NULL, NULL,
                                 ipa_topo_get_plugin_id(), 0);
    slapi_search_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);
    if (ret != 0) {
        sdn = NULL;
    } else {
        slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &entries);
        if (NULL == entries || NULL == entries[0]) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_agreement_dn: no replica found\n");
            sdn = NULL;
        } else {
            sdn = slapi_sdn_dup(slapi_entry_get_sdn(entries[0]));
        }
    }
    slapi_free_search_results_internal(pb);

    /* remove principal from binddns */
    smods = slapi_mods_new();
    slapi_mods_add_string(smods, LDAP_MOD_DELETE,
                          "nsds5replicabinddn", principal);
    ret = ipa_topo_util_modify(sdn, smods);
    slapi_sdn_free(&sdn);

    /* find binddn group */
    slapi_pblock_init(pb);

    slapi_search_internal_set_pb(pb, ipa_topo_get_plugin_shared_bindgroup(), LDAP_SCOPE_BASE,
                                 "(objectclass=groupofnames)",
                                 NULL, 0, NULL, NULL, ipa_topo_get_plugin_id(), 0);
    slapi_search_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);
    if (ret != 0) {
        sdn = NULL;
    } else {
        slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &entries);
        if (NULL == entries || NULL == entries[0]) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_agreement_dn: no replica found\n");
            sdn = NULL;
        } else {
            sdn = slapi_sdn_dup(slapi_entry_get_sdn(entries[0]));
        }
    }
    slapi_free_search_results_internal(pb);
    slapi_pblock_destroy(pb);

    /* delete principal as binddn group member */
    smods = slapi_mods_new();
    slapi_mods_add_string(smods, LDAP_MOD_DELETE,
                          "member", principal);
    ret = ipa_topo_util_modify(sdn, smods);
    slapi_mods_free(&smods);
    slapi_sdn_free(&sdn);
    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "<-- ipa_topo_util_disable_repl_for_principal\n");
}

void
ipa_topo_util_reset_init(char *repl_root)
{
    TopoReplica *replica_config = NULL;
    TopoReplicaSegmentList *seglist = NULL;
    TopoReplicaSegment *segment = NULL;
    char *localhost = ipa_topo_get_plugin_hostname();
    char *dirattr;

    replica_config = ipa_topo_cfg_replica_find(repl_root, 1);
    if (replica_config) {
        seglist = ipa_topo_util_get_replica_segments(replica_config);
    } else {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "ipa_topo_util_reset_init: no replica found for: %s\n", repl_root);
        return;
    }

    while (seglist) {
        /* this is executed after an online init completed, reset the init in segments
         * which target this server
         */
        segment = seglist->segm;
        if (segment->left && (0 == strcasecmp(localhost,segment->left->target))
                && ipa_topo_util_get_segm_attr(segment->left,"nsds5BeginReplicaRefresh")) {
            dirattr = "nsds5BeginReplicaRefresh;left";
            break;
        } else if (segment->right && (0 == strcasecmp(localhost,segment->right->target))
                && ipa_topo_util_get_segm_attr(segment->right,"nsds5BeginReplicaRefresh")) {
            dirattr = "nsds5BeginReplicaRefresh;right";
            break;
        } else {
            segment = NULL;
        }
        seglist = seglist->next;
    }
    if (segment) {
        Slapi_Mods *smods = slapi_mods_new();
        slapi_mods_add_string(smods, LDAP_MOD_DELETE,
                              dirattr, "");
        ipa_topo_util_segm_modify (replica_config, segment, smods);
        slapi_mods_free(&smods);
    }
}

void
ipa_topo_util_suffix_init(Slapi_Entry *config_entry)
{
    int rc = 0;
    TopoReplica *topoRepl = NULL;
    char *repl_suffix = slapi_entry_attr_get_charptr(config_entry,"ipaReplTopoConfRoot");
    if (repl_suffix) {
        topoRepl = ipa_topo_util_replica_init(config_entry);
        if (topoRepl) {
            rc = ipa_topo_cfg_replica_add(topoRepl);
            rc = ipa_topo_apply_shared_replica_config(topoRepl);
            if (rc)
                slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "ipa_topo_util_suffix_init: failed to init suffix %s\n", repl_suffix);
        }
    }
    slapi_ch_free_string(&repl_suffix);
}


void
ipa_topo_util_suffix_update(Slapi_Entry *config_post, Slapi_Entry *config_pre,
                       LDAPMod **mods)
{
}

#ifndef SLAPI_OP_FLAG_TOMBSTONE_ENTRY
#define SLAPI_OP_FLAG_TOMBSTONE_ENTRY 0x001000
#endif

int
ipa_topo_util_is_tombstone_op(Slapi_PBlock *pb)
{
    Slapi_Operation *op;

    slapi_pblock_get(pb, SLAPI_OPERATION, &op);
    return slapi_operation_is_flag_set(op, SLAPI_OP_FLAG_TOMBSTONE_ENTRY);
}
int
ipa_topo_util_cleanruv_task(char *repl_root, int replicaID)
{
    Slapi_Entry *e = NULL;
    Slapi_PBlock *pb;
    char *dn = NULL;
    char *repl_rid;
    Slapi_DN *sdn = NULL;
    int ret = 0;
    dn = slapi_ch_smprintf("cn=clean %d,cn=cleanallruv,cn=tasks,cn=config", replicaID);
    if (dn  == NULL) return -1;
    sdn = slapi_sdn_new_normdn_byref(dn);

    e = slapi_entry_alloc();
    /* the entry now owns the dup'd dn */
    slapi_entry_init_ext(e, sdn, NULL); /* sdn is copied into e */
    slapi_sdn_free(&sdn);

    slapi_entry_add_string(e, SLAPI_ATTR_OBJECTCLASS, "extensibleobject");
    slapi_entry_add_string(e, "replica-base-dn",repl_root);
    repl_rid = slapi_ch_smprintf("%d",replicaID);
    slapi_entry_add_string(e, "replica-id",repl_rid);
    slapi_entry_add_string(e, "replica-force-cleaning", "yes");

    pb = slapi_pblock_new();
    slapi_pblock_init(pb);

    /* e will be consumed by slapi_add_internal() */
    slapi_add_entry_internal_set_pb(pb, e, NULL, ipa_topo_get_plugin_id(), 0);
    slapi_add_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);
    slapi_pblock_destroy(pb);
    slapi_ch_free_string(&repl_rid);

    return ret;

}

void
ipa_topo_util_cleanruv_element(char *repl_root, char *hostname)
{
    Slapi_PBlock *pb = NULL;
    char *filter = "(&(objectclass=nstombstone)(nsuniqueid=ffffffff-ffffffff-ffffffff-ffffffff))";
    int ret;
    Slapi_Entry **entries = NULL;

    /* find ruv object */
    pb = slapi_pblock_new();
    slapi_search_internal_set_pb(pb, repl_root, LDAP_SCOPE_SUB,
                                 filter, NULL, 0, NULL, NULL,
                                 ipa_topo_get_plugin_id(), 0);
    slapi_search_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);
    if (ret != 0) {
        slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_util_cleanruv: no RUV entry found\n");
    } else {
        slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &entries);
        if (NULL == entries || NULL == entries[0]) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_util_cleanruv: no RUV entry found\n");
        } else {
            int i = 0;
            int rid = 0;
            int rc = 0;
            char **ruv_ele = slapi_entry_attr_get_charray(entries[0], "nsds50ruv");
            /* a ruv element has the form:
             * {replica <rid> ldap://<host>:<port>} <mincsn_str> <maxcsn_str>
             */
            char *urlstr = slapi_ch_smprintf("ldap://%s:",hostname);
            while (ruv_ele && ruv_ele[i]) {
                if (strstr(ruv_ele[i], urlstr)) {
                    rid = atoi(ruv_ele[i]+strlen("{replica "));
                    rc = ipa_topo_util_cleanruv_task(repl_root,rid);
                    if (rc) {
                         slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_util_cleanruv: failed to create cleanalltuv task\n");
                    }
                    break;
                }
                i++;
            }
            slapi_ch_array_free(ruv_ele);
            slapi_ch_free_string(&urlstr);
        }
    }
    slapi_free_search_results_internal(pb);
    slapi_pblock_destroy(pb);
}

void
ipa_topo_util_cleanruv(Slapi_Entry *del_entry)
{
    char* delhost = NULL;
    char **shared_root = ipa_topo_get_plugin_replica_root();
    int i = 0;

    delhost = slapi_entry_attr_get_charptr(del_entry,"cn");

    while (shared_root[i]) {
        ipa_topo_util_cleanruv_element(shared_root[i], delhost);
        i++;
    }
}
