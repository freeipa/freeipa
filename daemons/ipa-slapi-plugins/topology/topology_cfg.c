
#include "topology.h"

/* two static data structures to hold the
 * plugin configuration and the information
 * stored in the shared tree.
 * They will be initialized at plugin init/start,
 * updated when the shared config is modified
 * and accessed via set/get functions
 */
static TopoPluginConf topo_plugin_conf = {0};
static TopoReplicaConf topo_shared_conf = {0};
static int ipa_domain_level = 0;
static int topo_min_domain_level = 1;

char *ipa_topo_plugin_managed_attrs[] = {
        "nsds5ReplicaStripAttrs",
        "nsds5ReplicatedAttributeList",
        "nsDS5ReplicatedAttributeListTotal",
        "nsds5BeginReplicaRefresh",
        "nsds5replicaTimeout",
        "nsds5ReplicaEnabled",
        "nsds5replicaSessionPauseTime",
        "nsds5replicabinddn",
        "nsds5replicacredentials",
        "nsds5replicatransportinfo",
        "nsds5replicabindmethod",
        NULL };

/* subset of attrs which can only be modified via
 * modification of segments in the shared tree.
 * Other attributes still can be directly modified
 * eg to reinit a replica or change bind method and
 * credentials.
 * This is currently needed to make ipa-replica-install work
 */
char *ipa_topo_plugin_restricted_attrs[] = {
        "nsds5ReplicaStripAttrs",
        "nsds5ReplicatedAttributeList",
        "nsDS5ReplicatedAttributeListTotal",
        "nsds5replicaTimeout",
        "nsds5replicaSessionPauseTime",
        NULL };

void *
ipa_topo_get_plugin_id(void)
{
    return topo_plugin_conf.identity;
}

char *
ipa_topo_get_plugin_hostname(void)
{
    return topo_plugin_conf.hostname;
}

char **
ipa_topo_get_plugin_managed_attrs(void)
{
    return topo_plugin_conf.managed_attrs;
}

char **
ipa_topo_get_plugin_restricted_attrs(void)
{
    return topo_plugin_conf.restricted_attrs;
}

char *
ipa_topo_get_plugin_shared_config(void)
{
    return topo_plugin_conf.shared_config_base;
}
char *
ipa_topo_get_plugin_shared_topo(void)
{
    return topo_plugin_conf.shared_topo;
}

Slapi_DN *
ipa_topo_get_plugin_shared_topo_dn(void)
{
    return topo_plugin_conf.shared_topo_sdn;
}

char *
ipa_topo_get_domain_level_entry(void)
{
    return topo_plugin_conf.domain_level;
}

Slapi_DN *
ipa_topo_get_domain_level_entry_dn(void)
{
    return topo_plugin_conf.domain_level_sdn;
}

int
ipa_topo_get_min_domain_level(void)
{
    return topo_min_domain_level;
}

int
ipa_topo_get_domain_level(void)
{
    return ipa_domain_level;
}

char *
ipa_topo_get_plugin_shared_hosts(void)
{
    return topo_plugin_conf.shared_hosts;
}

Slapi_DN *
ipa_topo_get_plugin_shared_hosts_dn(void)
{
    return topo_plugin_conf.shared_hosts_sdn;
}

char *
ipa_topo_get_plugin_shared_bindgroup(void)
{
    return topo_plugin_conf.shared_bindgroup;
}

Slapi_DN *
ipa_topo_get_plugin_shared_bindgroup_dn(void)
{
    return topo_plugin_conf.shared_bindgroup_sdn;
}
char **
ipa_topo_get_plugin_replica_root(void)
{
    return topo_plugin_conf.shared_replica_root;
}

int
ipa_topo_get_plugin_version_major(void)
{
    return topo_plugin_conf.version_major;
}

int
ipa_topo_get_plugin_version_minor(void)
{
    return topo_plugin_conf.version_minor;
}

int
ipa_topo_get_plugin_startup_delay(void)
{
    return topo_plugin_conf.startup_delay;
}

void
ipa_topo_set_plugin_id(void *plg_id)
{
    topo_plugin_conf.identity = plg_id;
}

void
ipa_topo_set_plugin_active(int state)
{
     topo_plugin_conf.activated = state;
}
int
ipa_topo_get_plugin_active(void)
{
    return topo_plugin_conf.activated;
}


void
ipa_topo_set_post_init(int state)
{
     topo_plugin_conf.post_init = state;
}
int
ipa_topo_get_post_init(void)
{
    return topo_plugin_conf.post_init;
}

void
ipa_topo_set_plugin_shared_config(char *cfg)
{
    char *topo;
    char *hosts;
    char *domain_level;
    topo_plugin_conf.shared_config_base = cfg;
    topo = slapi_ch_smprintf("%s,%s","cn=topology",cfg);
    hosts = slapi_ch_smprintf("%s,%s","cn=masters",cfg);
    domain_level = slapi_ch_smprintf("%s,%s","cn=domain level",cfg);
    topo_plugin_conf.shared_topo = topo;
    topo_plugin_conf.shared_topo_sdn = slapi_sdn_new_normdn_byref(topo);
    topo_plugin_conf.shared_hosts = hosts;
    topo_plugin_conf.shared_hosts_sdn = slapi_sdn_new_normdn_byref(hosts);
    topo_plugin_conf.domain_level = domain_level;
    topo_plugin_conf.domain_level_sdn = slapi_sdn_new_normdn_byref(domain_level);

}

void
ipa_topo_set_plugin_shared_bindgroup(char *bindgroup)
{
    topo_plugin_conf.shared_bindgroup = bindgroup;
    topo_plugin_conf.shared_bindgroup_sdn = slapi_sdn_new_normdn_byref(bindgroup);
}

void
ipa_topo_set_domain_level(char *level)
{
    if (level == NULL) {
        ipa_domain_level = 0;
        return;
    }

    ipa_domain_level = atoi(level);
}

void
ipa_topo_set_plugin_hostname(char *hostname)
{
    topo_plugin_conf.hostname = hostname;
}

#define TOPO_PLUGIN_DEFAULT_STARTUP_DELAY 20
void
ipa_topo_set_plugin_startup_delay(char *delay)
{
    if (delay) {
        topo_plugin_conf.startup_delay = atoi(delay);
    } else {
        topo_plugin_conf.startup_delay = TOPO_PLUGIN_DEFAULT_STARTUP_DELAY;
    }
}

void
ipa_topo_set_plugin_version(char *version)
{
    char *minor;

    if ( version == NULL) {
        topo_plugin_conf.version_major = 0;
        topo_plugin_conf.version_minor = 0;
        return;
    }

    minor = strchr(version,'.');
    if (minor) {
        *minor = '\0';
        topo_plugin_conf.version_minor = atoi(++minor);
    } else {
        topo_plugin_conf.version_minor = 0;
    }
    topo_plugin_conf.version_major = atoi(version);
}

void
ipa_topo_init_shared_config(void)
{
    topo_shared_conf.allhosts = NULL;
    topo_shared_conf.replicas = NULL;
    topo_shared_conf.conf_lock = slapi_new_mutex();
}

void
ipa_topo_set_plugin_managed_attrs(char **attrs)
{
    if (attrs) {
        topo_plugin_conf.managed_attrs = attrs;
    } else {
        topo_plugin_conf.managed_attrs = ipa_topo_plugin_managed_attrs;
    }
}

void
ipa_topo_set_plugin_restricted_attrs(char **attrs)
{
    if (attrs) {
        topo_plugin_conf.restricted_attrs = attrs;
    } else {
        topo_plugin_conf.restricted_attrs = ipa_topo_plugin_restricted_attrs;
    }
}

int
ipa_topo_cfg_plugin_suffix_is_managed(const char *be_suffix) {

    int i = 0;
    char **shared_replica_root = ipa_topo_get_plugin_replica_root();

    while (shared_replica_root[i]) {
        if (0 == strcasecmp(shared_replica_root[i], be_suffix)) return 1;
        i++;
    }
    return 0;
}

int
ipa_topo_cfg_attr_is_restricted(char *type)
{
    int i;
    int rc = 0;
    char **rattrs = ipa_topo_get_plugin_restricted_attrs();
    for (i=0; rattrs[i]; i++) {
        if(0 == strcasecmp(rattrs[i], type)) {
            rc = 1;
            break;
        }
    }
    return rc;
}

void
ipa_topo_set_plugin_replica_root(char **root)
{
    topo_plugin_conf.shared_replica_root = root;
}

int
ipa_topo_init_plugin_config(Slapi_PBlock * pb)
{
    Slapi_Entry *plugin_entry = NULL;
    char *hostname;
    char *config_base;
    char *startup_delay;
    char *plugin_version;
    char *bindgroup;
    char **replica_root;

    /* get the local hostname */
    hostname = ipa_topo_util_get_pluginhost();
    if (hostname == NULL) {
        /* log error */
        return -1;
    } else {
        ipa_topo_set_plugin_hostname(hostname);
    }
    /* get the args */
    /* slapi_pblock_get(pb, SLAPI_PLUGIN_CONFIG_ENTRY, &plugin_entry); */
    slapi_pblock_get(pb, SLAPI_ADD_ENTRY, &plugin_entry);

    if(plugin_entry == NULL){
        return -1;
    }

    ipa_topo_set_plugin_active(0);

    config_base = slapi_entry_attr_get_charptr(plugin_entry,
                                               CONFIG_ATTR_SHARED_BASE);
    if(config_base){
        ipa_topo_set_plugin_shared_config(config_base);
    }

    replica_root = slapi_entry_attr_get_charray(plugin_entry,
                                                CONFIG_ATTR_REPLICA_ROOT);
    if(replica_root){
        ipa_topo_set_plugin_replica_root(replica_root);
    }

    bindgroup = slapi_entry_attr_get_charptr(plugin_entry,
                                               CONFIG_ATTR_SHARED_BINDDNGROUP);
    if(bindgroup){
        ipa_topo_set_plugin_shared_bindgroup(bindgroup);
    }

    startup_delay = slapi_entry_attr_get_charptr(plugin_entry,
                                                CONFIG_ATTR_STARTUP_DELAY);
    ipa_topo_set_plugin_startup_delay(startup_delay);
    slapi_ch_free_string(&startup_delay);

    plugin_version = slapi_entry_attr_get_charptr(plugin_entry,
                                                CONFIG_ATTR_PLUGIN_VERSION);
    ipa_topo_set_plugin_version(plugin_version);
    slapi_ch_free_string(&plugin_version);

    ipa_topo_util_set_domain_level();

    ipa_topo_util_check_plugin_active();


    ipa_topo_set_plugin_managed_attrs(NULL); /* use defaults */
    ipa_topo_set_plugin_restricted_attrs(NULL); /* use defaults */
    return 0;

}

void
ipa_topo_free_plugin_config(void)
{
    slapi_destroy_mutex(topo_plugin_conf.plg_lock);
    slapi_ch_free((void **)topo_plugin_conf.identity);
    slapi_ch_free_string(&topo_plugin_conf.hostname);
    slapi_ch_free_string(&topo_plugin_conf.shared_config_base);
    slapi_ch_free_string(&topo_plugin_conf.shared_topo);
    slapi_sdn_free(&topo_plugin_conf.shared_topo_sdn);
    slapi_ch_free_string(&topo_plugin_conf.shared_hosts);
    slapi_sdn_free(&topo_plugin_conf.shared_hosts_sdn);
    slapi_ch_free_string(&topo_plugin_conf.shared_bindgroup);
    slapi_sdn_free(&topo_plugin_conf.shared_bindgroup_sdn);
    slapi_ch_free_string(&topo_plugin_conf.domain_level);
    slapi_sdn_free(&topo_plugin_conf.domain_level_sdn);
    slapi_ch_array_free(topo_plugin_conf.shared_replica_root);
    if (ipa_topo_plugin_managed_attrs != topo_plugin_conf.managed_attrs)
        slapi_ch_array_free(topo_plugin_conf.managed_attrs);
    if (ipa_topo_plugin_restricted_attrs != topo_plugin_conf.restricted_attrs)
        slapi_ch_array_free(topo_plugin_conf.restricted_attrs);
}

void
ipa_topo_lock_conf(void)
{
    slapi_lock_mutex(topo_shared_conf.conf_lock);
}

void
ipa_topo_unlock_conf(void)
{
    slapi_unlock_mutex(topo_shared_conf.conf_lock);
}

int
ipa_topo_acquire_startup_inprogress(void)
{
    int acquired = 0;
    slapi_lock_mutex(topo_shared_conf.conf_lock);
    if (topo_shared_conf.startup_inprogress == 0 ) {
        topo_shared_conf.startup_inprogress = 1;
        acquired = 1;
    }
    slapi_unlock_mutex(topo_shared_conf.conf_lock);
    return acquired;
}

void
ipa_topo_release_startup_inprogress(void)
{
    slapi_lock_mutex(topo_shared_conf.conf_lock);
    topo_shared_conf.startup_inprogress = 0;
    slapi_unlock_mutex(topo_shared_conf.conf_lock);
}

TopoReplicaHost *
ipa_topo_cfg_host_find(TopoReplica *tconf, char *findhost, int lock)
{
    TopoReplicaHost *host = NULL;

    if (tconf->hosts == NULL) return NULL;

    if (lock) slapi_lock_mutex(tconf->repl_lock);
    for (host=tconf->hosts;host;host=host->next) {
        if (host->hostname == NULL) {
            /* this check is done to avoid a crash,
             * for which the root cause is not yet known.
             * Avoid the crash and log an error
             */
            slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_cfg_host_find: found a NULL hostname in host list\n");
            continue;
        }
        if (!strcasecmp(host->hostname,findhost)) {
           break;
        }
    }
    if (lock) slapi_unlock_mutex(tconf->repl_lock);
    return host;
}

TopoReplicaHost *
ipa_topo_cfg_host_new(char *newhost)
{
    TopoReplicaHost *newnode;
    newnode = (TopoReplicaHost *)slapi_ch_malloc(sizeof(TopoReplicaHost));
    newnode->next = NULL;
    newnode->hostname = newhost;
    return newnode;
}

void
ipa_topo_cfg_host_add(TopoReplica *replica, char *newhost)
{
    TopoReplicaHost *hostnode = NULL;
    if (replica == NULL || newhost == NULL) return;

    slapi_lock_mutex(replica->repl_lock);
    if (ipa_topo_cfg_host_find(replica, newhost, 0)) {
        /* host already added */
        slapi_unlock_mutex(replica->repl_lock);
        return;
    }
    hostnode = ipa_topo_cfg_host_new(slapi_ch_strdup(newhost));
    hostnode->next = replica->hosts;
    replica->hosts = hostnode;
    slapi_unlock_mutex(replica->repl_lock);

    return;
}

void
ipa_topo_cfg_host_free(TopoReplicaHost **node)
{
    slapi_ch_free((void **)&((*node)->hostname));
    slapi_ch_free((void **)node);
}

void
ipa_topo_cfg_host_del(Slapi_Entry *hostentry)
{
    char *delhost;
    TopoReplicaHost *hostnode = NULL;
    TopoReplicaHost *prevnode = NULL;
    char **repl_root = NULL;
    TopoReplica *replica = NULL;
    int i;

    delhost = slapi_entry_attr_get_charptr(hostentry,"cn");
    if (delhost == NULL) return;

    repl_root = slapi_entry_attr_get_charray(hostentry,"ipaReplTopoManagedSuffix");
    if (repl_root == NULL || *repl_root == NULL) return;

    for (i=0; repl_root[i];i++) {
        replica = ipa_topo_cfg_replica_find(repl_root[i], 1);
        if (replica == NULL) continue;

        slapi_lock_mutex(replica->repl_lock);
        hostnode = replica->hosts;
        prevnode = NULL;
        while (hostnode) {
            if (!strcasecmp(hostnode->hostname,delhost)) {
                /*remove from list and free*/
                if (prevnode) {
                    prevnode->next = hostnode->next;
                } else {
                    replica->hosts = hostnode->next;
                }
                ipa_topo_cfg_host_free(&hostnode);
                break;
            } else {
                prevnode = hostnode;
                hostnode = hostnode->next;
            }
        }
        slapi_unlock_mutex(replica->repl_lock);
    }

    return;
}

TopoReplicaSegment *
ipa_topo_cfg_replica_segment_find(TopoReplica *replica, char *leftHost, char *rightHost, int dir, int lock)
{
    TopoReplicaSegment *tsegm = NULL;
    TopoReplicaSegmentList *segments = NULL;
    int reverse_dir = SEGMENT_BIDIRECTIONAL;

    if (dir == SEGMENT_LEFT_RIGHT) reverse_dir = SEGMENT_RIGHT_LEFT;
    else if (dir == SEGMENT_RIGHT_LEFT) reverse_dir = SEGMENT_LEFT_RIGHT;
    else reverse_dir = SEGMENT_BIDIRECTIONAL;

    if (lock) slapi_lock_mutex(replica->repl_lock);
    segments = replica->repl_segments;
    while (segments) {

        tsegm = segments->segm;
        if ( (!strcasecmp(leftHost,tsegm->from) && !strcasecmp(rightHost,tsegm->to) &&
             (tsegm->direct & dir)) ||
             (!strcasecmp(leftHost,tsegm->to) && !strcasecmp(rightHost,tsegm->from) &&
             (tsegm->direct & reverse_dir))) {
           break;
        }
        tsegm = NULL;
        segments = segments->next;
    }
    if (lock) slapi_unlock_mutex(replica->repl_lock);

    return tsegm;
}

TopoReplicaAgmt *
ipa_topo_cfg_agmt_dup(TopoReplicaAgmt *agmt)
{
    TopoReplicaAgmt *dup = NULL;

    if (agmt == NULL) return NULL;

    dup = (TopoReplicaAgmt *) slapi_ch_calloc(1,sizeof(TopoReplicaAgmt));
    dup->rdn = slapi_ch_strdup(agmt->rdn);
    dup->origin = slapi_ch_strdup(agmt->origin);
    dup->target = slapi_ch_strdup(agmt->target);
    dup->enabled = slapi_ch_strdup(agmt->enabled);
    dup->repl_root = slapi_ch_strdup(agmt->repl_root);
    dup->strip_attrs = slapi_ch_strdup(agmt->strip_attrs);
    dup->total_attrs = slapi_ch_strdup(agmt->total_attrs);
    dup->repl_attrs = slapi_ch_strdup(agmt->repl_attrs);
    dup->repl_pause = slapi_ch_strdup(agmt->repl_pause);
    dup->repl_timeout = slapi_ch_strdup(agmt->repl_timeout);
    dup->repl_refresh = slapi_ch_strdup(agmt->repl_refresh);
    dup->repl_transport = slapi_ch_strdup(agmt->repl_transport);
    dup->repl_bind_dn = slapi_ch_strdup(agmt->repl_bind_dn);
    dup->repl_bind_cred = slapi_ch_strdup(agmt->repl_bind_cred);
    dup->repl_bind_method = slapi_ch_strdup(agmt->repl_bind_method);

    return dup;
}

TopoReplicaAgmt *
ipa_topo_cfg_agmt_dup_reverse(TopoReplicaAgmt *agmt)
{
    char *tmp;
    TopoReplicaAgmt *dup = NULL;
    dup = ipa_topo_cfg_agmt_dup(agmt);

    if (dup == NULL) return NULL;

    tmp = dup->origin;
    dup->origin = dup->target;
    dup->target = tmp;

    /* this is not enough, if a reverse agmt is
     * created because segment becomes bidirectional
     * we don't really know the rdn of the other direction
     * As long as this info is not in the segment,
     * assume std agmt naming and do best effort.
     */

    slapi_ch_free_string(&dup->rdn);
    dup->rdn = ipa_topo_agmt_std_rdn(dup->target);
    return dup;
}
static void
ipa_topo_cfg_agmt_done(TopoReplicaAgmt *agmt)
{
    if (agmt == NULL) return;

    slapi_ch_free_string(&agmt->origin);
    slapi_ch_free_string(&agmt->target);
    slapi_ch_free_string(&agmt->enabled);
    slapi_ch_free_string(&agmt->repl_root);
    slapi_ch_free_string(&agmt->strip_attrs);
    slapi_ch_free_string(&agmt->total_attrs);
    slapi_ch_free_string(&agmt->repl_attrs);
    slapi_ch_free_string(&agmt->repl_pause);
    slapi_ch_free_string(&agmt->repl_timeout);
    slapi_ch_free_string(&agmt->repl_refresh);
    slapi_ch_free_string(&agmt->repl_transport);
    slapi_ch_free_string(&agmt->repl_bind_dn);
    slapi_ch_free_string(&agmt->repl_bind_cred);
    slapi_ch_free_string(&agmt->repl_bind_method);
}

static void
ipa_topo_cfg_segment_done(TopoReplicaSegment *tsegm)
{
    if (tsegm == NULL) return;

    slapi_ch_free_string(&tsegm->name);
    slapi_ch_free_string(&tsegm->from);
    slapi_ch_free_string(&tsegm->to);
    ipa_topo_cfg_agmt_done(tsegm->left);
    ipa_topo_cfg_agmt_done(tsegm->right);
    slapi_ch_free((void **)&tsegm->left);
    slapi_ch_free((void **)&tsegm->right);
}

void
ipa_topo_cfg_segment_free(TopoReplicaSegment *tsegm)
{
    ipa_topo_cfg_segment_done(tsegm);
    slapi_ch_free((void **)&tsegm);
}

TopoReplicaSegment *
ipa_topo_cfg_segment_dup(TopoReplicaSegment *orig)
{
    TopoReplicaSegment *dup = NULL;

    if (orig == NULL) return NULL;

    dup = (TopoReplicaSegment *) slapi_ch_calloc(1,sizeof(TopoReplicaSegment));
    dup->name = slapi_ch_strdup(orig->name);
    dup->from = slapi_ch_strdup(orig->from);
    dup->to = slapi_ch_strdup(orig->to);
    dup->left = ipa_topo_cfg_agmt_dup(orig->left);
    dup->left = ipa_topo_cfg_agmt_dup(orig->left);
    dup->direct = orig->direct;
    dup->state = orig->state;
    return dup;
}

TopoReplicaSegment *
ipa_topo_cfg_segment_find(char *repl_root, char *leftHost, char *rightHost, int dir)
{
    TopoReplicaSegment *tsegm = NULL;
    TopoReplica *replica = NULL;

    slapi_lock_mutex(topo_shared_conf.conf_lock);

    replica = ipa_topo_cfg_replica_find(repl_root, 0);
    if (replica) {
        tsegm = ipa_topo_cfg_replica_segment_find(replica,leftHost,rightHost, dir, 1);
    }
    slapi_unlock_mutex(topo_shared_conf.conf_lock);
    return tsegm;
}

void
ipa_topo_cfg_segment_set_visited(TopoReplica *replica, TopoReplicaSegment *vsegm)
{
    TopoReplicaSegmentList *segments = NULL;
    TopoReplicaSegment *tsegm = NULL;
    char *leftHost = vsegm->from;
    char *rightHost = vsegm->to;

    slapi_lock_mutex(replica->repl_lock);
    segments = replica->repl_segments;
    while (segments) {
        tsegm = segments->segm;
        if ( (!strcasecmp(leftHost,tsegm->from) && !strcasecmp(rightHost,tsegm->to) &&
             (tsegm->direct == SEGMENT_BIDIRECTIONAL || tsegm->direct == SEGMENT_LEFT_RIGHT)) ||
             (!strcasecmp(leftHost,tsegm->to) && !strcasecmp(rightHost,tsegm->from) &&
             (tsegm->direct == SEGMENT_BIDIRECTIONAL || tsegm->direct == SEGMENT_RIGHT_LEFT))) {
            segments->visited = 1;
            break;
        }
        tsegm = NULL;
        segments = segments->next;
    }
    slapi_unlock_mutex(replica->repl_lock);

}

void
ipa_topo_cfg_segment_add(TopoReplica *replica, TopoReplicaSegment *tsegm)
{
    TopoReplicaSegmentList *seglist = NULL;

    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_cfg_segment_add: %s\n", tsegm->name);
    slapi_lock_mutex(replica->repl_lock);
    if (ipa_topo_cfg_replica_segment_find(replica,
                                          tsegm->from,
                                          tsegm->to, tsegm->direct, 0)){
        /* already exists: log error */
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                        "ipa_topo_cfg_segment_add: error: segment exists: %s\n",
                        tsegm->name);
        goto done;
    }
    seglist = (TopoReplicaSegmentList *)
              slapi_ch_calloc(1,sizeof(TopoReplicaSegmentList));
    seglist->visited = 0;
    seglist->segm = tsegm;
    if (replica->repl_segments == NULL) {
        replica->repl_segments = seglist;
    } else {
        seglist->next = replica->repl_segments;
        replica->repl_segments = seglist;
    }
    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_cfg_segment_added: %s\n", tsegm->name);
done:
    slapi_unlock_mutex(replica->repl_lock);
}

void
ipa_topo_cfg_segment_del(TopoReplica *tconf, TopoReplicaSegment *tsegm)
{
    TopoReplicaSegmentList *segment = NULL;
    TopoReplicaSegmentList *prev = NULL;

    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_cfg_segment_del: %s\n", tsegm->name);
    slapi_lock_mutex(tconf->repl_lock);
    segment = tconf->repl_segments;
    while (segment) {
        if (segment->segm == tsegm) {
            if (prev == NULL) {
                tconf->repl_segments = segment->next;
            } else {
                prev->next = segment->next;
            }
            /* free segment */
            ipa_topo_cfg_segment_free(tsegm);
            slapi_ch_free((void **)&segment);
            break;
        }
        prev = segment;
        segment = segment->next;
    }
    slapi_unlock_mutex(tconf->repl_lock);
}

TopoReplica *
ipa_topo_cfg_replica_new(void)
{
    TopoReplica *topoRepl;
    topoRepl = (TopoReplica *)slapi_ch_malloc(sizeof(TopoReplica));
    if (topoRepl) {
        topoRepl->next = NULL;
        topoRepl->repl_segments = NULL;
        topoRepl->repl_root = NULL;
        topoRepl->strip_attrs = NULL;
        topoRepl->total_attrs = NULL;
        topoRepl->repl_attrs = NULL;
        topoRepl->shared_config_base = NULL;
        topoRepl->hosts = NULL;
        topoRepl->repl_lock = slapi_new_mutex();
    }
    return topoRepl;

}

int
ipa_topo_cfg_replica_add(TopoReplica *tconf)
{
    int rc = 0;
    slapi_lock_mutex(topo_shared_conf.conf_lock);
    if (topo_shared_conf.replicas == NULL) {
        topo_shared_conf.replicas = tconf;
    } else if (ipa_topo_cfg_replica_find(tconf->repl_root,0)) {
        /* log error: already exists */
        rc = -1;
    } else {
        tconf->next = topo_shared_conf.replicas;
        topo_shared_conf.replicas = tconf;
    }
    slapi_unlock_mutex(topo_shared_conf.conf_lock);

    return rc;
}

void
ipa_topo_cfg_replica_del(TopoReplica *tconf)
{
/* TBD */
}

void
ipa_topo_cfg_replica_free(TopoReplica *tconf)
{
    TopoReplicaSegmentList *seg, *seg_next;
    TopoReplicaHost *host, *host_next;
    if (tconf) {
        slapi_destroy_mutex(tconf->repl_lock);
        slapi_ch_free_string(&tconf->shared_config_base);
        slapi_ch_free_string(&tconf->repl_root);
        seg = tconf->repl_segments;
        while (seg) {
            seg_next = seg->next;
            ipa_topo_cfg_segment_free(seg->segm);
            slapi_ch_free((void **)&seg);
            seg = seg_next;
        }
        host = tconf->hosts;
        while (host) {
            host_next = host->next;
            slapi_ch_free_string(&host->hostname);
            slapi_ch_free((void **)&host);
            host = host_next;
        }
        slapi_ch_free((void **)&tconf);
    }

}

TopoReplica *
ipa_topo_cfg_replica_find(char *repl_root, int lock)
{
    TopoReplica *tconf = NULL;

    if (lock) {
        slapi_lock_mutex(topo_shared_conf.conf_lock);
    }
    if (topo_shared_conf.replicas == NULL) goto done;

    tconf = topo_shared_conf.replicas;
    while (tconf) {
        if (!strcasecmp(repl_root,tconf->repl_root)) {
           break;
        }
        tconf = tconf->next;
    }

done:
    if (lock) {
        slapi_unlock_mutex(topo_shared_conf.conf_lock);
    }
    return tconf;
}
