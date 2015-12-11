
/**
 * IPA Replication Topology Plugin
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include "slapi-plugin.h"

#define PLUGIN_NAME            "ipa-topology-plugin"
#define PLUGIN_VENDOR          "freeipa"
#define PLUGIN_VERSION         "1.0"

#define IPA_TOPO_PLUGIN_SUBSYSTEM     "ipa-topology-plugin"
#define IPA_TOPO_PREOP_DESC           "ipa-topology-preop-subplugin"
#define IPA_TOPO_POSTOP_DESC          "ipa-topology-postop-subplugin"
#define IPA_TOPO_INTERNAL_POSTOP_DESC "ipa-topology-internal-postop-subplugin"

#define AGMT_TIMEOUT "300"
#define REPL_MAN_DN "cn=replman,cn=config"
#define REPL_MAN_PASSWD "replman"
#define REPL_ATTR_LIST  "(objectclass=*) $ EXCLUDE memberof idnssoaserial " \
                        "entryusn krblastsuccessfulauth krblastfailedauth "\
                        "krbloginfailedcount"
#define REPL_ATTR_STRIP "modifiersName modifyTimestamp internalModifiersName "\
                        "internalModifyTimestamp"
#define REPL_ATTR_LIST_TOTAL "(objectclass=*) $ EXCLUDE entryusn "\
                             "krblastsuccessfulauth krblastfailedauth "\
                             "krbloginfailedcount"

#define SEGMENT_DIR_BOTH "both"
#define SEGMENT_DIR_LEFT_ORIGIN "left-right"
#define SEGMENT_DIR_RIGHT_ORIGIN "right-left"
#define SEGMENT_LEFT_RIGHT 0x01
#define SEGMENT_RIGHT_LEFT 0x02
#define SEGMENT_BIDIRECTIONAL 0x03
#define SEGMENT_OBSOLETE 0x04
#define SEGMENT_AUTOGEN 0x05
#define SEGMENT_REMOVED 0x06
#define SEGMENT_OBSOLETE_STR "obsolete"
#define SEGMENT_AUTOGEN_STR "autogen"
#define SEGMENT_REMOVED_STR "removed"
#define TOPO_IGNORE_ENTRY  0
#define TOPO_CONFIG_ENTRY  1
#define TOPO_SEGMENT_ENTRY 2
#define TOPO_HOST_ENTRY    3
#define TOPO_DOMLEVEL_ENTRY 4

typedef struct topo_replica_agmt {
    char *rdn;
    char *origin;    /* supplier side of agmt */
    char *target;    /* consumer side of agmt */
    char *enabled;
    char *repl_root;
    char *strip_attrs;
    char *total_attrs;
    char *repl_attrs;
    char *repl_pause;
    char *repl_timeout;
    char *repl_refresh;
    char *repl_transport;
    char *repl_bind_dn;
    char *repl_bind_cred;
    char *repl_bind_method;
} TopoReplicaAgmt;

typedef struct topo_replica_segment {
    char *name;
    int direct;
    char *from;
    char *to;
    int state;
    TopoReplicaAgmt *left;
    TopoReplicaAgmt *right;
} TopoReplicaSegment;

typedef struct topo_replica_segment_list {
    struct topo_replica_segment_list *next;
    TopoReplicaSegment *segm;
    int visited;
} TopoReplicaSegmentList;

typedef struct topo_replica_host {
    struct topo_replica_host *next;
    char *hostname;
} TopoReplicaHost;

typedef struct topo_replica {
    struct topo_replica *next;
    Slapi_Mutex *repl_lock;
    char *shared_config_base;
    char *repl_root;
    char *strip_attrs;
    char *total_attrs;
    char *repl_attrs;
    TopoReplicaSegmentList *repl_segments;
    TopoReplicaHost *hosts;
} TopoReplica;

typedef struct topo_replica_conf {
    Slapi_Mutex *conf_lock;
    int startup_inprogress;
    TopoReplica *replicas;
    TopoReplicaHost *allhosts; /* maybe not needed */
} TopoReplicaConf;

typedef struct topo_plugin_config {
    Slapi_Mutex *plg_lock;
    void *identity;
    int version_major;
    int version_minor;
    int startup_delay;
    char *hostname;
    char *shared_config_base;
    char *shared_topo;
    Slapi_DN *shared_topo_sdn;
    char *shared_hosts;
    Slapi_DN *shared_hosts_sdn;
    char *shared_bindgroup;
    Slapi_DN *shared_bindgroup_sdn;
    char *domain_level;
    Slapi_DN *domain_level_sdn;
    char **shared_replica_root;
    char **managed_attrs;
    char **restricted_attrs;
    int activated;
    int post_init;
} TopoPluginConf;

#define CONFIG_ATTR_SHARED_BASE "nsslapd-topo-plugin-shared-config-base"
#define CONFIG_ATTR_REPLICA_ROOT "nsslapd-topo-plugin-shared-replica-root"
#define CONFIG_ATTR_SHARED_BINDDNGROUP "nsslapd-topo-plugin-shared-binddngroup"
#define CONFIG_ATTR_STARTUP_DELAY "nsslapd-topo-plugin-startup-delay"
#define CONFIG_ATTR_PLUGIN_ACTIVE "nsslapd-topo-plugin-activated"
#define CONFIG_ATTR_PLUGIN_VERSION "nsslapd-pluginVersion"

/* functions to manage config and global variables */
int ipa_topo_init_plugin_config(Slapi_PBlock *pb);
void ipa_topo_init_shared_config(void);
int ipa_topo_init_config(Slapi_PBlock *pb);
void *ipa_topo_get_plugin_id(void);
int ipa_topo_get_plugin_active(void);
int ipa_topo_get_post_init(void);
char *ipa_topo_get_plugin_shared_config(void);
Slapi_DN *ipa_topo_get_plugin_shared_topo_dn(void);
Slapi_DN *ipa_topo_get_plugin_shared_hosts_dn(void);
Slapi_DN *ipa_topo_get_plugin_shared_bindgroup_dn(void);
char *ipa_topo_get_plugin_shared_topo(void);
char *ipa_topo_get_plugin_shared_hosts(void);
char *ipa_topo_get_plugin_shared_bindgroup(void);
char *ipa_topo_get_plugin_hostname(void);
char **ipa_topo_get_plugin_replica_root(void);
char **ipa_topo_get_plugin_managed_attrs(void);
char **ipa_topo_get_plugin_restricted_attrs(void);
int ipa_topo_get_plugin_version_major(void);
int ipa_topo_get_plugin_version_minor(void);
char *ipa_topo_get_domain_level_entry(void);
Slapi_DN *ipa_topo_get_domain_level_entry_dn(void);
int ipa_topo_get_domain_level(void);
int ipa_topo_get_min_domain_level(void);
int ipa_topo_get_plugin_startup_delay(void);
void ipa_topo_set_plugin_id(void *plg_id);
void ipa_topo_set_plugin_active(int state);
void ipa_topo_set_post_init(int state);
void ipa_topo_set_plugin_shared_config(char *);
void ipa_topo_set_plugin_hostname(char *hostname);
void ipa_topo_set_plugin_replica_root(char **roots);
void ipa_topo_set_plugin_managed_attrs(char **mattrs);
void ipa_topo_set_plugin_restricted_attrs(char **mattrs);
void ipa_topo_set_plugin_startup_delay(char *delay);
void ipa_topo_set_plugin_version(char *version);
int ipa_topo_cfg_plugin_suffix_is_managed(const char *be_suffix);
void ipa_topo_free_plugin_config(void);
void ipa_topo_set_domain_level(char *level);
void ipa_topo_util_check_plugin_active(void);
void ipa_topo_lock_conf(void);
void ipa_topo_unlock_conf(void);
int ipa_topo_acquire_startup_inprogress(void);
void ipa_topo_release_startup_inprogress(void);
void ipa_topo_cfg_host_add(TopoReplica *tconf, char *host);
void ipa_topo_cfg_host_del(Slapi_Entry *hostentry);
TopoReplicaHost *ipa_topo_cfg_host_find(TopoReplica *tconf, char *host, int lock);
TopoReplicaHost *ipa_topo_cfg_host_new(char *newhost);
int ipa_topo_util_segm_dir(char *direction);
TopoReplicaSegment *
ipa_topo_cfg_segment_find(char *repl_root, char *leftHost, char *rightHosti, int dir);
TopoReplicaSegment *
ipa_topo_cfg_replica_segment_find(TopoReplica *tconf, char *leftHost,
                                  char *rightHost, int dir, int lock);
void ipa_topo_cfg_segment_set_visited(TopoReplica *tconf, TopoReplicaSegment *tsegm);
void ipa_topo_cfg_segment_add(TopoReplica *tconf, TopoReplicaSegment *tsegm);
void ipa_topo_cfg_segment_del(TopoReplica *tconf, TopoReplicaSegment *tsegm);
void ipa_topo_cfg_segment_free(TopoReplicaSegment *tsegm);
TopoReplicaSegment *ipa_topo_cfg_segment_dup(TopoReplicaSegment *orig);
TopoReplicaAgmt *ipa_topo_cfg_agmt_dup(TopoReplicaAgmt *agmt);
TopoReplicaAgmt *ipa_topo_cfg_agmt_dup_reverse(TopoReplicaAgmt *agmt);
TopoReplica *ipa_topo_cfg_replica_new(void);
int ipa_topo_cfg_replica_add(TopoReplica *tconf);
void ipa_topo_cfg_replica_del(TopoReplica *tconf);
void ipa_topo_cfg_replica_free(TopoReplica *tconf);
TopoReplica *ipa_topo_cfg_replica_find(char *repl_root, int lock);

/* pre and postop plugin functions */
int ipa_topo_check_entry_type(Slapi_Entry *entry);
/* postop plugin functions */
int ipa_topo_post_add(Slapi_PBlock *pb);
int ipa_topo_post_mod(Slapi_PBlock *pb);
int ipa_topo_post_del(Slapi_PBlock *pb);

/* preop plugin functions */
int ipa_topo_pre_add(Slapi_PBlock *pb);
int ipa_topo_pre_mod(Slapi_PBlock *pb);
int ipa_topo_pre_modrdn(Slapi_PBlock *pb);
int ipa_topo_pre_del(Slapi_PBlock *pb);

/* functions to modify agreements */
int ipa_topo_agmt_new(char *hostname, TopoReplica *repl_conf,
                      TopoReplicaAgmt *agmt);
int ipa_topo_agmt_del_dn(char *dn);
int ipa_topo_agmt_del(char *hostname, TopoReplica *conf,
                      TopoReplicaAgmt *agmt);
int ipa_topo_agmt_mod(TopoReplica *conf, TopoReplicaAgmt *agmt,
                      LDAPMod **mod, char *direction);
int ipa_topo_agmt_setup(char *hostname, TopoReplica *repl_conf,
                        TopoReplicaAgmt *agmt, int isgssapi);
int ipa_topo_setup_std_agmt(char *hostname, TopoReplica *repl_conf,
                            TopoReplicaAgmt *agmt);
int ipa_topo_setup_gssapi_agmt(char *hostname, TopoReplica *repl_conf,
                               TopoReplicaAgmt *agmt);
void ipa_topo_queue_apply_shared_config(time_t event_time, void *arg);
int ipa_topo_apply_shared_config(void);
int ipa_topo_apply_shared_replica_config(TopoReplica *replica_config);
void ipa_topo_util_suffix_init(Slapi_Entry *config);
void ipa_topo_util_suffix_update(Slapi_Entry *config_post, Slapi_Entry *config_pre,
                            LDAPMod **mods);
int ipa_topo_setup_managed_servers(void);
int ipa_topo_util_start(int delay);
int ipa_topo_util_update_agmt_list(TopoReplica *repl_conf,
                               TopoReplicaSegmentList *repl_segments);
char *ipa_topo_agmt_gen_rdn(char *from, char *to);
char *ipa_topo_agmt_std_rdn(char *to);
char *ipa_topo_agreement_dn(TopoReplica *conf, TopoReplicaAgmt *agmt, char *rdn);
char *ipa_topo_segment_dn(TopoReplica *tconf, char *segname);
void ipa_topo_util_segment_update(TopoReplica *repl_conf,
                                         TopoReplicaSegment *repl_segment,
                                         LDAPMod **mods ,char *fromHost);
void ipa_topo_util_missing_agmts_add(TopoReplica *repl_conf,
                                     TopoReplicaSegment *repl_segment,
                                     char *fromHost);
void ipa_topo_util_existing_agmts_del(TopoReplica *repl_conf,
                                      TopoReplicaSegment *repl_segment,
                                      char *fromHost);
void ipa_topo_util_existing_agmts_update(TopoReplica *repl_conf,
                                         TopoReplicaSegment *repl_segment,
                                         LDAPMod **mods ,char *fromHost);
void ipa_topo_util_missing_agmts_add_list(TopoReplica *repl_conf,
                                     TopoReplicaSegmentList *repl_segments,
                                     char *fromHost);
void ipa_topo_util_existing_agmts_del_list(TopoReplica *repl_conf,
                                      TopoReplicaSegmentList *repl_segments,
                                      char *fromHost);
void ipa_topo_util_existing_agmts_update_list(TopoReplica *repl_conf,
                                         TopoReplicaSegmentList *repl_segments,
                                         LDAPMod **mods ,char *fromHost);
TopoReplicaAgmt *ipa_topo_util_agmt_from_entry(Slapi_Entry *entry,
                                               char* replRoot, char *fromHost,
                                               char *toHost, char *direction);
TopoReplicaAgmt *
ipa_topo_util_find_segment_agmt(TopoReplicaSegmentList *repl_segments,
                                char *fromHost, char *toHost);
void ipa_topo_util_segm_update(TopoReplica *tconf, TopoReplicaSegment *tsegm,
                               int property);
int ipa_topo_util_segment_write(TopoReplica *tconf, TopoReplicaSegment *tsegm);
void ipa_topo_util_segm_remove(TopoReplica *tconf, TopoReplicaSegment *tsegm);
void ipa_topo_util_segment_merge(TopoReplica *tconf,
                                 TopoReplicaSegment *tsegm);
int ipa_topo_util_agmt_mark(TopoReplica *tconf, Slapi_Entry * repl_agmt,
                            TopoReplicaSegment *tsegm);
int ipa_topo_util_agmt_is_marked(Slapi_Entry * repl_agmt);
char *ipa_topo_agmt_attr_is_managed(char *type, char *direction);
int ipa_topo_cfg_attr_is_restricted(char *type);
int ipa_topo_util_setup_servers(void);
void ipa_topo_util_update_segments_for_host(TopoReplica *conf, char *hostname);
char *ipa_topo_util_get_ldap_principal(char *repl_root, char *hostname);
void ipa_topo_util_disable_repl_for_principal(char *repl_root, char *principal);
void ipa_topo_util_init_hosts(Slapi_Entry *hostentry);
void ipa_topo_util_add_host(Slapi_Entry *hostentry);
void ipa_topo_util_delete_host(Slapi_Entry *hostentry);
void ipa_topo_util_update_host(Slapi_Entry *hostentry, LDAPMod **mods);
void ipa_topo_util_cleanruv(Slapi_Entry *hostentry);
void ipa_topo_util_disable_repl_from_host(char *repl_root, char *delhost);
void ipa_topo_util_delete_segments_for_host(char *repl_root, char *delhost);

int ipa_topo_util_is_tombstone_op(Slapi_PBlock *pb);
int ipa_topo_util_entry_is_candidate(Slapi_Entry *e);
int ipa_topo_util_target_is_managed(Slapi_Entry *e);
int ipa_topo_util_segment_is_managed(TopoReplica *tconf, TopoReplicaSegment *tsegm);
char * ipa_topo_util_get_segm_attr(TopoReplicaAgmt *agmt, char *attr_type);
void ipa_topo_util_set_segm_attr(TopoReplicaAgmt *agmt, char *attr_type,
                                 char *attr_val);
TopoReplicaSegment *ipa_topo_util_segm_from_agmt(Slapi_Entry *repl_agmt);
TopoReplicaSegment *ipa_topo_util_segment_from_entry(TopoReplica *conf,
                                                     Slapi_Entry *entry);
TopoReplicaSegment *ipa_topo_util_find_segment(TopoReplica *conf,
                                               Slapi_Entry *entry);
TopoReplica *ipa_topo_util_conf_from_entry(Slapi_Entry *entry);
TopoReplica *ipa_topo_util_replica_init(Slapi_Entry *entry);
TopoReplica *ipa_topo_util_get_conf_for_segment(Slapi_Entry *segment_entry);
Slapi_Entry *ipa_topo_util_get_entry(char *dn);
int ipa_topo_util_modify(Slapi_DN *entrySDN, Slapi_Mods *smods);
char *ipa_topo_util_get_pluginhost(void);
TopoReplica *ipa_topo_util_get_replica_conf(char *repl_root);
TopoReplicaSegmentList *ipa_topo_util_get_replica_segments(TopoReplica *replica);
void ipa_topo_util_set_domain_level(void);
void ipa_topo_util_reset_init(char *repl_root);
