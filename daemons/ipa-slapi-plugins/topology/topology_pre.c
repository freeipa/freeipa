#include "topology.h"

/* the preoperation plugins check if the managed replication config
 * is attempted to be directly modified.
 * This is only allowed for internal operations triggerd by the
 * topology plugin itself
 */

static int ipa_topo_pre_entry_in_scope(Slapi_PBlock *pb)
{
    Slapi_DN *dn;
    static Slapi_DN *config_dn =  NULL;;

    slapi_pblock_get(pb, SLAPI_TARGET_SDN, &dn);
    if (config_dn == NULL) {
        config_dn = slapi_sdn_new_dn_byval("cn=mapping tree,cn=config");
        /* this rules out entries in regular backends and most of
         * cn=config entries.
         */
    }
    return slapi_sdn_issuffix(dn,config_dn);

}
int ipa_topo_is_entry_managed(Slapi_PBlock *pb)
{
    Slapi_Entry *e;
    char *pi;
    int op_type;

    if (!ipa_topo_pre_entry_in_scope(pb)) {
        /* we don't care for general mods, only specific
         * entries in the mapping tree
         */
        return 0;
    }
    slapi_pblock_get(pb, SLAPI_OPERATION_TYPE, &op_type);
    if (op_type == SLAPI_OPERATION_ADD) {
        slapi_pblock_get(pb, SLAPI_ADD_ENTRY, &e);
    } else {
        slapi_pblock_get(pb, SLAPI_ENTRY_PRE_OP, &e);
    }
    if (!ipa_topo_util_entry_is_candidate(e)) {
        /* entry has no objectclass the plugin controls */
        return 0;
    }

    /* we have to check if the operation is triggered by the
     * topology plugin itself - allow it
     */
    slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY,&pi);
    if (pi && 0 == strcasecmp(pi, ipa_topo_get_plugin_id())) {
        return 0;
    }
    /* last check: is the endpoint of the agreement amanaged host ? */
    if (ipa_topo_util_target_is_managed(e)) {
        return 1;
    } else {
        return 0;
    }

}
int
ipa_topo_is_agmt_attr_restricted(Slapi_PBlock *pb)
{
    LDAPMod **mods;
    int i;
    int rc = 0;

    slapi_pblock_get(pb, SLAPI_MODIFY_MODS, &mods);
    for (i = 0; (mods != NULL) && (mods[i] != NULL); i++) {
        if (ipa_topo_cfg_attr_is_restricted(mods[i]->mod_type)) {
            rc = 1;
            break;
        }
    }
    return rc;
}
int
ipa_topo_is_invalid_managed_suffix(Slapi_PBlock *pb)
{
    LDAPMod **mods;
    int i;
    int rc = 0;

    slapi_pblock_get(pb, SLAPI_MODIFY_MODS, &mods);
    for (i = 0; (mods != NULL) && (mods[i] != NULL); i++) {
        if (0 == strcasecmp(mods[i]->mod_type, "ipaReplTopoManagedSuffix")) {
            switch (mods[i]->mod_op & ~LDAP_MOD_BVALUES) {
            case LDAP_MOD_DELETE:
                /* only deletion of specific valuses supported */
                if (NULL == mods[i]->mod_bvalues || NULL == mods[i]->mod_bvalues[0]) {
                    rc = 1;
                }
                break;
            case LDAP_MOD_ADD:
                break;
            case LDAP_MOD_REPLACE:
                rc = 1;
                break;
            }
        }
    }
    return rc;
}

int
ipa_topo_is_segm_attr_restricted(Slapi_PBlock *pb)
{
    LDAPMod **mods;
    int i;
    int rc = 0;

    slapi_pblock_get(pb, SLAPI_MODIFY_MODS, &mods);
    for (i = 0; (mods != NULL) && (mods[i] != NULL); i++) {
        if ((0 == strcasecmp(mods[i]->mod_type, "ipaReplTopoSegmentDirection")) ||
            (0 == strcasecmp(mods[i]->mod_type, "ipaReplTopoSegmentLeftNode")) ||
            (0 == strcasecmp(mods[i]->mod_type, "ipaReplTopoSegmentRightNode"))) {
            rc = 1;
            break;
        }
    }
    return rc;
}

/* connectivity check for topology
 * checks if the nodes of a segment would still be connected after
 * removal of the segments.
 * For description of the algorithm see design page
 */
struct node_list {
    struct node_list *next;
    char *node;
};

struct node_fanout {
    struct node_fanout *next;
    char *node;
    struct node_list *targets;
    int visited;
};
struct node_list *
node_list_dup (struct node_list *orig)
{
    struct node_list *dup = NULL;
    struct node_list *cursor = orig;
    struct node_list *start_dup = NULL;
    while (cursor) {
        if (dup) {
            dup->next = (struct node_list *)slapi_ch_malloc(sizeof(struct node_list));
            dup = dup->next;
        } else {
            dup = (struct node_list *)slapi_ch_malloc(sizeof(struct node_list));
            start_dup = dup;
        }
        dup->next = NULL;
        dup->node = slapi_ch_strdup(cursor->node);
        cursor = cursor->next;
    }
    return start_dup;
}

void
node_list_free(struct node_list *orig)
{
    struct node_list *cursor = orig;
    struct node_list *cur_next = NULL;
    while (cursor) {
        cur_next = cursor->next;
        slapi_ch_free_string(&cursor->node);
        slapi_ch_free((void **)&cursor);
        cursor = cur_next;
    }
}

struct node_fanout *
ipa_topo_connection_fanout_new (char *from, char *to)
{
   struct node_fanout *new_fanout = (struct node_fanout *)
                                    slapi_ch_malloc(sizeof(struct node_fanout));
   struct node_list *targets = (struct node_list *)
                               slapi_ch_malloc(sizeof(struct node_list));
   targets->next = NULL;
   targets->node = slapi_ch_strdup(to);
   new_fanout->next = NULL;
   new_fanout->node = slapi_ch_strdup(from);
   new_fanout->targets = targets;
   new_fanout->visited = 0;
   return new_fanout;
}

void
ipa_topo_connection_fanout_free (struct node_fanout *fanout)
{
    struct node_fanout *cursor = fanout;
    struct node_fanout *cur_next = NULL;
    while (cursor) {
        cur_next = cursor->next;
        slapi_ch_free_string(&cursor->node);
        node_list_free(cursor->targets);
        slapi_ch_free((void **)&cursor);
        cursor = cur_next;
    }
}

struct node_fanout *
ipa_topo_connection_fanout_extend (struct node_fanout *fanout_in, char *from, char *to)
{
    struct node_fanout *cursor;
    if (fanout_in == NULL) {
        /* init fanout */
        return ipa_topo_connection_fanout_new(from,to);
    }
    /* extend existing fanout struct */
    cursor = fanout_in;
    while (cursor) {
        if (strcasecmp(cursor->node, from) == 0) break;
        cursor = cursor->next;
    }
    if (cursor) {
        struct node_list *target = (struct node_list *)
                                   slapi_ch_malloc(sizeof(struct node_list));
        target->next = cursor->targets;
        target->node = slapi_ch_strdup(to);
        cursor->targets = target;
        return fanout_in;
    } else {
        cursor = ipa_topo_connection_fanout_new(from,to);
        cursor->next = fanout_in;
        return cursor;
    }
}
struct node_fanout *
ipa_topo_connection_fanout(TopoReplica *tconf, TopoReplicaSegment *tseg)
{
    struct node_fanout *fout = NULL;
    TopoReplicaSegment *segm;

    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_connection_fanout for segment: %s\n",tseg->name);
    /* lock it */
    TopoReplicaSegmentList *seglist = tconf->repl_segments;
    while (seglist) {
        segm = seglist->segm;
        if (strcasecmp(segm->name, tseg->name)) {
            if (segm->direct == SEGMENT_LEFT_RIGHT ||
                segm->direct == SEGMENT_BIDIRECTIONAL ) {
                fout = ipa_topo_connection_fanout_extend(fout, segm->from, segm->to);
            }
            if (segm->direct == SEGMENT_RIGHT_LEFT ||
                segm->direct == SEGMENT_BIDIRECTIONAL) {
                fout = ipa_topo_connection_fanout_extend(fout, segm->to, segm->from);
            }
        }
        seglist = seglist->next;
    }
    return fout;
}

void
ipa_topo_connection_append(struct node_fanout *fanout, struct node_list *reachable)
{
    struct node_fanout *cursor = fanout;

    while (cursor) {
        if (strcasecmp(reachable->node, cursor->node) == 0 &&
           cursor->visited == 0) {
            struct node_list *tail;
            struct node_list *extend;
            cursor->visited = 1;
            extend = node_list_dup(cursor->targets);
            tail = reachable;
            while (tail->next) {
                tail = tail->next;
            }
            tail->next = extend;
            break;
        }
        cursor = cursor->next;
    }
}

int
ipa_topo_connection_exists(struct node_fanout *fanout, char* from, char *to)
{
    struct node_list *reachable = NULL;
    struct node_fanout *cursor = fanout;
    int connected = 0;
    /* init reachable nodes */
    while (cursor) {
        if (strcasecmp(cursor->node, from) == 0) {
            cursor->visited = 1;
            reachable = node_list_dup(cursor->targets);
        } else {
            cursor->visited = 0;
        }
        cursor = cursor->next;
    }
    /* check if target is in reachable nodes, if
     * not, expand reachables
     */
    if (reachable == NULL) return 0;
    while (reachable) {
        if (strcasecmp(reachable->node, to) == 0) {
            connected = 1;
            break;
        }
        ipa_topo_connection_append(fanout, reachable);
        reachable = reachable->next;
    }
    node_list_free(reachable);
    return connected;
}

int
ipa_topo_check_segment_is_valid(Slapi_PBlock *pb, char **errtxt)
{
    int rc = 0;
    Slapi_Entry *add_entry;
    char *pi;

    /* we have to check if the operation is triggered by the
     * topology plugin itself - allow it
     */
    slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY,&pi);
    if (pi && 0 == strcasecmp(pi, ipa_topo_get_plugin_id())) {
        return 0;
    }
    slapi_pblock_get(pb,SLAPI_ADD_ENTRY,&add_entry);
    if (TOPO_SEGMENT_ENTRY != ipa_topo_check_entry_type(add_entry)) {
        return 0;
    } else {
        /* a new segment is added
         * verify that the segment does not yet exist
         */
        char *leftnode = slapi_entry_attr_get_charptr(add_entry,"ipaReplTopoSegmentLeftNode");
        char *rightnode = slapi_entry_attr_get_charptr(add_entry,"ipaReplTopoSegmentRightNode");
        char *dir = slapi_entry_attr_get_charptr(add_entry,"ipaReplTopoSegmentDirection");
        if (leftnode == NULL || rightnode == NULL || dir == NULL) {
                *errtxt = slapi_ch_smprintf("Segment definition is incomplete"
                                   ". Add rejected.\n");
            rc = 1;
        } else if (strcasecmp(dir,SEGMENT_DIR_BOTH) && strcasecmp(dir,SEGMENT_DIR_LEFT_ORIGIN) &&
            strcasecmp(dir,SEGMENT_DIR_RIGHT_ORIGIN)) {
                *errtxt = slapi_ch_smprintf("Segment has unsupported direction"
                                   ". Add rejected.\n");
                slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                                "segment has unknown direction: %s\n", dir);
                rc = 1;
        } else if (0 == strcasecmp(leftnode,rightnode)) {
                *errtxt = slapi_ch_smprintf("Segment is self referential"
                                   ". Add rejected.\n");
                slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                                "segment is self referential\n");
                rc = 1;
        } else {
            TopoReplicaSegment *tsegm = NULL;
            TopoReplica *tconf = ipa_topo_util_get_conf_for_segment(add_entry);
            if (tconf == NULL ) {
                *errtxt = slapi_ch_smprintf("Segment configuration suffix not found"
                                   ". Add rejected.\n");
                slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                                "topology not configured for segment\n");
                rc = 1;
            } else {
                tsegm = ipa_topo_util_find_segment(tconf, add_entry);
            }
            if (tsegm) {
                *errtxt = slapi_ch_smprintf("Segment already exists in topology"
                                   ". Add rejected.\n");
                slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                                "segment to be added does already exist\n");
                rc = 1;
            }
        }
        slapi_ch_free_string(&leftnode);
        slapi_ch_free_string(&rightnode);
        slapi_ch_free_string(&dir);
    }
    return rc;
}

int
ipa_topo_check_segment_updates(Slapi_PBlock *pb)
{
    int rc = 0;
    Slapi_Entry *mod_entry;
    char *pi;

    /* we have to check if the operation is triggered by the
     * topology plugin itself - allow it
     */
    slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY,&pi);
    if (pi && 0 == strcasecmp(pi, ipa_topo_get_plugin_id())) {
        return 0;
    }
    slapi_pblock_get(pb,SLAPI_MODIFY_EXISTING_ENTRY,&mod_entry);
    if (TOPO_SEGMENT_ENTRY == ipa_topo_check_entry_type(mod_entry) &&
        (ipa_topo_is_segm_attr_restricted(pb))) {
        rc = 1;
    }
    return rc;
}

int
ipa_topo_check_entry_move(Slapi_PBlock *pb)
{
    int rc = 0;
    int entry_type = TOPO_IGNORE_ENTRY;
    Slapi_Entry *modrdn_entry;
    slapi_pblock_get(pb,SLAPI_MODRDN_TARGET_ENTRY,&modrdn_entry);
    entry_type = ipa_topo_check_entry_type(modrdn_entry);
    switch (entry_type) {
    case TOPO_SEGMENT_ENTRY:
    case TOPO_CONFIG_ENTRY: {
        Slapi_DN *newsuperior = NULL;
        slapi_pblock_get(pb, SLAPI_MODRDN_NEWSUPERIOR_SDN, &newsuperior);
        if (newsuperior && slapi_sdn_get_dn(newsuperior)) rc = 1;
        break;
        }
    default:
        rc = 0;
        break;
    }
    return rc;
}

int
ipa_topo_check_host_updates(Slapi_PBlock *pb)
{
    int rc = 0;
    Slapi_Entry *mod_entry;
    char *pi;

    /* we have to check if the operation is triggered by the
     * topology plugin itself - allow it
     */
    slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY,&pi);
    if (pi && 0 == strcasecmp(pi, ipa_topo_get_plugin_id())) {
        return 0;
    }
    slapi_pblock_get(pb,SLAPI_MODIFY_EXISTING_ENTRY,&mod_entry);
    if (TOPO_HOST_ENTRY == ipa_topo_check_entry_type(mod_entry) &&
        (ipa_topo_is_invalid_managed_suffix(pb))) {
        rc = 1;
    }
    return rc;
}

int
ipa_topo_check_topology_disconnect(Slapi_PBlock *pb)
{
    int rc = 1;
    Slapi_Entry *del_entry;
    struct node_fanout *fanout = NULL;
    char *pi;

    /* we have to check if the operation is triggered by the
     * topology plugin itself - allow it
     */
    slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY,&pi);
    if (pi && 0 == strcasecmp(pi, ipa_topo_get_plugin_id())) {
        return 0;
    }
    slapi_pblock_get(pb,SLAPI_DELETE_EXISTING_ENTRY,&del_entry);
    if (TOPO_SEGMENT_ENTRY != ipa_topo_check_entry_type(del_entry)) {
        return 0;
    } else {
        TopoReplica *tconf = ipa_topo_util_get_conf_for_segment(del_entry);
        if (tconf == NULL) {
            slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "topology not configured for segment\n");
            rc = 0; /* this segment is not controlled by the plugin */
            goto done;
        }
        TopoReplicaSegment *tsegm = NULL;
        tsegm = ipa_topo_util_find_segment(tconf, del_entry);
        if (tsegm == NULL) {
            slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "segment to be deleted does not exist\n");
            goto done;
        }
        if (!ipa_topo_util_segment_is_managed(tconf,tsegm)) {
            /* not both endpoints are managed servers, delete is ok */
            rc = 0;
            goto done;
        }
        /* check if removal of segment would break connectivity */
        fanout = ipa_topo_connection_fanout(tconf, tsegm);
        if (fanout == NULL) goto done;

        if (ipa_topo_connection_exists(fanout, tsegm->from, tsegm->to) &&
            ipa_topo_connection_exists(fanout, tsegm->to, tsegm->from)) {
            rc = 0;
        }
        ipa_topo_connection_fanout_free(fanout);
    }

done:
    return rc;
}

static int
ipa_topo_pre_ignore_op(Slapi_PBlock *pb)
{
    int repl_op = 0;
    /* changes to cn=config aren't replicated, for changes to
     * shared topology area checks have been done on master
     * accepting the operation
     */
    slapi_pblock_get (pb, SLAPI_IS_REPLICATED_OPERATION, &repl_op);
    return repl_op;
}

int ipa_topo_pre_add(Slapi_PBlock *pb)
{
    int result = SLAPI_PLUGIN_SUCCESS;
    char *errtxt  = NULL;

    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                    "--> ipa_topo_pre_add\n");

    if (0 == ipa_topo_get_plugin_active()) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                    "<-- ipa_topo_pre_add - plugin not active\n");
        return 0;
    }

    if (ipa_topo_pre_ignore_op(pb)) return result;

    if (ipa_topo_is_entry_managed(pb)) {
        int rc = LDAP_UNWILLING_TO_PERFORM;
        errtxt = slapi_ch_smprintf("Entry is managed by topology plugin."
                                   " Adding of entry not allowed.\n");
        slapi_pblock_set(pb, SLAPI_PB_RESULT_TEXT, errtxt);
        slapi_pblock_set(pb, SLAPI_RESULT_CODE, &rc);
        result = SLAPI_PLUGIN_FAILURE;
    } else if (ipa_topo_check_segment_is_valid(pb, &errtxt)) {
        int rc = LDAP_UNWILLING_TO_PERFORM;
        slapi_pblock_set(pb, SLAPI_PB_RESULT_TEXT, errtxt);
        slapi_pblock_set(pb, SLAPI_RESULT_CODE, &rc);
        result = SLAPI_PLUGIN_FAILURE;
    }
    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                    "<-- ipa_topo_pre_add\n");
    return result;
}
int
ipa_topo_pre_mod(Slapi_PBlock *pb)
{

    int result = SLAPI_PLUGIN_SUCCESS;
    char *errtxt = NULL;

    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                    "--> ipa_topo_pre_mod\n");

    if (0 == ipa_topo_get_plugin_active()) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                    "<-- ipa_topo_pre_mod - plugin not active\n");
        return 0;
    }

    if (ipa_topo_pre_ignore_op(pb)) return result;

    if (ipa_topo_is_entry_managed(pb)){
        /* this means it is a replication agreement targeting a managed server
         * next check is if it tries to modify restricted attributes
         */
        if(ipa_topo_is_agmt_attr_restricted(pb)) {
            errtxt = slapi_ch_smprintf("Entry and attributes are managed by topology plugin."
                                       "No direct modifications allowed.\n");
        }
    } else if (ipa_topo_check_segment_updates(pb)) {
        /* some updates to segments are not supported */
        errtxt = slapi_ch_smprintf("Modification of connectivity and segment nodes "
                                   " is not supported.\n");
    } else if (ipa_topo_check_host_updates(pb)) {
        /* some updates to segments are not supported */
        errtxt = slapi_ch_smprintf("Modification of managed suffixes must explicitely "
                                   " list suffix.\n");
    }
    if (errtxt) {
        int rc = LDAP_UNWILLING_TO_PERFORM;
        slapi_pblock_set(pb, SLAPI_PB_RESULT_TEXT, errtxt);
        slapi_pblock_set(pb, SLAPI_RESULT_CODE, &rc);
        result = SLAPI_PLUGIN_FAILURE;
    }
    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                    "<-- ipa_topo_pre_mod\n");
    return result;
}

int
ipa_topo_pre_del(Slapi_PBlock *pb)
{
    int result = SLAPI_PLUGIN_SUCCESS;

    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                    "--> ipa_topo_pre_del\n");

    if (0 == ipa_topo_get_plugin_active()) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                    "<-- ipa_topo_pre_del - plugin not active\n");
        return 0;
    }

    if (ipa_topo_pre_ignore_op(pb) ||
        ipa_topo_util_is_tombstone_op(pb)) return result;

    if (ipa_topo_is_entry_managed(pb)) {
        int rc = LDAP_UNWILLING_TO_PERFORM;
        char *errtxt;
        errtxt = slapi_ch_smprintf("Entry is managed by topology plugin."
                                   "Deletion not allowed.\n");
        slapi_pblock_set(pb, SLAPI_PB_RESULT_TEXT, errtxt);
        slapi_pblock_set(pb, SLAPI_RESULT_CODE, &rc);
        result = SLAPI_PLUGIN_FAILURE;
    } else if (ipa_topo_check_topology_disconnect(pb)) {
        int rc = LDAP_UNWILLING_TO_PERFORM;
        char *errtxt;
        errtxt = slapi_ch_smprintf("Removal of Segment disconnects topology."
                                   "Deletion not allowed.\n");
        slapi_pblock_set(pb, SLAPI_PB_RESULT_TEXT, errtxt);
        slapi_pblock_set(pb, SLAPI_RESULT_CODE, &rc);
        result = SLAPI_PLUGIN_FAILURE;
    }
    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                    "<-- ipa_topo_pre_del\n");
    return result;
}
int
ipa_topo_pre_modrdn(Slapi_PBlock *pb)
{

    int result = SLAPI_PLUGIN_SUCCESS;

    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                    "--> ipa_topo_pre_modrdn\n");

    if (0 == ipa_topo_get_plugin_active()) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_TOPO_PLUGIN_SUBSYSTEM,
                    "<-- ipa_topo_pre_modrdn - plugin not active\n");
        return 0;
    }

    if (ipa_topo_pre_ignore_op(pb)) return result;

    if (ipa_topo_check_entry_move(pb)){
        int rc = LDAP_UNWILLING_TO_PERFORM;
        char *errtxt;
        errtxt = slapi_ch_smprintf("Moving of a segment or config entry "
                                   "to another subtree is not allowed.\n");
        slapi_pblock_set(pb, SLAPI_PB_RESULT_TEXT, errtxt);
        slapi_pblock_set(pb, SLAPI_RESULT_CODE, &rc);
        result = SLAPI_PLUGIN_FAILURE;
    }

    return result;

}
