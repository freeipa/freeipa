#include "topology.h"

/* generate the dn for a topology segment by providing replroot and segment name */
char *
ipa_topo_segment_dn(TopoReplica *tconf, char *segname)
{
    char *dn = NULL;

    dn = slapi_ch_smprintf("cn=%s,%s", segname, tconf->shared_config_base);
    return dn;
}

/* generate the rdn for a replication agreement by providing connected nodes */
char *
ipa_topo_agmt_gen_rdn(char *from, char *to)
{
    char *agmt_rdn = slapi_ch_smprintf("cn=%s-to-%s", from, to);

    return agmt_rdn;
}

/* generate the rdn for a replication agreement by providing target node */
char *
ipa_topo_agmt_std_rdn(char *to)
{
    char *agmt_rdn = slapi_ch_smprintf("cn=meTo%s", to);

    return agmt_rdn;
}

/* generate the dn for a replication agreement by providing replroot and host */
char *
ipa_topo_agreement_dn(TopoReplica *conf, TopoReplicaAgmt *agmt, char *rdn)
{
    char *dn;
    char *filter;
    Slapi_PBlock *pb;
    Slapi_Entry **entries;
    int ret;

    pb = slapi_pblock_new();
    filter = slapi_ch_smprintf("(&(objectclass=nsds5replica)(nsds5replicaroot=%s))",
                               conf->repl_root);
    slapi_search_internal_set_pb(pb, "cn=config", LDAP_SCOPE_SUB,
                                 filter, NULL, 0, NULL, NULL,
                                 ipa_topo_get_plugin_id(), 0);
    slapi_search_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);
    if (ret != 0) {
        dn = NULL;
    } else {
        slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &entries);
        if (NULL == entries || NULL == entries[0]) {
            slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_agreement_dn: no replica found\n");
            dn = NULL;
        } else if (rdn) {
            dn = slapi_ch_smprintf("%s,%s", rdn,
                                   slapi_entry_get_dn_const(entries[0]));
        } else {
            dn = slapi_ch_smprintf("cn=meTo%s,%s", agmt->target,
                                   slapi_entry_get_dn_const(entries[0]));
        }
    }
    slapi_free_search_results_internal(pb);
    slapi_pblock_destroy(pb);
    return dn;
}
int
ipa_topo_agmt_new(char *hostname, TopoReplica *conf, TopoReplicaAgmt *agmt)
{
    int ret = 0;
    if ((agmt->repl_bind_method == NULL) /* use GSSAPI as default */ ||
         (strcasecmp(agmt->repl_bind_method,"SASL/GSSAPI") == 0)) {
        ret = ipa_topo_agmt_setup(hostname, conf, agmt, 1);
    } else {
        ret = ipa_topo_agmt_setup(hostname, conf, agmt, 0);
    }
    return ret;
}

int ipa_topo_agmt_mod(TopoReplica *conf, TopoReplicaAgmt *agmt, LDAPMod **mods,
                      char *direction)
{
    int ret;
    Slapi_PBlock *pb;
    char *dn = NULL;
    Slapi_Entry **entries;
    int i;
    LDAPMod *tmp;
    Slapi_Mods *smods = NULL;

    dn = ipa_topo_agreement_dn(conf, agmt, agmt->rdn);
    if (dn  == NULL)
        return 1;

    pb = slapi_pblock_new();
    slapi_search_internal_set_pb(pb, dn, LDAP_SCOPE_BASE,
                                 "objectclass=*", NULL, 0, NULL, NULL,
                                 ipa_topo_get_plugin_id(), 0);
    slapi_search_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);
    if (ret != 0) {
        /* search failed */
        slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_agmt_mod: agreement not found: %s\n", dn);
        goto done;
    }
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &entries);
    if (NULL == entries || NULL == entries[0]) {
        /* no entry */
        ret = 1;
        goto done;
    }
    /* apply mods to entry */

    smods = slapi_mods_new();
    for (i = 0; (mods != NULL) && (mods[i] != NULL); i++) {
        char *type = ipa_topo_agmt_attr_is_managed(mods[i]->mod_type,direction);
        if (type) {
            tmp = mods[i];
            switch (tmp->mod_op & ~LDAP_MOD_BVALUES) {
            case LDAP_MOD_DELETE:
                break;
            case LDAP_MOD_ADD:
            case LDAP_MOD_REPLACE:
                slapi_mods_add_modbvps(smods, LDAP_MOD_REPLACE,
                                       type, tmp->mod_bvalues);
                break;
            }
            slapi_ch_free_string(&type);
        }
    }
    if (slapi_mods_get_num_mods(smods) > 0) {
        Slapi_DN *sdn = slapi_sdn_new_normdn_byref(dn);
        ipa_topo_util_modify(sdn, smods);
        slapi_sdn_free(&sdn);
    } else {
        slapi_ch_free_string(&dn);
    }
    slapi_mods_free(&smods);
done:
    if (ret) slapi_ch_free_string(&dn);
    slapi_free_search_results_internal(pb);
    slapi_pblock_destroy(pb);
    return ret;
}

int
ipa_topo_agmt_del(char *hostname, TopoReplica *conf, TopoReplicaAgmt *agmt)
{
    char *dn = NULL;
    int rc;

    dn = ipa_topo_agreement_dn(conf, agmt, agmt->rdn);
    slapi_log_error(SLAPI_LOG_FATAL, IPA_TOPO_PLUGIN_SUBSYSTEM,
                            "ipa_topo_agmt_del: %s\n", agmt->rdn?agmt->rdn:"RDN missing");
    if (dn  == NULL)
        return (-1);

    rc = ipa_topo_agmt_del_dn(dn);
    slapi_ch_free_string(&dn);

    return rc;
}

int
ipa_topo_agmt_del_dn(char *dn)
{
    int ret = 0;
    Slapi_PBlock *pb;
    pb = slapi_pblock_new();
    slapi_delete_internal_set_pb(pb, dn, NULL, NULL,
                                 ipa_topo_get_plugin_id(), 0);

    slapi_delete_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);
    slapi_pblock_destroy(pb);

    return ret;
}
int
ipa_topo_agmt_setup(char *hostname, TopoReplica *conf,
                    TopoReplicaAgmt *agmt, int isgssapi)
{
    Slapi_Entry *e = NULL;
    Slapi_PBlock *pb;
    char *dn = NULL;
    Slapi_DN *sdn = NULL;
    char *cn;
    char port[] = "389";
    char *description;
    int ret;
    /* Set up the new replication agreement entry */
    agmt->rdn = ipa_topo_agmt_gen_rdn(agmt->origin, agmt->target);
    dn = ipa_topo_agreement_dn(conf, agmt, agmt->rdn);
    if (dn  == NULL)
        return -1;
    sdn = slapi_sdn_new_normdn_byref(dn);
    e = slapi_entry_alloc();
    /* the entry now owns the dup'd dn */
    slapi_entry_init_ext(e, sdn, NULL); /* sdn is copied into e */
    slapi_sdn_free(&sdn);

    slapi_entry_add_string(e, SLAPI_ATTR_OBJECTCLASS, "nsds5replicationagreement");
    slapi_entry_add_string(e, SLAPI_ATTR_OBJECTCLASS, "ipaReplTopoManagedAgreement");
    cn = slapi_ch_smprintf("%s-to-%s", agmt->origin, agmt->target);
    slapi_entry_add_string(e, "cn",cn);
    slapi_ch_free_string(&cn);
    slapi_entry_add_string(e, "nsds5replicahost",hostname);
    slapi_entry_add_string(e, "nsds5replicaport",port);
    slapi_entry_add_string(e, "nsds5replicatimeout",AGMT_TIMEOUT);
    slapi_entry_add_string(e, "nsds5replicaroot",agmt->repl_root);
    description = slapi_ch_smprintf("%s to %s", ipa_topo_get_plugin_hostname(), hostname);
    slapi_entry_add_string(e, "description",description);
    slapi_ch_free_string(&description);
    slapi_entry_add_string(e, "ipaReplTopoManagedAgreementState",
                              "managed agreement - generated by topology plugin");

    if (isgssapi) {
        slapi_entry_add_string(e, "nsds5replicatransportinfo","LDAP");
        slapi_entry_add_string(e, "nsds5replicabindmethod","SASL/GSSAPI");
    } else {
        slapi_entry_add_string(e, "nsds5replicabinddn",REPL_MAN_DN);
        slapi_entry_add_string(e, "nsds5replicacredentials",REPL_MAN_PASSWD);
        slapi_entry_add_string(e, "nsds5replicatransportinfo","TLS");
        slapi_entry_add_string(e, "nsds5replicabindmethod","simple");
    }
    if (agmt->repl_attrs) {
        slapi_entry_add_string(e, "nsDS5ReplicatedAttributeList",agmt->repl_attrs);
    } else if (conf->repl_attrs) {
        slapi_entry_add_string(e, "nsDS5ReplicatedAttributeList",conf->repl_attrs);
    }
    if (agmt->strip_attrs) {
        slapi_entry_add_string(e, "nsds5ReplicaStripAttrs", agmt->strip_attrs);
    } else if (conf->strip_attrs) {
        slapi_entry_add_string(e, "nsds5ReplicaStripAttrs", conf->strip_attrs);
    }
    if (agmt->total_attrs) {
        slapi_entry_add_string(e, "nsDS5ReplicatedAttributeListTotal",
                               agmt->total_attrs);
    } else if (conf->total_attrs) {
        slapi_entry_add_string(e, "nsDS5ReplicatedAttributeListTotal",
                               conf->total_attrs);
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


int
ipa_topo_agmt_initialize_replication(char *hostname,
                                     TopoReplica *conf, TopoReplicaAgmt *agmt)
{
    int ret = 0;
    char *dn;
    Slapi_Mods *smods = slapi_mods_new();

    slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                          "nsds5ReplicaEnabled", "on");
    slapi_mods_add_string(smods, LDAP_MOD_ADD,
                          "nsds5BeginReplicaRefresh", "start");
    if (slapi_mods_get_num_mods(smods) > 0) {
        dn = ipa_topo_agreement_dn(conf, agmt, agmt->rdn);
        Slapi_DN *sdn = slapi_sdn_new_normdn_byref(dn);
        ipa_topo_util_modify(sdn, smods);
        slapi_sdn_free(&sdn);
    }
    slapi_mods_free(&smods);
    return ret;
}

char *
ipa_topo_agmt_attr_is_managed(char *type, char *direction)
{
    char *mtype = NULL;
    char **mattrs = NULL;
    char *subtype;
    char *ctype = slapi_ch_strdup(type);
    int i;

    /* segment attrs have the form
     * attrtype od attrtype;direction
     * find the attrtype and return the corresponding
     * repl agreeement attribute type
     */
    subtype = strchr(ctype,';');
    if (subtype) {
        /* attr is handling specific direction,
         * check if interested
         */
        if (strstr(ctype,direction)) {
            *subtype = '\0';
        } else {
            return NULL;
        }
    }
    mattrs = ipa_topo_get_plugin_managed_attrs();
    for (i=0; mattrs[i]; i++) {
        if(0 == strcasecmp(mattrs[i], ctype)) {
            mtype = slapi_ch_strdup(mattrs[i]);
            break;
        }
    }
    return mtype;
}
