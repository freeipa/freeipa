/*
 * MIT Kerberos KDC database backend for FreeIPA
 *
 * Authors: Simo Sorce <ssorce@redhat.com>
 *
 * Copyright (C) 2011  Simo Sorce, Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <kdb.h>

static krb5_error_code ipadb_init_library(void)
{
    return KRB5_PLUGIN_OP_NOTSUPP;
}

static krb5_error_code ipadb_fini_library(void)
{
    return KRB5_PLUGIN_OP_NOTSUPP;
}

static krb5_error_code ipadb_init_module(krb5_context kcontext,
                                         char *conf_section,
                                         char **db_args, int mode)
{
    return KRB5_PLUGIN_OP_NOTSUPP;
}

static krb5_error_code ipadb_fini_module(krb5_context kcontext)
{
    return KRB5_PLUGIN_OP_NOTSUPP;
}

static krb5_error_code ipadb_create(krb5_context kcontext,
                                    char *conf_section,
                                    char **db_args)
{
    return KRB5_PLUGIN_OP_NOTSUPP;
}

static krb5_error_code ipadb_get_age(krb5_context kcontext,
                                     char *db_name, time_t *age)
{
    return KRB5_PLUGIN_OP_NOTSUPP;
}

static krb5_error_code ipadb_get_principal(krb5_context kcontext,
                                           krb5_const_principal search_for,
                                           unsigned int flags,
                                           krb5_db_entry **entry)
{
    return KRB5_PLUGIN_OP_NOTSUPP;
}

void ipadb_free_principal(krb5_context kcontext, krb5_db_entry *entry)
{
    return;
}

static krb5_error_code ipadb_put_principal(krb5_context kcontext,
                                           krb5_db_entry *entry,
                                           char **db_args)
{
    return KRB5_PLUGIN_OP_NOTSUPP;
}

static krb5_error_code ipadb_delete_principal(krb5_context kcontext,
                                              krb5_const_principal search_for)
{
    return KRB5_PLUGIN_OP_NOTSUPP;
}

static krb5_error_code ipadb_iterate(krb5_context kcontext,
                                     char *match_entry,
                                     int (*func)(krb5_pointer,
                                                 krb5_db_entry *),
                                     krb5_pointer func_arg)
{
    return KRB5_PLUGIN_OP_NOTSUPP;
}

static krb5_error_code ipadb_create_policy(krb5_context kcontext,
                                           osa_policy_ent_t policy)
{
    return KRB5_PLUGIN_OP_NOTSUPP;
}

static krb5_error_code ipadb_get_policy(krb5_context kcontext, char *name,
                                        osa_policy_ent_t *policy)
{
    return KRB5_PLUGIN_OP_NOTSUPP;
}

static krb5_error_code ipadb_put_policy(krb5_context kcontext,
                                        osa_policy_ent_t policy)
{
    return KRB5_PLUGIN_OP_NOTSUPP;
}

static krb5_error_code ipadb_iterate_policy(krb5_context kcontext,
                                            char *match_entry,
                                            osa_adb_iter_policy_func func,
                                            void *data)
{
    return KRB5_PLUGIN_OP_NOTSUPP;
}

static krb5_error_code ipadb_delete_policy(krb5_context kcontext,
                                           char *policy)
{
    return KRB5_PLUGIN_OP_NOTSUPP;
}

static void ipadb_free_policy(krb5_context kcontext, osa_policy_ent_t val)
{
    return;
}

static void *ipadb_alloc(krb5_context context, void *ptr, size_t size)
{
    return realloc(ptr, size);
}

static void ipadb_free(krb5_context context, void *ptr)
{
    free(ptr);
}

/* KDB Virtual Table */

kdb_vftabl kdb_function_table = {
    KRB5_KDB_DAL_MAJOR_VERSION,         /* major version number */
    0,                                  /* minor version number */
    ipadb_init_library,                 /* init_library */
    ipadb_fini_library,                 /* fini_library */
    ipadb_init_module,                  /* init_module */
    ipadb_fini_module,                  /* fini_module */
    ipadb_create,                       /* create */
    NULL,                               /* destroy */
    ipadb_get_age,                      /* get_age */
    NULL,                               /* lock */
    NULL,                               /* unlock */
    ipadb_get_principal,                /* get_principal */
    ipadb_free_principal,               /* free_principal */
    ipadb_put_principal,                /* put_principal */
    ipadb_delete_principal,             /* delete_principal */
    ipadb_iterate,                      /* iterate */
    ipadb_create_policy,                /* create_policy */
    ipadb_get_policy,                   /* get_policy */
    ipadb_put_policy,                   /* put_policy */
    ipadb_iterate_policy,               /* iter_policy */
    ipadb_delete_policy,                /* delete_policy */
    ipadb_free_policy,                  /* free_policy */
    ipadb_alloc,                        /* alloc */
    ipadb_free,                         /* free */
    NULL,                               /* fetch_master_key */
    NULL,                               /* fetch_master_key_list */
    NULL,                               /* store_master_key_list */
    NULL,                               /* dbe_search_enctype */
    NULL,                               /* change_pwd */
    NULL,                               /* promote_db */
    NULL,                               /* decrypt_key_data */
    NULL,                               /* encrypt_key_data */
    NULL,                               /* sign_authdata */
    NULL,                               /* check_transited_realms */
    NULL,                               /* check_policy_as */
    NULL,                               /* check_policy_tgs */
    NULL,                               /* audit_as_req */
    NULL,                               /* refresh_config */
    NULL                                /* check_allowed_to_delegate */
};

