/** BEGIN COPYRIGHT BLOCK
 * This program is free software; you can redistribute it and/or modify
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
 *
 * Additional permission under GPLv3 section 7:
 *
 * In the following paragraph, "GPL" means the GNU General Public
 * License, version 3 or any later version, and "Non-GPL Code" means
 * code that is governed neither by the GPL nor a license
 * compatible with the GPL.
 *
 * You may link the code of this Program with Non-GPL Code and convey
 * linked combinations including the two, provided that such Non-GPL
 * Code only links to the code of this Program through those well
 * defined interfaces identified in the file named EXCEPTION found in
 * the source code files (the "Approved Interfaces"). The files of
 * Non-GPL Code may instantiate templates or use macros or inline
 * functions from the Approved Interfaces without causing the resulting
 * work to be covered by the GPL. Only the copyright holders of this
 * Program may make changes or additions to the list of Approved
 * Interfaces.
 *
 * Authors:
 * original authors of 389 example ldap/servers/slapd/test-plugins/testpreop.c
 * Petr Spacek <pspacek@redhat.com>
 *
 * Copyright (C) 2001 Sun Microsystems, Inc. Used by permission.
 * Copyright (C) 2013 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/


/*
 * This is 389 DS plug-in with supporting functions for IPA-integrated DNS.
 *
 * To test this plug-in, stop the server, edit the dse.ldif file
 * (in the <server_root>/slapd-<server_id>/config directory)
 * and add the following lines before restarting the server:
 *
 * dn: cn=IPA DNS,cn=plugins,cn=config
 * objectClass: top
 * objectClass: nsslapdPlugin
 * objectClass: extensibleObject
 * cn: IPA DNS
 * nsslapd-pluginDescription: IPA DNS support plugin
 * nsslapd-pluginEnabled: on
 * nsslapd-pluginId: ipa_dns
 * nsslapd-pluginInitfunc: ipadns_init
 * nsslapd-pluginPath: libipa_dns.so
 * nsslapd-pluginType: preoperation
 * nsslapd-pluginVendor: Red Hat, Inc.
 * nsslapd-pluginVersion: 1.0
 * nsslapd-plugin-depends-on-type: database
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include "slapi-plugin.h"
#include "util.h"

#define IPA_PLUGIN_NAME "ipa_dns"
#define IPADNS_CLASS_ZONE "idnsZone"
#define IPADNS_ATTR_SERIAL "idnsSOASerial"
#define IPADNS_DEFAULT_SERIAL "1"

#define EFALSE 0
#define ETRUE 1

Slapi_PluginDesc ipadns_desc = { IPA_PLUGIN_NAME, "Red Hat, Inc.", "1.0",
				"IPA DNS support plugin" };

/* Global variable with "constant" = IPADNS_ZONE_SERIAL. */
Slapi_Value *value_zone = NULL;

/**
 * Determine if given entry represents IPA DNS zone.
 *
 * \return \c 0 when objectClass idnsZone is not present in the entry.
 * \return \c 1 when objectClass idnsZone is present in the entry.
 * \return \c -1 when some error occurred.
 */
int
ipadns_entry_iszone( Slapi_Entry *entry ) {
	Slapi_Attr *obj_class = NULL;
	Slapi_Value *value = NULL;
	char *dn = NULL;
	int hint = 0;

	dn = slapi_entry_get_dn( entry );

	if ( slapi_entry_attr_find( entry, SLAPI_ATTR_OBJECTCLASS, &obj_class )
	    != 0) {
		LOG( "Object without objectClass encountered: entry '%s'\n",
		    dn );
		return EFAIL;
	}

	if ( slapi_attr_first_value( obj_class, &value ) != 0 ) {
		LOG( "Cannot iterate over objectClass values in entry '%s'\n",
		    dn );
		return EOK;
	}

	do {
		if ( slapi_value_compare( obj_class, value, value_zone ) == 0 )
			return ETRUE; /* Entry is a DNS zone */

		hint = slapi_attr_next_value( obj_class, hint, &value );
	} while ( hint != -1 );

	return EFALSE; /* Entry is not a DNS zone */
}

/**
 * The server calls this plug-in function before executing LDAP ADD operation.
 *
 * ipadns_add function adds default value to idnsSOAserial attribute
 * in idnsZone objects if the attribute is not present.
 *
 * Default value is added only to objects coming from other servers
 * via replication.
 */
int
ipadns_add( Slapi_PBlock *pb )
{
	Slapi_Entry	*e = NULL;
	Slapi_Attr	*a = NULL;
	char 		*dn = NULL;
	int		cnt;
	int 		ret;
	int		is_repl_op;

	if ( slapi_pblock_get( pb, SLAPI_IS_REPLICATED_OPERATION,
			      &is_repl_op ) != 0 ) {
		LOG_FATAL( "slapi_pblock_get SLAPI_IS_REPLICATED_OPERATION "
			  "failed!?\n" );
		return EFAIL;
	}

	/* Mangle only ADDs coming from replication. */
	if ( !is_repl_op )
		return EOK;

	/* Get the entry that is about to be added. */
	if ( slapi_pblock_get( pb, SLAPI_ADD_ENTRY, &e ) != 0 ) {
		LOG( "Could not get entry\n" );
		return EFAIL;
	}
	dn = slapi_entry_get_dn( e );

	/* Do nothing if entry doesn't represent IPA DNS zone. */
	ret = ipadns_entry_iszone( e );
	if ( ret == EFALSE )
		return EOK;
	else if ( ret == EFAIL ) {
		LOG( "Could not check objectClasses in entry '%s'\n", dn );
		return EFAIL; /* TODO: Should I return OK to not block DS? */
	}

	/* Do nothing if the entry already has idnsSOASerial attribute set
	 * and a value is present. */
	if ( slapi_entry_attr_find( e, IPADNS_ATTR_SERIAL, &a ) == 0 ) {
		if ( slapi_attr_get_numvalues( a, &cnt ) != 0 ) {
			LOG( "Could not get value count for attribute '%s' "
			     "in entry '%s'\n", IPADNS_ATTR_SERIAL, dn );
			return EFAIL;
		} else if ( cnt != 0 ) {
			return EOK;
		}
	}

	if ( slapi_entry_add_string( e, IPADNS_ATTR_SERIAL,
				    IPADNS_DEFAULT_SERIAL ) != 0 ) {
		LOG( "Could not add default SOA serial to entry '%s'\n", dn );
		return EFAIL;
	}

	return EOK; /* allow the operation to continue */
}

static int
ipadns_close( Slapi_PBlock *pb )
{
	( void ) pb;
	if ( value_zone )
		slapi_value_free( &value_zone );

	return EOK;
}

/* Initialization function. */
#ifdef _WIN32
__declspec(dllexport)
#endif
int
ipadns_init( Slapi_PBlock *pb )
{
	/* Register the two pre-operation plug-in functions,
	   and specify the server plug-in version. */
	if ( slapi_pblock_set( pb, SLAPI_PLUGIN_VERSION,
	    SLAPI_PLUGIN_VERSION_03 ) != 0 ||
	    slapi_pblock_set( pb, SLAPI_PLUGIN_DESCRIPTION,
	    (void *)&ipadns_desc ) != 0 ||
	    slapi_pblock_set( pb, SLAPI_PLUGIN_CLOSE_FN,
	    (void *) ipadns_close ) != 0 ||
	    slapi_pblock_set( pb, SLAPI_PLUGIN_PRE_ADD_FN,
	    (void *) ipadns_add ) != 0 ) {
		LOG_FATAL( "Failed to set version and function\n" );
		return EFAIL;
	}

	value_zone = slapi_value_new_string( IPADNS_CLASS_ZONE );

	return EOK;
}
