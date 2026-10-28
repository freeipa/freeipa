# Extdom plugin protocol

SSSD on ipa client uses extdom plugin to translate SID to names and POSIX IDs. It can
also return secondary groups for any user.

## EXTDOM V0 (2.16.840.1.113730.3.8.10.4)

### V0 request

    /*
     * ExtdomRequestValue ::= SEQUENCE {
     *    inputType ENUMERATED {
     *        sid (1),
     *        name (2),
     *        posix uid (3),
     *        posix gid (4)
     *    },
     *    requestType ENUMERATED {
     *        simple (1),
     *        full (2)
     *    },
     *    data InputData
     * }
     *
     * InputData ::= CHOICE {
     *    sid OCTET STRING,
     *    name NameDomainData
     *    uid PosixUid,
     *    gid PosixGid
     * }
     *
     * NameDomainData ::= SEQUENCE {
     *    domain_name OCTET STRING,
     *    object_name OCTET STRING
     * }
     *
     * PosixUid ::= SEQUENCE {
     *    domain_name OCTET STRING,
     *    uid INTEGER
     * }
     *
     * PosixGid ::= SEQUENCE {
     *    domain_name OCTET STRING,
     *    gid INTEGER
     * }
     */

### V0 reply

    /*
     * ExtdomResponseValue ::= SEQUENCE {
     *    responseType ENUMERATED {
     *        sid (1),
     *        name (2),
     *        posix_user (3),
     *        posix_group (4)
     *    },
     *    data OutputData
     * }
     *
     * OutputData ::= CHOICE {
     *    sid OCTET STRING,
     *    name NameDomainData,
     *    user PosixUser,
     *    group PosixGroup
     * }
     *
     * NameDomainData ::= SEQUENCE {
     *    domain_name OCTET STRING,
     *    object_name OCTET STRING
     * }
     *
     * PosixUser ::= SEQUENCE {
     *    domain_name OCTET STRING,
     *    user_name OCTET STRING,
     *    uid INTEGER
     *    gid INTEGER
     * }
     *
     * PosixGroup ::= SEQUENCE {
     *    domain_name OCTET STRING,
     *    group_name OCTET STRING,
     *    gid INTEGER
     * }
     */

## EXTDOM V1 (2.16.840.1.113730.3.8.10.4.1)

In V1 version the requestType is extended of `full_with_groups`.
The response introduces new type `posix_user_grouplist` containing
the list of groups

### V1 request

    /*
     * ExtdomRequestValue ::= SEQUENCE {
     *    inputType ENUMERATED {
     *        sid (1),
     *        name (2),
     *        posix uid (3),
     *        posix gid (4),
     *    },
     *    requestType ENUMERATED {
     *        simple (1),
     *        full (2),
     *        full_with_groups (3)
     *    },
     *    data InputData
     * }
     *
     * InputData ::= CHOICE {
     *    sid OCTET STRING,
     *    name NameDomainData
     *    uid PosixUid,
     *    gid PosixGid
     * }
     *
     * NameDomainData ::= SEQUENCE {
     *    domain_name OCTET STRING,
     *    object_name OCTET STRING
     * }
     *
     * PosixUid ::= SEQUENCE {
     *    domain_name OCTET STRING,
     *    uid INTEGER
     * }
     *
     * PosixGid ::= SEQUENCE {
     *    domain_name OCTET STRING,
     *    gid INTEGER
     * }
     */

### V1 reply

    /*
     * ExtdomResponseValue ::= SEQUENCE {
     *    responseType ENUMERATED {
     *        sid (1),
     *        name (2),
     *        posix_user (3),
     *        posix_group (4),
     *        posix_user_grouplist (5)
     *    },
     *    data OutputData
     * }
     *
     * OutputData ::= CHOICE {
     *    sid OCTET STRING,
     *    name NameDomainData,
     *    user PosixUser,
     *    group PosixGroup,
     *    user_grouplist PosixUserGrouplist
     * }
     *
     * NameDomainData ::= SEQUENCE {
     *    domain_name OCTET STRING,
     *    object_name OCTET STRING
     * }
     *
     * PosixUser ::= SEQUENCE {
     *    domain_name OCTET STRING,
     *    user_name OCTET STRING,
     *    uid INTEGER
     *    gid INTEGER
     * }
     *
     * GroupNameList ::= SEQUENCE OF groupname OCTET STRING
     *
     * PosixGroup ::= SEQUENCE {
     *    domain_name OCTET STRING,
     *    group_name OCTET STRING,
     *    gid INTEGER
     * }
     *
     * PosixUserGrouplist ::= SEQUENCE {
     *    domain_name OCTET STRING,
     *    user_name OCTET STRING,
     *    uid INTEGER
     *    gid INTEGER
     *    gecos OCTET STRING,
     *    home_directory OCTET STRING,
     *    shell OCTET STRING,
     *    grouplist GroupNameList
     * }
     *
     * GroupNameList ::= SEQUENCE OF groupname OCTET STRING
     *
     */

## EXTDOM V2 (2.16.840.1.113730.3.8.10.4.2)

The `name` request tries to translate name to ID. It first tries translate it
as if it is a user and when it fails, it tries to resolve is as group.

To make it more efficient when SSSD knows the type of requested object, two new
inputTypes are defined - username and groupname.

The response is the same as in V1

### V2 request

    /*
     * ExtdomRequestValue ::= SEQUENCE {
     *    inputType ENUMERATED {
     *        sid (1),
     *        name (2),
     *        posix uid (3),
     *        posix gid (4),
     *        username (5),
     *        groupname (6)
     *    },
     *    requestType ENUMERATED {
     *        simple (1),
     *        full (2),
     *        full_with_groups (3)
     *    },
     *    data InputData
     * }
     *
     * InputData ::= CHOICE {
     *    sid OCTET STRING,
     *    name NameDomainData
     *    uid PosixUid,
     *    gid PosixGid
     * }
     *
     * NameDomainData ::= SEQUENCE {
     *    domain_name OCTET STRING,
     *    object_name OCTET STRING
     * }
     *
     * PosixUid ::= SEQUENCE {
     *    domain_name OCTET STRING,
     *    uid INTEGER
     * }
     *
     * PosixGid ::= SEQUENCE {
     *    domain_name OCTET STRING,
     *    gid INTEGER
     * }
     */
