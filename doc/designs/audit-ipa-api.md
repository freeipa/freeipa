# Audit IPA API operations

## Overview

IPA servers present an API to perform various actions that change the state of
the deployment. These actions include, among others, modifications of user and
group databases, add or remove information about hosts and Kerberos services,
HBAC and SUDO rules, and many other action types.

It is possible to observe IPA API actions through the web server logs. Each IPA
server logs their API calls in `/var/log/httpd/error_log` log file, as part of
standard Apache webserver logs. However, IPA command line utilities, when run
as `root` on IPA server, operate directly against LDAP database and results of
these operations only present in LDAP logs.

Thus, current IPA API implementation does not provide a unified method to
collect logs to audit API operations. The goal of this change is to make sure
IPA API backend logs externally-initiated operations, regardless how these
operations were invoked.

## Use Cases

- As an administrator, I'd like to collect details on who and when has called
  a particular IPA API on a particular IPA server. This information needs to be
  easily queried and it should be possible to correlate it across all servers
  in the IPA deployment.

- As an administrator, I'd like to make sure operations performed as part of
  IPA administrative utilities are audited as well.

## How to Use

`journalctl` tool can be used to query and filter through the IPA
API audit details. Each logged entry will be tagged with an 'IPA.API' label and
thus can easily be queried:

```
# journalctl -g IPA.API
...
```

`journalctl -g` allows to search through the content of the log entries'
messages. Each found entry has associated metadata which can be retrieved in a
different format, depending on other options to `journalctl` invocation.

## Design

Audit of IPA API operations should happen independently. Operations should be
logged whenever they happen.

IPA deployment heavily relies on a working systemd setup. systemd provides
logging facilities in the form of a system journal. systemd journal allows
centralized collection of the journals from individual systems, forward secure
sealing of the forwarded data, and rich metadata associated with the log
entries. Thus, it already provides an infrastructure to allow secure
centralized collection of actions performed through IPA API on IPA servers.

From administrator's point of view, when IPA API operations logged through the
systemd journal, standard journal commands can be used to retrieve and
manipulate logged entries.

## Implementation

All IPA API calls end up in `Command.__do_call()` internal method. This method
prepares execution of the command and runs it. After the command was performed,
the output is formatted. If operations require forwarding the request to a
remote IPA server, this will be performed automatically. As a result,
`Command.__do_call()` is executed by both IPA client and IPA server components.
It is possible to derive a context of operations through IPA API environment,
using `api.env.in_server` boolean.

systemd journal provides a simple Python binding, `systemd.journal`, that
allows structured logging of the messages against a `journald` daemon running
on the system. If such operation is performed in the server context, system
journal will be updated.

To aid with identification of these messages, an application name is replaced
with IPA.API and the actual name from api.env.script is made a part of the
logged message. The actual application script name is available as part of the
journal metadata anyway. Additionally, a `MESSAGE_ID` property is set to IPA
API-specific application UID, generated with Python's
`uuid.uuid3(uuid.NAMESPACE_DNS, 'IPA.API')` function call. This value is
available in IPA constants (`ipalib/constants.py`) as `SD_IPA_API_MESSAGE_ID`.
The value of the constant is `6d70f1b493df36478bc3499257cd3b17`.

If no Kerberos authentication was used but rather LDAPI autobind was in use,
the name of the authenticated principal will be replaced with `[autobind]`
text.

Messages sent with syslog `NOTICE` priority.

An example session looks like the following output:

```
# ipa -e in_server=True console
(Custom IPA interactive Python console)
    api: IPA API object
    pp: pretty printer
>>> api.Command.user_del('foobar')
{'result': {'failed': []}, 'value': ['foobar'], 'messages': [{'type':
'warning', 'name': 'VersionMissing', 'message': "API Version number was not
sent, forward compatibility not guaranteed. Assuming server's API version,
2.253", 'code': 13001, 'data': {'server_version': '2.253'}}], 'summary':
'Deleted user "foobar"'}
>>> ^D
now exiting InteractiveConsole...

# journalctl -g IPA.API
May 21 11:31:33 master1.ipa1.test /usr/bin/ipa[247422]: [IPA.API] [autobind]: user_del: SUCCESS [ldap2_140328582446688] {"uid": ["foobar"], "continue": false, "version": "2.253"}
```

All operations triggered through IPA API logged, including locally initiated,
as can be seen in the output above. For httpd end-point operations will be
logged as requested by the `/mod_wsgi` binary:

```
May 21 11:35:19 master1.ipa1.test /mod_wsgi[247035]: [IPA.API] admin@IPA1.TEST: ping: SUCCESS [ldap2_139910420944784] {"version": "2.253"}
```

The message includes following fields:
- executable name and PID (`/mod_wsgi` for HTTP end-point)
- `[IPA.API]` marker to allow searches with `journalctl -g IPA.API`
- authenticated Kerberos principal or `[autobind]` marker for LDAPI-based access as root
- name of the command executed
- result of execution: `SUCCESS` or an exception name
- LDAP backend instance identifier. The identifier will be the same for all operations performed under the same request. This allows to identify operations which were executed as a part of the same API request instance. For API operations that didn't result in LDAP access, there will be `[no_connection_id]` marker.
- finally, a list of arguments and options passed to the command is provided in JSON format

If an API call results in multiple operations triggered by the internal
implementation of the API command, only the external operation is recorded.
This means, for example, that a `user_del` API call will only be recorded as a
`user_del` command and not a sequence of a `user_find`, `otptoken_find`,
`subid_find`, and corresponding deletion commands which `user_del`
implementation is using.

IPA supplies a message catalog to systemd journal which allows to explain
content of the audited message and provide references to corresponding IPA API
documentation. This feature is triggered by `journalctl -x` systemd journal
command.

Full journal entry looks like the one below and can be obtained with `journalctl -o json-pretty` command:

```
{
        "PRIORITY" : "5",
        "_HOSTNAME" : "master1.ipa1.test",
        "__SEQNUM" : "608971",
        "_COMM" : "ipa",
        "_AUDIT_LOGINUID" : "0",
        "CODE_FUNC" : "__audit_to_journal",
        "_TRANSPORT" : "journal",
        "__SEQNUM_ID" : "aa96317d3ab84c16b5f131922414af11",
        "_CAP_EFFECTIVE" : "1ffffffffff",
        "_MACHINE_ID" : "5582ad1e90354a2e82710afb4cd4477f",
        "_RUNTIME_SCOPE" : "system",
        "MESSAGE" : "[IPA.API] [autobind]: user_del: SUCCESS [ldap2_140155643874720] {\"uid\": [\"zuser3\"], \"continue\": false, \"version\": \"2.253\"}",
        "CODE_LINE" : "495",
        "__REALTIME_TIMESTAMP" : "1716360895014405",
        "__MONOTONIC_TIMESTAMP" : "5952405665424",
        "_SYSTEMD_OWNER_UID" : "0",
        "_SYSTEMD_UNIT" : "session-30.scope",
        "_SYSTEMD_CGROUP" : "/user.slice/user-0.slice/session-30.scope",
        "CODE_FILE" : "/usr/lib/python3.12/site-packages/ipalib/frontend.py",
        "_SYSTEMD_SESSION" : "30",
        "_SYSTEMD_INVOCATION_ID" : "d166c864dba04b478d01658aa180d50d",
        "_PID" : "255232",
        "IPA_API_PARAMS" : "{\"uid\": [\"zuser3\"], \"continue\": false, \"version\": \"2.253\"}",
        "MESSAGE_ID" : "6d70f1b493df36478bc3499257cd3b17",
        "IPA_API_ACTOR" : "[autobind]",
        "_SYSTEMD_SLICE" : "user-0.slice",
        "IPA_API_COMMAND" : "user_del",
        "_BOOT_ID" : "cce41ab07f404ced8676400eb01bf220",
        "__CURSOR" : "s=aa96317d3ab84c16b5f131922414af11;i=94acb;b=cce41ab07f404ced8676400eb01bf220;m=569e7067690;t=6190569742605;x=265dd38af30f934c",
        "_AUDIT_SESSION" : "30",
        "SYSLOG_IDENTIFIER" : "/usr/bin/ipa",
        "_UID" : "0",
        "_SYSTEMD_USER_SLICE" : "-.slice",
        "_SOURCE_REALTIME_TIMESTAMP" : "1716360895014364",
        "_SELINUX_CONTEXT" : "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
        "_CMDLINE" : "/usr/bin/python3 -I /usr/bin/ipa -e in_server=True console",
        "_EXE" : "/usr/bin/python3.12",
        "_GID" : "0",
        "IPA_API_RESULT" : "SUCCESS"
}
```

An explanation for this audit message can be generated with `journalctl -x` command:

```
# journalctl -x -g ldap2_140155643874720
May 22 06:54:55 master1.ipa1.test /usr/bin/ipa[255232]: [🡕] [IPA.API] [autobind]: user_del: SUCCESS [ldap2_140155643874720] {"uid": ["zuser3"], "continue": false, "version": "2.253"}
░░ Subject: IPA API command was executed and result of its execution was audited
░░ Defined-by: FreeIPA
░░ Support: https://lists.fedorahosted.org/archives/list/freeipa-users@lists.fedorahosted.org/
░░ Documentation: man:ipa(1)
░░ Documentation: https://freeipa.readthedocs.io/en/latest/api/index.html
░░ Documentation: https://freeipa.readthedocs.io/en/latest/api/user_del.html

░░ FreeIPA provides an extensive API that allows to manage all aspects of IPA deployments.

░░ The following information about the API command executed is available:

░░ [IPA.API] [autobind]: user_del: SUCCESS [ldap2_140155643874720] {"uid": ["zuser3"], "continue": false, "version": "2.253"}

░░ The command was executed by '/usr/bin/ipa' utility. If the utility name
░░ is '/mod_wsgi`, then this API command came from a remote source through the IPA
░░ API end-point.

░░ The message includes following fields:

░░   - executable name and PID ('/mod_wsgi' for HTTP end-point; in this case it
░░     was '/usr/bin/ipa' command)

░░   - '[IPA.API]' marker to allow searches with 'journalctl -g IPA.API'

░░   - authenticated Kerberos principal or '[autobind]' marker for LDAPI-based
░░     access as root. In this case it was '[autobind]'

░░   - name of the command executed, in this case 'user_del'

░░   - result of execution: `SUCCESS` or an exception name. In this case it was
░░     'SUCCESS'

░░   - LDAP backend instance identifier. The identifier will be the same for all
░░     operations performed under the same request. This allows to identify operations
░░     which were executed as a part of the same API request instance. For API
░░     operations that didn't result in LDAP access, there will be
░░     '[no_connection_id]' marker.

░░   - finally, a list of arguments and options passed to the command is provided
░░     in JSON format.

░░ ---------
░░ The following list of arguments and options were passed to the command
░░ 'user_del' by the '[autobind]' actor:
░░ 
░░ {"uid": ["zuser3"], "continue": false, "version": "2.253"}
░░ ---------

░░ A detailed information about FreeIPA API can be found at upstream documentation API reference:
░░ https://freeipa.readthedocs.io/en/latest/api/index.html

░░ For details on the IPA API command 'user_del' see
░░ https://freeipa.readthedocs.io/en/latest/api/user_del.html
```

## Feature Management

There is no separate management of the IPA API audit logging. Logging is always
active on IPA server.

systemd journal has own mechanisms to control rates of messages coming from the
services. The details can be found in the man page `journald.conf(5)`.

## Upgrade

There is no impact on upgrade. Once new IPA API code installed, any new
application using it will start issuing log entries to the journald.

## Test plan

Test of IPA API audit logging can be done by observing systemd journal.
