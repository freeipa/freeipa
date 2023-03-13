# API basic usage guide

- [API basic usage guide](#api-basic-usage-guide)
  - [Introduction](#introduction)
  - [Initializing API access](#initializing-api-access)
  - [Running commands](#running-commands)
  - [Passing arguments and options](#passing-arguments-and-options)
  - [Retrieving output](#retrieving-output)
  - [Displaying information about commands and parameters](#displaying-information-about-commands-and-parameters)
  - [API Contexts](#api-contexts)
  - [Batch operations](#batch-operations)

## Introduction

FreeIPA provides both command line and web based interfaces to interact with its
data and perform various operations. While these are enough to access the entire
set of features provided by FreeIPA, some users might take advantage of
additional ways to interact with it. For this purpose, FreeIPA provides an API
that can be accessed through Python, allowing users to interact with FreeIPA
programatically and develop custom tools to respond to specific needs not 
covered by the main interfaces. For users looking to perform stateless
operations or manage deployments with statically defined properties,
[ansible-freeipa](https://github.com/freeipa/ansible-freeipa) is recommended
instead.

While FreeIPA API provides a JSON-RPC interface, it is recommended to access the
API through Python instead, since it automates important parts such as the
metadata retrieval from the server, which allows to list all available commands.

## Initializing API access

We need to run our script in a host that is enrolled to our FreeIPA deployment,
either a client or a server. Before running commands, we need a Kerberos ticket:

```bash
$ echo $ADMIN_PASSWORD | kinit admin
```

After this, we can start writing our script. When the API is initialized, we
have to set the correct context for the access. Setting the context to server
will allow us to access the entire set of backend plugins. This is done with the
`in_server` option.

```python
from ipalib import api

api.bootstrap(context="custom", in_server=True)
api.finalize()
```

After calling `api.finalize()`, the initialization is completed and the required
plugins are instantiated. Then, we need to create a connection. This depends
whether we are accessing from a client or from the server itself, so we can
setup logic for it:

```python
if api.env.in_server:
    api.Backend.ldap2.connect()
else:
    api.Backend.rpcclient.connect()
```

This will connect to LDAP directly if we are running our script in server, or
use a RPC client if we are running it from a FreeIPA client.

After we have initialized the API and stablished a connection, we are ready to
issue commands.

## Running commands

Once the API is initialized, we can find all the available commands under
`api.Command`. You can call them by passing the required parameters.

```python
api.Command.user_show("admin")
```

Check the API Reference for the full list of commands.

## Passing arguments and options

Pass the required arguments as parameters to the command function in the same
order as you would on the CLI. To set options, pass them as named parameters
after the command arguments.

```python
api.Command.user_show("admin", no_members=True, all=True)
```

Alternatively, you can use the asterisk operator to pass the set of options as a
dictionary:

```python
args = ["admin"]
kw = {
  "no_members" : True,
  "all" : True
}
api.Command.user_show(*args, **kw)
```

The full list of available arguments and options for each command can be found
in the API Reference. Alternatively, it is possible to see the mapping of CLI
option to API attribute through `ipa show-mappings`.

## Retrieving output

Command output is returned as a Python dictionary. Example shown is the output
of:

```python
api.Command.user_add("test", givenname="a", sn="b")
```

```python
{
    "result": {
        "displayname": ["a b"],
        "objectclass": [
            "top",
            "person",
            "organizationalperson",
            "inetorgperson",
            "inetuser",
            "posixaccount",
            "krbprincipalaux",
            "krbticketpolicyaux",
            "ipaobject",
            "ipasshuser",
            "ipaSshGroupOfPubKeys",
            "mepOriginEntry",
            "ipantuserattrs",
        ],
        "cn": ["a b"],
        "gidnumber": ["1445000004"],
        "mail": ["test@ipa.test"],
        "krbprincipalname": [ipapython.kerberos.Principal("test@IPA.TEST")],
        "loginshell": ["/bin/sh"],
        "initials": ["ab"],
        "uid": ["test"],
        "uidnumber": ["1445000004"],
        "sn": ["b"],
        "krbcanonicalname": [ipapython.kerberos.Principal("test@IPA.TEST")],
        "homedirectory": ["/home/test"],
        "givenname": ["a"],
        "gecos": ["a b"],
        "ipauniqueid": ["9f9c1df8-5073-11ed-9a56-fa163ea98bb3"],
        "mepmanagedentry": [
            ipapython.dn.DN("cn=test,cn=groups,cn=accounts,dc=ipa,dc=test")
        ],
        "has_password": False,
        "has_keytab": False,
        "memberof_group": ["ipausers"],
        "dn": ipapython.dn.DN("uid=test,cn=users,cn=accounts,dc=ipa,dc=test"),
    },
    "value": "test",
    "messages": [
        {
            "type": "warning",
            "name": "VersionMissing",
            "message": "API Version number was not sent, forward compatibility not guaranteed. Assuming server's API version, 2.248",
            "code": 13001,
            "data": {"server_version": "2.248"},
        }
    ],
    "summary": 'Added user "test"',
}
```

The output contains four sections:

* `result`: The actual result of the command. This contains details about the
  operation, including different options and arguments passed to the command.
* `value`: The argument the command is applied to. In this example, we created an
  user called `test`.
* `messages`: Different diagnostic information provided by FreeIPA after the operation.
* `summary`: A summary of the operation.

## Displaying information about commands and parameters

All available information about commands and their parameters is provided in the
API Reference. Additionally, the API provides tools to display this information. 
It can be retrieved using the `command_show` and `param_show` commands.

```python
api.Command.command_show("user_add")
```

```python
{
    "result": {
        "name": "user_add",
        "version": "1",
        "full_name": "user_add/1",
        "doc": "Add a new user.",
        "topic_topic": "user/1",
        "obj_class": "user/1",
        "attr_name": "add",
    },
    "value": "user_add",
    "messages": [
        {
            "type": "warning",
            "name": "VersionMissing",
            "message": "API Version number was not sent, forward compatibility not guaranteed. Assuming server's API version, 2.251",
            "code": 13001,
            "data": {"server_version": "2.251"},
        }
    ],
    "summary": None,
}
```

For listing all available parameters for a certain command, the `param_find`
command can be used. We can additionally show information of a certain
parameter from a command using `param_show`.


```python
api.Command.param_show("user_add", name="givenname")
```

```python
{
    "result": {
        "name": "givenname",
        "type": "str",
        "positional": False,
        "cli_name": "first",
        "label": "First name",
    },
    "value": "givenname",
    "messages": [
        {
            "type": "warning",
            "name": "VersionMissing",
            "message": "API Version number was not sent, forward compatibility not guaranteed. Assuming server's API version, 2.251",
            "code": 13001,
            "data": {"server_version": "2.251"},
        }
    ],
    "summary": None,
}
```

## API Contexts

As explained earlier, a context can be specified before initializing the API.
The purpose of the context is to define the set of methods that can be
performed. FreeIPA defines by default four major contexts:

* `server`: plugins validate any arguments and options passed and then execute
  the requested action.
* `client`: plugins validate any arguments and options passed and then forward
  the request to the FreeIPA server to execute.
* `installer`: plugins specific to the installation process are loaded.
* `updates`: plugins specific the update process are loaded.

## Batch operations

Batch operations are useful for executing multiple commands at once, as it
allows to make multiple calls while just starting one remote procedure call.
This might be useful, for example, in scenarios when we want to bulk create
entries. Following is the example of bulk creating IPA users using batch
operations:

```python
batch_args = []
for i in range(100):
    user_id = "user%i" % i
    args = [user_id]
    kw = {
        'givenname' : user_id,
        'sn' : user_id
    }
    batch_args.append({
        'method' : 'user_add',
        'params' : [args, kw]
    })
ret = api.Command.batch(*batch_args)
```