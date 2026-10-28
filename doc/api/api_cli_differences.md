# Differences between API and CLI usage

While the functionality between API and CLI is mostly the same, there are some
difference in their usage that should be taken into account.

- [Differences between API and CLI usage](#differences-between-api-and-cli-usage)
  - [Command naming](#command-naming)
  - [Parameter naming](#parameter-naming)
  - [Date format](#date-format)
  - [CLI-specific tools](#cli-specific-tools)

## Command naming

Commands in the CLI are constructed by specifying a topic and an action, with a
hyphen between them: `user-add`, `group-mod`, `host-del`. When accessing through
the API, the topic and the action are divided by an underscore instead:
`user_add`, `group_mod`, `host_del`. All available commands can be found below
`api.Command` after the API is initialized.

## Parameter naming

When managing plugins through the CLI, their parameters have different names
than the API, where names are the same as the LDAP attributes. For example,
`user-add` takes the `first` parameter in the CLI. However, this is named
`givenname` when calling `user_add` through the Python API.

## Date format

When passing dates through the CLI, multiple date string formats are available:

* %Y%m%d%H%M%SZ
* %Y-%m-%dT%H:%M:%SZ
* %Y-%m-%dT%H:%MZ
* %Y-%m-%dZ
* %Y-%m-%d %H:%M:%SZ
* %Y-%m-%d %H:%MZ

When using the API, apart from these formats, the Python built-in `datetime` class
can be used as well.

## CLI-specific tools

FreeIPA provides multiple tools that are mainly useful for CLI usage:

* `console`: starts an interactive Python console with an IPA API object already initialized.
* `help`: shows help about topics and commands, including examples for the CLI.
* `show-mappings`: shows the mapping between CLI parameter names and LDAP attributes.
