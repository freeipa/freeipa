# Sudo rules management examples

Sudo rules provide the system administrator a way to delegate privileges to
certain users in order to perform commands either as root or as another user.

- [Sudo rules management examples](#sudo-rules-management-examples)
  - [Creating a sudo rule](#creating-a-sudo-rule)
  - [Managing sudo commands](#managing-sudo-commands)
  - [Adding users and hosts to sudo rules](#adding-users-and-hosts-to-sudo-rules)
  - [Setting "run as" for sudo rules](#setting-run-as-for-sudo-rules)
  - [Managing sudo options](#managing-sudo-options)
  - [Enabling and disabling sudo rule](#enabling-and-disabling-sudo-rule)


## Creating a sudo rule

Create a sudo rule that will hold time change commands.

```python
api.Command.sudorule_add("timechange")
```

## Managing sudo commands

Sudo rules must be filled with sudo commands. Create one for `date`.

```python
api.Command.sudocmd_add("/usr/bin/date")
```

Then, attach the sudo command to the sudo rule.

```python
api.Command.sudorule_add_allow_command("timechange", sudocmd="/usr/bin/date")
```

Alternatively, groups of sudo commands can be created and attached to the rule
in the same manner.

```python
api.Command.sudocmd_add("/usr/bin/date")
api.Command.sudocmd_add("/usr/bin/timedatectl")
api.Command.sudocmd_add("/usr/sbin/hwclock")
api.Command.sudocmdgroup_add("timecmds")
api.Command.sudocmdgroup_add_member("timecmds", sudocmd="/usr/bin/date")
api.Command.sudocmdgroup_add_member("timecmds", sudocmd="/usr/bin/timedatectl")
api.Command.sudocmdgroup_add_member("timecmds", sudocmd="/usr/sbin/hwclock")
api.Command.sudorule_add_allow_command("timechange", sudocmdgroup="timecmds")
```

Commands can be denied as well. Deny the `rm` command to be run as sudo.

```python
api.Command.sudocmd_add("/usr/bin/rm")
api.Command.sudorule_add_deny_command("timechange", sudocmd="/usr/bin/rm")
```

## Adding users and hosts to sudo rules

Add the user `bob` to the previously created rule.

```python
api.Command.sudorule_add_user("timechange", user="bob")
```

Restrict the rule to only be available for the `client.ipa.test` host.

```python
api.Command.sudorule_add_host("timechange", host="client.ipa.test")
```

## Setting "run as" for sudo rules

While sudo rules are run as root by default, a different "run as" can be
configured, both for user and group rights.

```python
api.Command.sudorule_add_runasuser("timechange", user="alice")
```

```python
api.Command.sudorule_add_runasgroup("timechange", group="sysadmins")
```

## Managing sudo options

Set a sudo option for the `timechange` sudo rule.

```python
api.Command.sudorule_add_option("timechange", ipasudoopt="logfile='/var/log/timechange_log'")
```

## Enabling and disabling sudo rule

Enable a sudo sule.

```python
api.Command.sudorule_enable("timechange")
```

Disable a sudo sule.

```python
api.Command.sudorule_disable("timechange")
```