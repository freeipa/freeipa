# Host-based Access Control (HBAC) Examples

HBAC rules allow to define policies to control how hosts and services are
accessed based on the user, user's group or host that is attempting to access.

- [Host-based Access Control (HBAC) Examples](#host-based-access-control-hbac-examples)
  - [Creating an HBAC rule](#creating-an-hbac-rule)
  - [Managing members of a HBAC rule](#managing-members-of-a-hbac-rule)
  - [Managing targets of a HBAC rule](#managing-targets-of-a-hbac-rule)
  - [Testing a HBAC rule](#testing-a-hbac-rule)
  - [Enabling and disabling HBAC rules](#enabling-and-disabling-hbac-rules)


## Creating an HBAC rule

Create a base rule that will handle SSH service access.

```python
api.Command.hbacrule_add("sshd_rule")
```

## Managing members of a HBAC rule

Add user `john` to the previously created HBAC rule.

```python
api.Command.hbacrule_add_user("sshd_rule", user="john")
```

Additionally, you can set access based on groups:

```python
api.Command.hbacrule_add_user("sshd_rule", group="developers")
```

Remove user `john` from the HBAC rule.

```python
api.Command.hbacrule_remove_user("sshd_rule", user="john")
```

## Managing targets of a HBAC rule

After we have created the rule and set the members, targets must be registered
before being added to the rule.

Adding a new HBAC service.

```python
api.Command.hbacsvc_add("chronyd")
```

Services must be attached to rules. Attach the sshd service to the previously
created rule. This service is registered in IPA by default, so there's no need
to add it with `hbacsvc_add` before.

```python
api.Command.hbacrule_add_service("sshd_rule", hbacsvc="sshd")
```

Hosts can be added as targets as well. Allow the SSH service to be accessed only in
the hosts part of the `workstations` hostgroup.

```python
api.Command.hbacrule_add_host("sshd_rule", hostgroup="workstations")
```

## Testing a HBAC rule

Simulate the use of the rule we previously created, against the host
`workstation.ipa.test`, the service `sshd` coming from the user `john`.

```python
api.Command.hbactest(user="john", targethost="workstation.ipa.test", service="sshd", rules="sshd_rule")
```

## Enabling and disabling HBAC rules

Enable a HBAC rule.

```python
api.Command.hbacrule_enable("sshd_rule")
```

Disable a HBAC rule.

```python
api.Command.hbacrule_disable("sshd_rule")
```