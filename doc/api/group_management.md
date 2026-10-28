# Group management examples

This guide provides various examples on how to perform common tasks related to
group management in a IPA environment making use of the provided API.

- [Group management examples](#group-management-examples)
  - [Creating a group](#creating-a-group)
  - [Adding members to a group](#adding-members-to-a-group)
  - [Adding group managers](#adding-group-managers)
  - [Finding a group](#finding-a-group)
  - [Showing group information](#showing-group-information)
  - [Modifying a group](#modifying-a-group)
  - [Removing members from a group](#removing-members-from-a-group)
  - [Removing group managers](#removing-group-managers)
  - [Removing a group](#removing-a-group)


## Creating a group

Create a group for developers, with an specific Group ID number.

```python
api.Command.group_add("developers", gidnumber=500, description="Developers")
```

## Adding members to a group

Add the admin user to the `developers` group.

```python
api.Command.group_add_member("developers", user="admin")
```

Apart from users, groups can also have services and groups as members:

```python
api.Command.group_add_member("developers", service="HTTP/server.ipa.test")
```

```python
api.Command.group_add_member("developers", group="admins")
```

## Adding group managers

Add `bob` as the group manager for `developers` group.

```python
api.Command.group_add_member_manager("developers", user="bob")
```

## Finding a group

Find all groups managed by `bob`.

```python
api.Command.group_find(membermanager_user="bob")
```

## Showing group information

Show information about the `developers` group, excluding the members list.

```python
api.Command.group_show("developers", no_members=True)
```

## Modifying a group

Convert a non-POSIX group to POSIX:

```python
api.Command.group_mod("testgroup", posix=True)
```

## Removing members from a group

Remove the admin user to the `developers` group.

```python
api.Command.group_remove_member("developers", user="admin")
```

## Removing group managers

Remove `bob` as the group manager from `developers` group.

```python
api.Command.group_remove_member_manager("developers", user="bob")
```

## Removing a group

Remove the `developers` group.

```python
api.Command.group_del("developers")
```