# Access control examples

IPA provides a way to manage delegation of rights. Permissions allows to define
certain management actions, which can then be grouped in privileges. These
privileges can then be added to roles, which can be assigned to users and
groups.

- [Access control examples](#access-control-examples)
  - [Managing permissions](#managing-permissions)
  - [Managing privileges](#managing-privileges)
  - [Managing roles](#managing-roles)
  - [Assigning roles to users and groups](#assigning-roles-to-users-and-groups)

## Managing permissions

Add a permission for creating users.

```python
api.Command.permission_add("Create users", ipapermright='add', type='user')
```

Add a permission for managing group membership.

```python
api.Command.permission_add("Manage group membership", ipapermright='write', type='group', attrs="member")
```

## Managing privileges

Add a privilege for user creation process (creating user, adding it to groups,
manage user certificates).

```python
api.Command.permission_add("Create users", ipapermright='add', type='user')
api.Command.permission_add("Manage group membership", ipapermright='write', type='group', attrs="member")
api.Command.permission_add("Manage User certificates", ipapermright='write', type='user', attrs='usercertificate')

api.Command.privilege_add("User creation")
api.Command.privilege_add_permission("User creation", permission="Create users")
api.Command.privilege_add_permission("User creation", permission="Manage group membership")
api.Command.privilege_add_permission("User creation", permission="Manage User certificates")
```

## Managing roles

Add a role with the privilege created earlier.

```python
api.Command.role_add("usermanager", description="Users manager")
api.Command.role_add_privilege("usermanager", privilege="User creation")
```

## Assigning roles to users and groups

Assign the role `usermanager` to user `bob`.

```python
api.Command.role_add_member("usermanager", user="bob")
```

Users, groups, hosts and hostgroups may be members of a role. Assign the
`usermanager` role to `managers` group.

```python
api.Command.role_add_member("usermanager", group="managers")
```
