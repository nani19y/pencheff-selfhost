from pencheff_api.auth.permissions import permissions_for_claims


def test_unknown_user_has_no_permissions():
    assert permissions_for_claims({"sub": "user-1"}) == set()


def test_readonly_realm_role_is_limited_to_read_permissions():
    permissions = permissions_for_claims({"realm_access": {"roles": ["pencheff-readonly"]}})
    assert "targets:read" in permissions
    assert "scans:read" in permissions
    assert "targets:write" not in permissions
    assert "scans:write" not in permissions
    assert "org:manage_members" not in permissions
    assert "org:manage_permissions" not in permissions


def test_admin_role_receives_catalog_permissions():
    permissions = permissions_for_claims({"realm_access": {"roles": ["pencheff-admin"]}})
    assert "org:manage_members" in permissions
    assert "org:manage_permissions" in permissions
    assert "remediation:execute" in permissions


def test_group_alias_maps_to_readonly_role():
    permissions = permissions_for_claims({"groups": ["/pencheff/pencheff-readonly"]})
    assert "targets:read" in permissions
    assert "targets:write" not in permissions


def test_unrecognized_roles_are_ignored():
    permissions = permissions_for_claims({
        "realm_access": {"roles": ["offline_access", "uma_authorization", "random-role"]}
    })
    assert permissions == set()


def test_client_roles_are_resolved():
    permissions = permissions_for_claims({
        "resource_access": {"pencheff-web": {"roles": ["pencheff-security"]}}
    })
    assert "scans:write" in permissions
    assert "org:manage_members" not in permissions
