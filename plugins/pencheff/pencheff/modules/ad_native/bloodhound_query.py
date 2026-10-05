"""Canonical BloodHound Cypher queries.

These are the 25 most useful BloodHound queries documented at
https://bloodhound.readthedocs.io. We do NOT execute them — we ship them so
that the user (or a downstream Neo4j connection) can run them directly.

Each query is a deterministic constant. There is no AI-generated Cypher.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CypherQuery:
    name: str
    description: str
    query: str


QUERIES: list[CypherQuery] = [
    CypherQuery(
        name="shortest_path_to_da",
        description="Shortest attack path from any user to Domain Admins",
        query=(
            "MATCH p=shortestPath((n:User)-[*1..]->(g:Group {name:'DOMAIN ADMINS@'+$domain})) "
            "RETURN p"
        ),
    ),
    CypherQuery(
        name="kerberoastable_users",
        description="Users with SPNs (kerberoastable)",
        query="MATCH (u:User {hasspn:true}) RETURN u.name, u.serviceprincipalnames",
    ),
    CypherQuery(
        name="asrep_roastable_users",
        description="Users with Kerberos pre-auth disabled",
        query="MATCH (u:User {dontreqpreauth:true}) RETURN u.name",
    ),
    CypherQuery(
        name="unconstrained_delegation",
        description="Computers with unconstrained delegation",
        query="MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name",
    ),
    CypherQuery(
        name="constrained_delegation",
        description="Principals trusted for constrained delegation",
        query=(
            "MATCH (n)-[:AllowedToDelegate]->(t) "
            "RETURN n.name AS principal, t.name AS target"
        ),
    ),
    CypherQuery(
        name="dcsync_rights",
        description="Principals with DCSync rights",
        query=(
            "MATCH p=(n)-[:GetChanges|GetChangesAll*1..]->(d:Domain) "
            "RETURN n.name, d.name"
        ),
    ),
    CypherQuery(
        name="local_admin_rights",
        description="Principals with local admin on at least one host",
        query=(
            "MATCH p=(n)-[:AdminTo|MemberOf*1..]->(c:Computer) "
            "RETURN n.name AS principal, c.name AS host"
        ),
    ),
    CypherQuery(
        name="rdp_rights",
        description="Principals with RDP access",
        query="MATCH p=(n)-[:CanRDP*1..]->(c:Computer) RETURN n.name, c.name",
    ),
    CypherQuery(
        name="psremote_rights",
        description="Principals with PowerShell Remoting access",
        query="MATCH p=(n)-[:CanPSRemote*1..]->(c:Computer) RETURN n.name, c.name",
    ),
    CypherQuery(
        name="dpapi_owners",
        description="Computers where users have logon and credentials may be cached",
        query=(
            "MATCH p=(u:User)-[:HasSession]->(c:Computer) "
            "RETURN u.name AS user, c.name AS host"
        ),
    ),
    CypherQuery(
        name="gpo_with_password",
        description="GPOs containing cleartext credentials (gpp-decrypt candidates)",
        query="MATCH (g:GPO) WHERE g.gpcfilesyspath IS NOT NULL RETURN g.name",
    ),
    CypherQuery(
        name="ous_under_attack_path",
        description="OUs containing computers reachable from a low-priv user",
        query=(
            "MATCH p=(u:User)-[*1..]->(c:Computer)<-[:Contains]-(o:OU) "
            "RETURN o.name, count(p) ORDER BY count(p) DESC"
        ),
    ),
    CypherQuery(
        name="da_session",
        description="Domain Admin sessions (lateral targets)",
        query=(
            "MATCH (u:User)-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@'+$domain}) "
            "MATCH (u)-[:HasSession]->(c:Computer) RETURN u.name, c.name"
        ),
    ),
    CypherQuery(
        name="trust_relationships",
        description="Domain trust relationships",
        query="MATCH (a:Domain)-[r:TrustedBy]->(b:Domain) RETURN a.name, b.name, r",
    ),
    CypherQuery(
        name="outbound_acl_misconfigs",
        description="ACL relationships that allow privilege escalation",
        query=(
            "MATCH p=(n)-[:GenericAll|WriteOwner|WriteDacl|GenericWrite|AddMember*1..]"
            "->(t) RETURN n.name, type(last(relationships(p))) AS edge, t.name"
        ),
    ),
    CypherQuery(
        name="adcs_esc1_templates",
        description="Certificate templates with ENROLLEE_SUPPLIES_SUBJECT (ESC1)",
        query="MATCH (t:GPO) WHERE t.enrolleesuppliessubject=true RETURN t.name",
    ),
    CypherQuery(
        name="laps_readable",
        description="Users who can read LAPS passwords",
        query="MATCH p=(u:User)-[:ReadLAPSPassword*1..]->(c:Computer) RETURN u.name, c.name",
    ),
    CypherQuery(
        name="empty_password_users",
        description="Users with PASSWD_NOTREQD set",
        query="MATCH (u:User {pwdnotrequired:true}) RETURN u.name",
    ),
    CypherQuery(
        name="never_expire_users",
        description="Users with passwords that never expire",
        query="MATCH (u:User {pwdneverexpires:true}) RETURN u.name",
    ),
    CypherQuery(
        name="admincount_users",
        description="Users marked AdminCount=1 (sensitive)",
        query="MATCH (u:User {admincount:true}) RETURN u.name",
    ),
    CypherQuery(
        name="kerberoast_to_da",
        description="Kerberoastable users with a path to Domain Admins",
        query=(
            "MATCH p=shortestPath((u:User {hasspn:true})-[*1..]->"
            "(g:Group {name:'DOMAIN ADMINS@'+$domain})) RETURN u.name, length(p)"
        ),
    ),
    CypherQuery(
        name="resource_based_delegation",
        description="Computers with msDS-AllowedToActOnBehalfOfOtherIdentity set",
        query="MATCH p=(n)-[:AllowedToAct]->(c:Computer) RETURN n.name, c.name",
    ),
    CypherQuery(
        name="dc_owners",
        description="Domain Controllers ownership and ACL state",
        query="MATCH (c:Computer {domain_controller:true}) RETURN c.name, c.objectid",
    ),
    CypherQuery(
        name="exchange_acls",
        description="Exchange-trusted-subsystem dangerous ACLs",
        query=(
            "MATCH p=(g:Group)-[:GenericAll|WriteDacl|WriteOwner*1..]->(d:Domain) "
            "WHERE g.name STARTS WITH 'EXCHANGE' RETURN g.name, d.name"
        ),
    ),
    CypherQuery(
        name="all_paths_to_da",
        description="All paths from a marked user to Domain Admins (limit 25)",
        query=(
            "MATCH p=(u:User {owned:true})-[*1..]->(g:Group "
            "{name:'DOMAIN ADMINS@'+$domain}) RETURN p LIMIT 25"
        ),
    ),
]


def by_name(name: str) -> CypherQuery | None:
    for q in QUERIES:
        if q.name == name:
            return q
    return None
