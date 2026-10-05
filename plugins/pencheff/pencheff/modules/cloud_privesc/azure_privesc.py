"""Deterministic Azure RBAC / Entra ID privilege-escalation paths.

Source: Andy Robbins / SpecterOps Azure IAM research; Microsoft documentation.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PrivescPath:
    name: str
    required_roles: tuple[str, ...]
    description: str


PATHS: tuple[PrivescPath, ...] = (
    PrivescPath("UserAccessAdministrator",
               ("User Access Administrator",),
               "Grant self any role at the assigned scope."),
    PrivescPath("Owner_at_management_group",
               ("Owner",),
               "Owner at management-group scope cascades down to all subscriptions."),
    PrivescPath("ApplicationAdministrator",
               ("Application Administrator",),
               "Add credentials to any service principal — impersonate it."),
    PrivescPath("CloudApplicationAdministrator",
               ("Cloud Application Administrator",),
               "Same as Application Admin minus on-prem app proxy."),
    PrivescPath("PrivilegedRoleAdministrator",
               ("Privileged Role Administrator",),
               "Assign Global Admin to any user."),
    PrivescPath("PrivilegedAuthenticationAdministrator",
               ("Privileged Authentication Administrator",),
               "Reset MFA for any admin and take over the account."),
    PrivescPath("ContributorOnAKS",
               ("Contributor",),
               "Contributor on an AKS cluster → exec into pods → steal node identity."),
    PrivescPath("ContributorWithMSI",
               ("Contributor",),
               "Attach a User-Assigned Managed Identity with high privileges to a VM you control."),
    PrivescPath("VirtualMachineContributor",
               ("Virtual Machine Contributor",),
               "Run scripts on a VM that has a system-assigned MI."),
    PrivescPath("StorageBlobDataContributor_with_function",
               ("Storage Blob Data Contributor",),
               "Modify code consumed by Azure Functions running as a privileged identity."),
)


def viable_paths(assigned_roles: set[str]) -> list[PrivescPath]:
    needles = {r.lower() for r in assigned_roles}
    out: list[PrivescPath] = []
    for path in PATHS:
        if any(r.lower() in needles for r in path.required_roles):
            out.append(path)
    return out
