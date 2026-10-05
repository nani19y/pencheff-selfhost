"""Deterministic GCP IAM privilege-escalation paths.

Source: Rhino Security Labs / SpecterOps GCP IAM research, Google's IAM
documentation. Subset of the most-cited paths.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PrivescPath:
    name: str
    required_permissions: tuple[str, ...]
    description: str


PATHS: tuple[PrivescPath, ...] = (
    PrivescPath("iam.serviceAccounts.actAs",
               ("iam.serviceAccounts.actAs",),
               "Impersonate any service account to inherit its permissions."),
    PrivescPath("iam.serviceAccountKeys.create",
               ("iam.serviceAccountKeys.create",),
               "Generate a JSON key for a service account; act as the SA offline."),
    PrivescPath("setIamPolicy_project",
               ("resourcemanager.projects.setIamPolicy",),
               "Grant self any role at project level."),
    PrivescPath("setIamPolicy_organization",
               ("resourcemanager.organizations.setIamPolicy",),
               "Grant self any role at org level."),
    PrivescPath("compute.instances.setMetadata",
               ("compute.instances.setMetadata",),
               "Set startup-script on a VM to run code as the VM's SA."),
    PrivescPath("cloudfunctions.functions.update",
               ("cloudfunctions.functions.update",),
               "Update a Cloud Function to run code as its SA."),
    PrivescPath("cloudbuild.builds.create",
               ("cloudbuild.builds.create",),
               "Trigger Cloud Build, which runs as the default Cloud Build SA."),
    PrivescPath("dataproc.clusters.create",
               ("dataproc.clusters.create",),
               "Spin up a Dataproc cluster running as a privileged SA."),
    PrivescPath("composer.environments.update",
               ("composer.environments.update",),
               "Run code via Cloud Composer / Airflow as the env's SA."),
    PrivescPath("deploymentmanager.deployments.create",
               ("deploymentmanager.deployments.create",),
               "Deployment Manager runs templates as a privileged SA."),
    PrivescPath("iam.roles.update",
               ("iam.roles.update",),
               "Add additional permissions to a custom role you hold."),
    PrivescPath("storage.objects.create_workflow",
               ("storage.objects.create",),
               "Inject malicious objects consumed by privileged workflows."),
)


def viable_paths(allowed_permissions: set[str]) -> list[PrivescPath]:
    needles = {p.lower() for p in allowed_permissions}
    out: list[PrivescPath] = []
    for path in PATHS:
        if all(p.lower() in needles for p in path.required_permissions):
            out.append(path)
    return out
