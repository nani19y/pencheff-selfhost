"""Deterministic AWS IAM privilege-escalation paths.

Each path is a tuple of (path_name, required_actions, target). The caller
supplies the principal's effective IAM actions (typically obtained via
``aws iam simulate-principal-policy`` or ``aws iam get-account-authorization-details``)
and we report which paths are viable.

Source: Rhino Security Labs "AWS IAM Privilege Escalation Methods"
(https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/).
21 documented paths.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PrivescPath:
    name: str
    required_actions: tuple[str, ...]
    description: str


PATHS: tuple[PrivescPath, ...] = (
    PrivescPath("CreateNewPolicyVersion", ("iam:CreatePolicyVersion",),
               "Replace a default IAM policy with one granting *:* — full admin."),
    PrivescPath("SetExistingDefaultPolicyVersion", ("iam:SetDefaultPolicyVersion",),
               "Promote an existing wide-open policy version."),
    PrivescPath("CreateAccessKey", ("iam:CreateAccessKey",),
               "Create access keys for a higher-privilege user."),
    PrivescPath("CreateLoginProfile", ("iam:CreateLoginProfile",),
               "Set a console password for a user that doesn't have one."),
    PrivescPath("UpdateLoginProfile", ("iam:UpdateLoginProfile",),
               "Reset a higher-privilege user's password."),
    PrivescPath("AttachUserPolicy", ("iam:AttachUserPolicy",),
               "Attach AdministratorAccess to self."),
    PrivescPath("AttachGroupPolicy", ("iam:AttachGroupPolicy",),
               "Attach AdministratorAccess to a group containing self."),
    PrivescPath("AttachRolePolicy", ("iam:AttachRolePolicy", "sts:AssumeRole"),
               "Attach AdministratorAccess to an assumable role."),
    PrivescPath("PutUserPolicy", ("iam:PutUserPolicy",),
               "Inline-policy self with admin."),
    PrivescPath("PutGroupPolicy", ("iam:PutGroupPolicy",),
               "Inline admin policy on a group containing self."),
    PrivescPath("PutRolePolicy", ("iam:PutRolePolicy", "sts:AssumeRole"),
               "Inline admin policy on an assumable role."),
    PrivescPath("AddUserToGroup", ("iam:AddUserToGroup",),
               "Add self to a privileged group."),
    PrivescPath("UpdateAssumeRolePolicy", ("iam:UpdateAssumeRolePolicy", "sts:AssumeRole"),
               "Modify a role's trust policy to permit self."),
    PrivescPath("PassExistingRoleToCloudFormation",
               ("iam:PassRole", "cloudformation:CreateStack"),
               "Have CloudFormation execute as a privileged role."),
    PrivescPath("PassExistingRoleToNewLambdaThenInvoke",
               ("iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"),
               "Run code as a privileged role via Lambda."),
    PrivescPath("PassExistingRoleToNewLambdaThenTriggerWithEvent",
               ("iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping"),
               "Asynchronously trigger a Lambda you created."),
    PrivescPath("PassExistingRoleToNewGlueDevEndpoint",
               ("iam:PassRole", "glue:CreateDevEndpoint"),
               "Glue dev-endpoint runs as the passed role."),
    PrivescPath("UpdateExistingGlueDevEndpoint", ("glue:UpdateDevEndpoint",),
               "Inject SSH key into an existing dev endpoint."),
    PrivescPath("PassExistingRoleToNewDataPipeline",
               ("iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition"),
               "Run pipeline tasks as the passed role."),
    PrivescPath("EditExistingLambdaFunctionWithRole",
               ("lambda:UpdateFunctionCode",),
               "Replace code in a Lambda with a privileged execution role."),
    PrivescPath("PassExistingRoleToNewECSTask",
               ("iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:RunTask"),
               "Run an ECS task as the passed role."),
)


def viable_paths(allowed_actions: set[str]) -> list[PrivescPath]:
    """Return all paths whose required actions are a subset of ``allowed_actions``.

    Wildcards (``iam:*``, ``*``) on the allowed side are honoured.
    """
    expanded = _expand(allowed_actions)
    out: list[PrivescPath] = []
    for path in PATHS:
        if all(_match(action, expanded) for action in path.required_actions):
            out.append(path)
    return out


def _expand(actions: set[str]) -> set[str]:
    """Expand wildcards once so ``_match`` can operate on a flat set."""
    return {a.lower() for a in actions}


def _match(action: str, allowed: set[str]) -> bool:
    needle = action.lower()
    if needle in allowed:
        return True
    if "*" in allowed:
        return True
    service = needle.split(":", 1)[0]
    return f"{service}:*" in allowed
