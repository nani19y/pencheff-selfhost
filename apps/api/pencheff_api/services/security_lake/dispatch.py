from __future__ import annotations

from typing import Any

from .primitives import LakeContext
from .mappers.sast import map_sast
from .mappers.sca import map_sca
from .mappers.secrets import map_secret
from .mappers.iac import map_iac
from .mappers.dast import map_dast
from .mappers.runtime import map_runtime

_DISPATCH = {
    "sast": map_sast,
    "sca": map_sca,
    "secret": map_secret,
    "iac": map_iac,
    "dast": map_dast,
    "runtime": map_runtime,
}


def map_finding(source: str, finding: Any, ctx: LakeContext) -> dict:
    """Route a finding to its source-specific OCSF mapper."""
    mapper = _DISPATCH.get((source or "").lower())
    if mapper is None:
        raise ValueError(f"unknown finding source: {source!r}")
    return mapper(finding, ctx)
