from __future__ import annotations

from functools import lru_cache

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from ocsf_json_schema import get_ocsf_schema, OcsfJsonSchemaEmbedded

# Single source of truth lives in primitives (re-exported here for callers).
from .primitives import OCSF_VERSION  # noqa: E402,F401

# OCSF class_uid -> class_name (the three Finding classes the lake emits).
_CLASS_NAME = {
    2002: "vulnerability_finding",
    2003: "compliance_finding",
    2004: "detection_finding",
}


class OCSFValidationError(ValueError):
    """An event failed OCSF 1.3.0 schema validation."""


@lru_cache(maxsize=1)
def _schema_source() -> OcsfJsonSchemaEmbedded:
    # Loads the packaged OCSF 1.3.0 schema; generates self-contained per-class
    # JSON Schema with referenced objects embedded (no remote $ref, offline).
    return OcsfJsonSchemaEmbedded(get_ocsf_schema(version=OCSF_VERSION))


@lru_cache(maxsize=None)
def _validator_for(class_uid: int) -> Draft202012Validator:
    name = _CLASS_NAME.get(class_uid)
    if name is None:
        raise OCSFValidationError(f"No OCSF schema for class_uid={class_uid!r}")
    schema = _schema_source().get_class_schema(class_name=name)
    return Draft202012Validator(schema)


def validate_ocsf(event: dict) -> None:
    """Validate an OCSF event against its class schema. Raises OCSFValidationError."""
    class_uid = event.get("class_uid")
    if not isinstance(class_uid, int):
        raise OCSFValidationError(f"event missing integer class_uid: {class_uid!r}")
    try:
        _validator_for(class_uid).validate(event)
    except ValidationError as exc:
        raise OCSFValidationError(
            f"OCSF validation failed at {list(exc.absolute_path)}: {exc.message}"
        ) from exc
