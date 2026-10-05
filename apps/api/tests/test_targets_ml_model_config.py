from __future__ import annotations
import pytest
from pydantic import ValidationError, TypeAdapter
from pencheff_api.schemas.targets import KindConfig
_adapter = TypeAdapter(KindConfig)
def _parse(d): return _adapter.validate_python(d)


def test_file_url_requires_url():
    ok = _parse({"kind": "ml_model", "source_type": "file_url", "url": "https://h/model.pkl"})
    assert ok.source_type == "file_url"
    with pytest.raises(ValidationError):
        _parse({"kind": "ml_model", "source_type": "file_url"})


def test_huggingface_requires_repo():
    ok = _parse({"kind": "ml_model", "source_type": "huggingface", "hf_repo": "owner/model"})
    assert ok.hf_repo == "owner/model"
    with pytest.raises(ValidationError):
        _parse({"kind": "ml_model", "source_type": "huggingface"})


def test_local_path_requires_path():
    ok = _parse({"kind": "ml_model", "source_type": "local_path", "local_path": "/models/m.pt"})
    assert ok.local_path == "/models/m.pt"
    with pytest.raises(ValidationError):
        _parse({"kind": "ml_model", "source_type": "local_path"})


def test_format_hint_default_and_extra_forbidden():
    cfg = _parse({"kind": "ml_model", "source_type": "huggingface", "hf_repo": "o/m"})
    assert cfg.format_hint == "auto"
    with pytest.raises(ValidationError):
        _parse({"kind": "ml_model", "source_type": "huggingface", "hf_repo": "o/m", "bogus": 1})
