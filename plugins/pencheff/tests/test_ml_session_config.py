from pencheff.core.session import create_session


def test_ml_config_round_trips():
    cfg = {"kind": "ml_model", "source_type": "huggingface", "hf_repo": "owner/model"}
    s = create_session(target_url="hf://owner/model", depth="quick", ml_config=cfg)
    assert s.ml_config == cfg


def test_ml_config_defaults_none():
    s = create_session(target_url="x", depth="quick")
    assert s.ml_config is None
