from pencheff.core.session import create_session


def test_create_session_carries_rag_config():
    cfg = {"kind": "rag", "source_type": "managed_vdb", "provider": "qdrant", "url": "https://q"}
    s = create_session(target_url="rag://t", depth="quick", rag_config=cfg)
    assert s.rag_config == cfg


def test_create_session_rag_config_defaults_none():
    assert create_session(target_url="rag://t", depth="quick").rag_config is None
