from pencheff.core.session import create_session


def test_create_session_carries_mcp_config():
    cfg = {"kind": "mcp", "source_type": "mcp_stdio", "command": ["x"]}
    s = create_session(target_url="mcp://t", depth="quick", mcp_config=cfg)
    assert s.mcp_config == cfg


def test_create_session_mcp_config_defaults_none():
    s = create_session(target_url="mcp://t", depth="quick")
    assert s.mcp_config is None
