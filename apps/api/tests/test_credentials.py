from pencheff_api.services.credentials import decrypt_credentials, encrypt_credentials


def test_roundtrip():
    blob = encrypt_credentials({"username": "admin", "password": "hunter2"})
    assert blob is not None
    out = decrypt_credentials(blob)
    assert out == {"username": "admin", "password": "hunter2"}


def test_none_passthrough():
    assert encrypt_credentials(None) is None
    assert decrypt_credentials(None) is None


def test_filters_empty_values():
    blob = encrypt_credentials({"username": "admin", "token": ""})
    out = decrypt_credentials(blob)
    assert "token" not in out
    assert out["username"] == "admin"
