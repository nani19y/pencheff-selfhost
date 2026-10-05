from pencheff_api.config import Settings


def test_ai_unavailable_without_key():
    assert Settings(llm_api_key="").ai_available is False


def test_ai_available_with_key():
    assert Settings(llm_api_key="sk-test").ai_available is True
