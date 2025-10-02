import os
from brsgpt.utils.config_manager import ConfigManager


def test_env_driven_models_defaults(monkeypatch, tmp_path):
    monkeypatch.setenv("BRS_GPT_CONFIG_DIR", str(tmp_path))
    # Ensure no .env influences; set explicit env vars
    monkeypatch.setenv("OPENAI_MODEL", "gpt-5-mini")
    monkeypatch.setenv("OPENAI_SEARCH_MODEL", "gpt-4o-mini-search-preview")
    monkeypatch.setenv("OPENAI_FALLBACK_MODEL", "gpt-5-nano")

    cfg = ConfigManager()
    settings = cfg.get_settings()
    ai = settings.get('ai', {})
    assert ai.get('model') == "gpt-5-mini"
    assert ai.get('search_model') == "gpt-4o-mini-search-preview"
    assert ai.get('fallback_model') == "gpt-5-nano"
    assert ai.get('provider') == "openai"
