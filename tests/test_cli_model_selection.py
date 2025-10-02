import builtins
from types import SimpleNamespace

from brsgpt.cli import main
from brsgpt.cli.model_catalog import MODEL_CATALOG
from brsgpt.utils.config_manager import ConfigManager


def test_select_model_non_interactive_uses_recommended(monkeypatch, tmp_path):
    monkeypatch.setenv("BRS_GPT_CONFIG_DIR", str(tmp_path))

    cfg = ConfigManager()

    # Silence console output during the test.
    monkeypatch.setattr(main, "console", SimpleNamespace(print=lambda *args, **kwargs: None))

    # Simulate non-interactive environment and ensure input() would fail if called.
    monkeypatch.setattr(main.sys, "stdin", SimpleNamespace(isatty=lambda: False))
    monkeypatch.setattr(builtins, "input", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("input should not be called")))

    selected_model = main._select_model_interactive(cfg)

    recommended_model = next(m for m in MODEL_CATALOG if m.get("recommended")).get("id")
    assert selected_model == recommended_model

    settings = cfg.get_settings()
    assert settings.get("ai", {}).get("model") == recommended_model
