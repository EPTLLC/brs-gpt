from brsgpt.utils.config_manager import ConfigManager


def test_apply_profile_merges_and_marks_active(tmp_path, monkeypatch):
    monkeypatch.setenv("BRS_GPT_CONFIG_DIR", str(tmp_path))
    cfg = ConfigManager()
    # baseline settings
    base = cfg.get_settings()
    assert base.get('active_profile') == 'balanced'

    ok = cfg.apply_profile('fast')
    assert ok is True

    updated = cfg.get_settings()
    assert updated.get('active_profile') == 'fast'
    # merged values exist
    assert updated['recon']['concurrent_requests'] == 32
    assert updated['xss']['rate_limit'] == 12.0