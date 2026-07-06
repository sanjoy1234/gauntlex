"""Tests for Forge Network — Sprint 13."""

from __future__ import annotations

import pytest

from combatpair.network.forge_network import (
    ForgeNetworkConfig,
    SharedPattern,
    NetworkResult,
    push_patterns,
    pull_patterns,
    fetch_hub_stats,
    extract_shareable_patterns,
    _score_to_verdict,
    _derive_contributor_id,
)


# ── ForgeNetworkConfig ─────────────────────────────────────────────────────────

def test_network_config_default_disabled():
    cfg = ForgeNetworkConfig()
    assert cfg.enabled is False


def test_network_config_from_env_enabled(monkeypatch):
    monkeypatch.setenv("COMBATPAIR_FORGE_NETWORK_ENABLED", "true")
    monkeypatch.setenv("COMBATPAIR_FORGE_HUB_URL", "http://hub.local")
    monkeypatch.setenv("COMBATPAIR_FORGE_MIN_ARS", "0.90")
    cfg = ForgeNetworkConfig.from_env()
    assert cfg.enabled is True
    assert cfg.hub_url == "http://hub.local"
    assert cfg.min_ars_to_share == 0.90


def test_network_config_contributor_id_is_hex():
    cfg = ForgeNetworkConfig.from_env()
    assert len(cfg.contributor_id) == 16
    int(cfg.contributor_id, 16)  # must be valid hex


def test_network_config_contributor_id_stable():
    id1 = _derive_contributor_id()
    id2 = _derive_contributor_id()
    assert id1 == id2


# ── SharedPattern ──────────────────────────────────────────────────────────────

def test_shared_pattern_to_dict():
    p = SharedPattern(cwe="CWE-89", attack_vector="UNION SELECT", severity="high",
                      verdict="missed", language="python", contributor_id="abc123")
    d = p.to_dict()
    assert d["cwe"] == "CWE-89"
    assert d["attack_vector"] == "UNION SELECT"
    assert d["contributor_id"] == "abc123"
    assert "pattern_id" not in d  # internal field, not serialized


# ── _score_to_verdict ──────────────────────────────────────────────────────────

def test_score_to_verdict_mitigated():
    assert _score_to_verdict(1.0) == "mitigated"
    assert _score_to_verdict(0.9) == "mitigated"


def test_score_to_verdict_partial():
    assert _score_to_verdict(0.5) == "partial"
    assert _score_to_verdict(0.8) == "partial"


def test_score_to_verdict_missed():
    assert _score_to_verdict(0.0) == "missed"
    assert _score_to_verdict(0.49) == "missed"


# ── push_patterns ──────────────────────────────────────────────────────────────

def test_push_disabled_returns_error():
    cfg = ForgeNetworkConfig(enabled=False)
    result = push_patterns([], cfg)
    assert result.success is False
    assert "disabled" in result.error


def test_push_empty_list_succeeds():
    cfg = ForgeNetworkConfig(enabled=True, hub_url="http://x")
    result = push_patterns([], cfg)
    assert result.success is True
    assert result.patterns_count == 0


def test_push_network_error_returns_failure(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "post", lambda *a, **kw: (_ for _ in ()).throw(httpx.ConnectError("x")))
    cfg = ForgeNetworkConfig(enabled=True, hub_url="http://localhost:9999", contributor_id="abc")
    patterns = [SharedPattern("CWE-89", "sql inj", "high", "missed", "python")]
    result = push_patterns(patterns, cfg)
    assert result.success is False
    assert result.error != ""


def test_push_success(monkeypatch):
    import httpx

    def mock_post(url, json, headers, timeout):
        class Resp:
            def raise_for_status(self): pass
            def json(self): return {"accepted": 1}
        return Resp()

    monkeypatch.setattr(httpx, "post", mock_post)
    cfg = ForgeNetworkConfig(enabled=True, hub_url="http://hub.local", contributor_id="abc")
    patterns = [SharedPattern("CWE-89", "sql inj", "high", "missed", "python")]
    result = push_patterns(patterns, cfg)
    assert result.success is True
    assert result.patterns_count == 1


def test_push_sends_contributor_id(monkeypatch):
    import httpx
    captured = {}

    def mock_post(url, json, headers, timeout):
        captured["payload"] = json
        class Resp:
            def raise_for_status(self): pass
        return Resp()

    monkeypatch.setattr(httpx, "post", mock_post)
    cfg = ForgeNetworkConfig(enabled=True, hub_url="http://hub.local", contributor_id="deadbeef")
    push_patterns([SharedPattern("CWE-79", "xss", "medium", "missed", "javascript")], cfg)
    assert captured["payload"]["contributor_id"] == "deadbeef"


# ── pull_patterns ──────────────────────────────────────────────────────────────

def test_pull_disabled_returns_empty():
    cfg = ForgeNetworkConfig(enabled=False)
    patterns, result = pull_patterns("CWE-89", cfg)
    assert patterns == []
    assert result.success is False


def test_pull_network_error_returns_empty(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "get", lambda *a, **kw: (_ for _ in ()).throw(httpx.ConnectError("x")))
    cfg = ForgeNetworkConfig(enabled=True, hub_url="http://localhost:9999")
    patterns, result = pull_patterns("CWE-89", cfg)
    assert patterns == []
    assert result.success is False


def test_pull_success_parses_patterns(monkeypatch):
    import httpx

    def mock_get(url, params, timeout):
        class Resp:
            def raise_for_status(self): pass
            def json(self):
                return {"patterns": [
                    {"cwe": "CWE-89", "attack_vector": "UNION SELECT", "severity": "high",
                     "verdict": "missed", "language": "python", "contributor_id": "xyz", "pattern_id": "p1"},
                    {"cwe": "CWE-89", "attack_vector": "OR 1=1", "severity": "medium",
                     "verdict": "partial", "language": "java", "contributor_id": "abc", "pattern_id": "p2"},
                ]}
        return Resp()

    monkeypatch.setattr(httpx, "get", mock_get)
    cfg = ForgeNetworkConfig(enabled=True, hub_url="http://hub.local")
    patterns, result = pull_patterns("CWE-89", cfg)
    assert result.success is True
    assert len(patterns) == 2
    assert patterns[0].cwe == "CWE-89"
    assert patterns[0].pattern_id == "p1"
    assert patterns[1].language == "java"


# ── fetch_hub_stats ────────────────────────────────────────────────────────────

def test_fetch_stats_disabled_returns_empty():
    cfg = ForgeNetworkConfig(enabled=False)
    assert fetch_hub_stats(cfg) == {}


def test_fetch_stats_network_error_returns_empty(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "get", lambda *a, **kw: (_ for _ in ()).throw(httpx.ConnectError("x")))
    cfg = ForgeNetworkConfig(enabled=True, hub_url="http://x")
    assert fetch_hub_stats(cfg) == {}


def test_fetch_stats_success(monkeypatch):
    import httpx

    def mock_get(url, timeout):
        class Resp:
            def raise_for_status(self): pass
            def json(self): return {"total_patterns": 1234, "cwe_counts": {"CWE-89": 300}}
        return Resp()

    monkeypatch.setattr(httpx, "get", mock_get)
    cfg = ForgeNetworkConfig(enabled=True, hub_url="http://hub.local")
    stats = fetch_hub_stats(cfg)
    assert stats["total_patterns"] == 1234


# ── extract_shareable_patterns ─────────────────────────────────────────────────

def test_extract_empty_attacks():
    cfg = ForgeNetworkConfig(enabled=True, min_ars_to_share=0.85)
    patterns = extract_shareable_patterns([], cfg)
    assert patterns == []


def test_extract_includes_missed_attacks():
    cfg = ForgeNetworkConfig(enabled=True, min_ars_to_share=0.85)
    attacks = [{"cwe": "CWE-89", "description": "SQL injection via username", "score": 0.0,
                "severity": "high"}]
    patterns = extract_shareable_patterns(attacks, cfg)
    assert len(patterns) == 1
    assert patterns[0].verdict == "missed"


def test_extract_includes_high_score_attacks():
    cfg = ForgeNetworkConfig(enabled=True, min_ars_to_share=0.85)
    attacks = [{"cwe": "CWE-79", "description": "XSS via reflected input", "score": 0.95,
                "severity": "medium"}]
    patterns = extract_shareable_patterns(attacks, cfg)
    assert len(patterns) == 1


def test_extract_excludes_mediocre_non_miss():
    cfg = ForgeNetworkConfig(enabled=True, min_ars_to_share=0.85)
    attacks = [{"cwe": "CWE-79", "description": "XSS via input", "score": 0.70,
                "severity": "medium"}]
    patterns = extract_shareable_patterns(attacks, cfg)
    assert patterns == []


def test_extract_caps_attack_vector_length():
    cfg = ForgeNetworkConfig(enabled=True, min_ars_to_share=0.85)
    attacks = [{"cwe": "CWE-89", "description": "A" * 1000, "score": 0.0, "severity": "high"}]
    patterns = extract_shareable_patterns(attacks, cfg)
    assert len(patterns[0].attack_vector) == 500


def test_extract_skips_empty_description():
    cfg = ForgeNetworkConfig(enabled=True, min_ars_to_share=0.85)
    attacks = [{"cwe": "CWE-89", "description": "", "score": 0.0, "severity": "high"}]
    patterns = extract_shareable_patterns(attacks, cfg)
    assert patterns == []


def test_extract_uses_fingerprint_language():
    cfg = ForgeNetworkConfig(enabled=True, min_ars_to_share=0.85)
    attacks = [{"cwe": "CWE-89", "description": "sql inj", "score": 0.0, "severity": "high"}]
    patterns = extract_shareable_patterns(attacks, cfg, fingerprint={"language": "go"})
    assert patterns[0].language == "go"
