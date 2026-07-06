"""Tests for IntentAdapter — Jira, Confluence, Aha!, and fallback resolution."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from combatpair.brain.intent_adapter import (
    IntentAdapter,
    IntentResult,
    _adf_to_text,
    _extract_aha_ref,
    _extract_confluence_page_id,
    _extract_jira_key,
    _strip_html,
    format_intent_context,
)


# ── _extract_jira_key ────────────────────────────────────────────────────────

class TestExtractJiraKey:
    def test_raw_key(self):
        assert _extract_jira_key("PROJ-123") == "PROJ-123"

    def test_browse_url(self):
        assert _extract_jira_key("https://company.atlassian.net/browse/PROJ-456") == "PROJ-456"

    def test_rest_api_url(self):
        assert _extract_jira_key("https://company.atlassian.net/rest/api/2/issue/ENG-99") == "ENG-99"

    def test_key_in_sentence(self):
        assert _extract_jira_key("See ticket PROJ-7 for details") == "PROJ-7"

    def test_numeric_only_project(self):
        assert _extract_jira_key("ABC123-45") == "ABC123-45"

    def test_no_match_returns_empty(self):
        assert _extract_jira_key("no ticket here") == ""

    def test_empty_string(self):
        assert _extract_jira_key("") == ""

    def test_lowercase_key_matches_after_upper(self):
        # _extract_jira_key calls .upper() internally, so lowercase inputs do match
        assert _extract_jira_key("proj-123") == "PROJ-123"


# ── _extract_confluence_page_id ──────────────────────────────────────────────

class TestExtractConfluencePageId:
    def test_numeric_id_passthrough(self):
        assert _extract_confluence_page_id("123456") == "123456"

    def test_url_with_pages_segment(self):
        url = "https://company.atlassian.net/wiki/spaces/ENG/pages/789012/Page+Title"
        assert _extract_confluence_page_id(url) == "789012"

    def test_url_with_page_id_param(self):
        url = "https://company.atlassian.net/wiki/pages/viewpage.action?pageId=345678"
        assert _extract_confluence_page_id(url) == "345678"

    def test_no_match_returns_empty(self):
        assert _extract_confluence_page_id("not-a-confluence-url") == ""

    def test_empty_string(self):
        assert _extract_confluence_page_id("") == ""


# ── _extract_aha_ref ─────────────────────────────────────────────────────────

class TestExtractAhaRef:
    def test_features_url(self):
        url = "https://company.aha.io/features/PROJ-F-123"
        assert _extract_aha_ref(url) == "PROJ-F-123"

    def test_raw_ref(self):
        assert _extract_aha_ref("PROJ-F-42") == "PROJ-F-42"

    def test_standard_ref(self):
        assert _extract_aha_ref("PROJ-123") == "PROJ-123"

    def test_no_match_returns_empty(self):
        assert _extract_aha_ref("not-an-aha-ref") == ""

    def test_empty_string(self):
        assert _extract_aha_ref("") == ""


# ── _adf_to_text ─────────────────────────────────────────────────────────────

class TestAdfToText:
    def test_simple_text_node(self):
        node = {"type": "text", "text": "Hello world"}
        assert _adf_to_text(node) == "Hello world"

    def test_nested_paragraph(self):
        node = {
            "type": "paragraph",
            "content": [
                {"type": "text", "text": "First"},
                {"type": "text", "text": "second"},
            ]
        }
        result = _adf_to_text(node)
        assert "First" in result
        assert "second" in result

    def test_empty_node(self):
        assert _adf_to_text({}) == ""

    def test_node_with_no_text_or_content(self):
        node = {"type": "hardBreak"}
        assert _adf_to_text(node) == ""

    def test_max_depth_guard(self):
        # Build a deeply nested structure — should not crash or recurse infinitely
        deep = {"type": "text", "text": "deep"}
        for _ in range(15):
            deep = {"type": "paragraph", "content": [deep]}
        result = _adf_to_text(deep)
        # Should return something (may be truncated by depth guard) without error
        assert isinstance(result, str)


# ── _strip_html ──────────────────────────────────────────────────────────────

class TestStripHtml:
    def test_removes_tags(self):
        assert _strip_html("<p>Hello <b>world</b></p>") == "Hello world"

    def test_decodes_entities(self):
        assert "&amp;" not in _strip_html("Tom &amp; Jerry")
        assert "&" in _strip_html("Tom &amp; Jerry")

    def test_nbsp_becomes_space(self):
        result = _strip_html("Hello&nbsp;World")
        assert "Hello" in result
        assert "World" in result

    def test_lt_gt_entities(self):
        result = _strip_html("&lt;script&gt;alert(1)&lt;/script&gt;")
        assert "<script>" in result

    def test_collapses_whitespace(self):
        result = _strip_html("<p>   lots   of   space   </p>")
        assert "  " not in result

    def test_plain_text_unchanged(self):
        assert _strip_html("No HTML here") == "No HTML here"

    def test_empty_string(self):
        assert _strip_html("") == ""


# ── IntentResult ─────────────────────────────────────────────────────────────

class TestIntentResult:
    def test_resolved_true_when_text_set(self):
        r = IntentResult(intent_text="some content", source="jira")
        assert r.resolved is True

    def test_resolved_false_when_text_empty(self):
        r = IntentResult(intent_text="", source="none")
        assert r.resolved is False

    def test_resolved_false_on_whitespace_only(self):
        r = IntentResult(intent_text="   ", source="jira")
        assert r.resolved is False


# ── IntentAdapter.resolve ─────────────────────────────────────────────────────

class TestIntentAdapterResolve:
    def test_none_ref_returns_empty(self):
        adapter = IntentAdapter()
        result = adapter.resolve(None)
        assert result.source == "none"
        assert not result.resolved

    def test_empty_string_returns_empty(self):
        adapter = IntentAdapter()
        result = adapter.resolve("")
        assert not result.resolved

    def test_whitespace_only_returns_empty(self):
        adapter = IntentAdapter()
        result = adapter.resolve("   ")
        assert not result.resolved

    def test_no_env_vars_set(self, monkeypatch):
        monkeypatch.delenv("JIRA_URL", raising=False)
        monkeypatch.delenv("CONFLUENCE_URL", raising=False)
        monkeypatch.delenv("AHA_DOMAIN", raising=False)
        adapter = IntentAdapter()
        result = adapter.resolve("PROJ-123")
        assert not result.resolved

    def test_jira_key_detected_in_attempt_list(self, monkeypatch):
        monkeypatch.setenv("JIRA_URL", "https://test.atlassian.net")
        monkeypatch.setenv("JIRA_EMAIL", "test@test.com")
        monkeypatch.setenv("JIRA_TOKEN", "token123")
        adapter = IntentAdapter()
        attempts = adapter._build_attempt_list("PROJ-123")
        names = [name for name, _ in attempts]
        assert "jira" in names

    def test_confluence_url_detected_in_attempt_list(self, monkeypatch):
        monkeypatch.setenv("CONFLUENCE_URL", "https://test.atlassian.net")
        monkeypatch.setenv("CONFLUENCE_EMAIL", "test@test.com")
        monkeypatch.setenv("CONFLUENCE_TOKEN", "token123")
        adapter = IntentAdapter()
        attempts = adapter._build_attempt_list("https://test.atlassian.net/wiki/spaces/ENG/pages/123")
        names = [name for name, _ in attempts]
        assert "confluence" in names

    def test_aha_url_detected_in_attempt_list(self, monkeypatch):
        monkeypatch.setenv("AHA_DOMAIN", "mycompany")
        monkeypatch.setenv("AHA_API_KEY", "apikey123")
        adapter = IntentAdapter()
        attempts = adapter._build_attempt_list("https://mycompany.aha.io/features/PROJ-F-1")
        names = [name for name, _ in attempts]
        assert "aha" in names

    def test_jira_success_via_mock(self, monkeypatch):
        monkeypatch.setenv("JIRA_URL", "https://test.atlassian.net")
        monkeypatch.setenv("JIRA_EMAIL", "test@test.com")
        monkeypatch.setenv("JIRA_TOKEN", "token123")

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "fields": {
                "summary": "Implement secure login",
                "description": "Login endpoint must use bcrypt and enforce rate limiting.",
            }
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.get", return_value=mock_response):
            adapter = IntentAdapter()
            result = adapter.resolve("PROJ-123")

        assert result.resolved
        assert result.source == "jira"
        assert "secure login" in result.intent_text.lower()

    def test_jira_http_failure_returns_empty(self, monkeypatch):
        monkeypatch.setenv("JIRA_URL", "https://test.atlassian.net")
        monkeypatch.setenv("JIRA_EMAIL", "test@test.com")
        monkeypatch.setenv("JIRA_TOKEN", "token123")

        with patch("httpx.get", side_effect=Exception("connection refused")):
            adapter = IntentAdapter()
            result = adapter.resolve("PROJ-123")

        assert not result.resolved
        assert result.error  # error message is set

    def test_confluence_success_via_mock(self, monkeypatch):
        monkeypatch.setenv("CONFLUENCE_URL", "https://test.atlassian.net")
        monkeypatch.setenv("CONFLUENCE_EMAIL", "test@test.com")
        monkeypatch.setenv("CONFLUENCE_TOKEN", "token123")

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "title": "Payment Service Requirements",
            "body": {
                "storage": {
                    "value": "<p>PCI-DSS compliant payment processing required.</p>"
                }
            }
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.get", return_value=mock_response):
            adapter = IntentAdapter()
            result = adapter.resolve("https://test.atlassian.net/wiki/spaces/ENG/pages/123456/Page")

        assert result.resolved
        assert result.source == "confluence"
        assert "Payment Service" in result.intent_text

    def test_aha_success_via_mock(self, monkeypatch):
        monkeypatch.setenv("AHA_DOMAIN", "mycompany")
        monkeypatch.setenv("AHA_API_KEY", "apikey123")

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "feature": {
                "name": "Fraud Detection Engine",
                "description": {"html": "<p>Real-time AML transaction scoring.</p>"},
                "requirements": [
                    {"name": "Must flag transactions above threshold", "description": {"html": "<p>Use ML model</p>"}}
                ]
            }
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.get", return_value=mock_response):
            adapter = IntentAdapter()
            result = adapter.resolve("https://mycompany.aha.io/features/PROJ-F-1")

        assert result.resolved
        assert result.source == "aha"
        assert "Fraud Detection" in result.intent_text

    def test_all_adapters_fail_gracefully(self, monkeypatch):
        monkeypatch.setenv("JIRA_URL", "https://test.atlassian.net")
        monkeypatch.setenv("JIRA_EMAIL", "test@test.com")
        monkeypatch.setenv("JIRA_TOKEN", "token")

        with patch("httpx.get", side_effect=Exception("timeout")):
            adapter = IntentAdapter()
            result = adapter.resolve("PROJ-999")

        assert not result.resolved
        assert result.source == "none"


# ── format_intent_context ────────────────────────────────────────────────────

class TestFormatIntentContext:
    def test_resolved_jira_result(self):
        r = IntentResult(
            intent_text="Implement rate limiting on login",
            source="jira",
            source_url="https://test.atlassian.net/browse/PROJ-1"
        )
        ctx = format_intent_context(r)
        assert "Jira issue" in ctx
        assert "Implement rate limiting" in ctx
        assert "https://test.atlassian.net/browse/PROJ-1" in ctx

    def test_resolved_confluence_result(self):
        r = IntentResult(intent_text="PCI-DSS requirements", source="confluence")
        ctx = format_intent_context(r)
        assert "Confluence page" in ctx
        assert "PCI-DSS" in ctx

    def test_resolved_aha_result(self):
        r = IntentResult(intent_text="Fraud scoring", source="aha")
        ctx = format_intent_context(r)
        assert "Aha!" in ctx
        assert "Fraud scoring" in ctx

    def test_unresolved_result_returns_empty(self):
        r = IntentResult(source="none")
        assert format_intent_context(r) == ""

    def test_no_source_url_omits_url_from_header(self):
        r = IntentResult(intent_text="Some intent", source="jira", source_url="")
        ctx = format_intent_context(r)
        assert "https://" not in ctx
        assert "Some intent" in ctx
