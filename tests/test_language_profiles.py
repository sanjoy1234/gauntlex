"""Tests for TypeScript/JS language profiles and extended fingerprinting — Sprint 3."""

from __future__ import annotations

from combatpair.brain.language_profiles import (
    get_profile,
    language_from_fingerprint,
    priority_cwes_for_spec,
    attack_context_for_spec,
    PROFILES,
)
from combatpair.brain.fingerprint import fingerprint_spec, _detect_language


# ── language_from_fingerprint ──────────────────────────────────────────────────

def test_language_from_fingerprint_python():
    assert language_from_fingerprint("python:async:sql_direct") == "python"

def test_language_from_fingerprint_typescript():
    assert language_from_fingerprint("typescript:promise_async:proto_surface") == "typescript"

def test_language_from_fingerprint_empty():
    assert language_from_fingerprint("") == "unknown"

def test_language_from_fingerprint_single_token():
    assert language_from_fingerprint("javascript") == "javascript"


# ── get_profile ────────────────────────────────────────────────────────────────

def test_get_profile_javascript():
    p = get_profile("javascript")
    assert p is not None
    assert p.language == "javascript"
    assert "CWE-1321" in p.priority_cwes  # prototype pollution

def test_get_profile_typescript():
    p = get_profile("typescript")
    assert p is not None
    assert "CWE-79" in p.priority_cwes  # XSS
    assert "CWE-1321" in p.priority_cwes

def test_get_profile_python():
    p = get_profile("python")
    assert p is not None
    assert "CWE-89" in p.priority_cwes
    assert "CWE-502" in p.priority_cwes

def test_get_profile_java():
    p = get_profile("java")
    assert p is not None
    assert "CWE-502" in p.priority_cwes  # Java deserialization
    assert "CWE-863" in p.priority_cwes  # Spring auth bypass

def test_get_profile_go():
    p = get_profile("go")
    assert p is not None
    assert "CWE-362" in p.priority_cwes  # race conditions
    assert "CWE-476" in p.priority_cwes  # nil pointer

def test_get_profile_unknown_returns_none():
    assert get_profile("cobol") is None

def test_get_profile_case_insensitive():
    assert get_profile("JavaScript") is not None
    assert get_profile("PYTHON") is not None


# ── attack_context_for_spec ────────────────────────────────────────────────────

_TS_SNIPPET = """\
import express from 'express';
const app = express();

app.post('/api/user', async (req, res) => {
  const { userId } = req.body;
  const result = await db.query(`SELECT * FROM users WHERE id = ${userId}`);
  res.json(result);
});
"""

_PY_SNIPPET = """\
from flask import Flask, request
app = Flask(__name__)

@app.route('/search')
def search():
    q = request.args.get('q')
    results = db.execute(f"SELECT * FROM items WHERE name='{q}'")
    return results
"""

_JS_SNIPPET = """\
const express = require('express');
const app = express();

function merge(dst, src) {
  for (const key in src) {
    dst[key] = src[key];   // prototype pollution: no __proto__ check
  }
}
"""

def test_attack_context_for_ts_spec():
    context = attack_context_for_spec(_TS_SNIPPET)
    assert "Prototype pollution" in context or "SSRF" in context

def test_attack_context_for_py_spec():
    context = attack_context_for_spec(_PY_SNIPPET)
    assert "SQL injection" in context or "pickle" in context.lower() or "template injection" in context.lower()

def test_attack_context_for_js_spec():
    context = attack_context_for_spec(_JS_SNIPPET)
    assert len(context) > 50  # non-empty language context

def test_attack_context_for_unknown_returns_empty():
    context = attack_context_for_spec("x = 1 + 2")
    # unknown language → empty or very short
    assert context == "" or len(context) < 20


# ── priority_cwes_for_spec ─────────────────────────────────────────────────────

def test_priority_cwes_for_ts_spec():
    cwes = priority_cwes_for_spec(_TS_SNIPPET)
    assert "CWE-79" in cwes
    assert "CWE-1321" in cwes

def test_priority_cwes_for_py_spec():
    cwes = priority_cwes_for_spec(_PY_SNIPPET)
    assert "CWE-89" in cwes

def test_priority_cwes_for_unknown_is_empty():
    cwes = priority_cwes_for_spec("x = 1")
    assert cwes == []


# ── fingerprint_spec extended signals ─────────────────────────────────────────

def test_fingerprint_detects_express_framework():
    fp = fingerprint_spec("const express = require('express'); const app = express();")
    assert "express" in fp

def test_fingerprint_detects_react():
    fp = fingerprint_spec("import React from 'react'; function App() { return <div />; }")
    assert "react" in fp

def test_fingerprint_detects_nextjs():
    fp = fingerprint_spec("import { NextApiRequest, NextApiResponse } from 'next'; export default function handler(req: NextApiRequest, res: NextApiResponse) {}")
    assert "nextjs" in fp

def test_fingerprint_detects_proto_surface():
    fp = fingerprint_spec("obj.__proto__ = malicious; dst[key] = src[key];")
    assert "proto_surface" in fp

def test_fingerprint_detects_promise_async():
    fp = fingerprint_spec("const result = await fetch(url); data.then(r => r.json())")
    assert "promise_async" in fp

def test_fingerprint_detects_dynamic_exec():
    fp = fingerprint_spec("eval(userInput); new Function('return ' + code)()")
    assert "dynamic_exec" in fp

def test_fingerprint_detects_filesystem():
    fp = fingerprint_spec("const data = fs.readFileSync(filePath, 'utf8');")
    assert "filesystem" in fp

def test_fingerprint_detects_spring():
    fp = fingerprint_spec("@RestController public class UserController { @GetMapping('/users') }")
    assert "spring" in fp

def test_fingerprint_language_javascript():
    assert _detect_language("const x = () => {}; let y = 1; var z;") == "javascript"

def test_fingerprint_language_typescript():
    assert _detect_language("const x: string = 'hello'; function greet(name: string): void {}") == "typescript"

def test_fingerprint_language_java():
    assert _detect_language("public class Foo { System.out.println('hi'); }") == "java"

def test_fingerprint_language_go():
    assert _detect_language("package main\nfunc main() {}") == "go"

def test_fingerprint_language_python():
    assert _detect_language("def foo(): pass\nimport os") == "python"


# ── all profiles have non-empty attack context ─────────────────────────────────

def test_all_profiles_have_attack_context():
    for lang, profile in PROFILES.items():
        assert len(profile.attack_context) > 100, f"{lang} attack context too short"

def test_all_profiles_have_priority_cwes():
    for lang, profile in PROFILES.items():
        assert len(profile.priority_cwes) >= 4, f"{lang} needs at least 4 priority CWEs"

def test_js_profile_includes_prototype_pollution_cwe():
    p = get_profile("javascript")
    assert "CWE-1321" in p.priority_cwes

def test_ts_profile_includes_csrf_cwe():
    p = get_profile("typescript")
    assert "CWE-352" in p.priority_cwes

def test_cwe_taxonomy_includes_prototype_pollution():
    import json
    from pathlib import Path
    taxonomy_path = Path(__file__).parent.parent / "src" / "combatpair" / "data" / "cwe_taxonomy.json"
    taxonomy = json.loads(taxonomy_path.read_text())
    assert "CWE-1321" in taxonomy
    assert "CWE-94" in taxonomy
