"""Tests for codebase fingerprinting."""

from combatpair.brain.fingerprint import fingerprint_spec, _detect_language


def test_detects_django():
    spec = "from django.db import models\n# Django model"
    fp = fingerprint_spec(spec)
    assert "django" in fp


def test_detects_flask():
    spec = "from flask import Flask, request\napp = Flask(__name__)"
    fp = fingerprint_spec(spec)
    assert "flask" in fp


def test_detects_sql():
    spec = "cursor.execute('SELECT * FROM users')"
    fp = fingerprint_spec(spec)
    assert "sql_direct" in fp


def test_detects_shell():
    spec = "subprocess.run(cmd, shell=True)"
    fp = fingerprint_spec(spec)
    assert "shell_exec" in fp


def test_detects_python():
    assert _detect_language("def main():\n    pass") == "python"


def test_detects_typescript():
    assert _detect_language("const x: string = 'hello'") == "typescript"


def test_detects_java():
    assert _detect_language("public class Main { System.out.println(); }") == "java"


def test_unknown_language():
    assert _detect_language("random text without code patterns") == "unknown"
