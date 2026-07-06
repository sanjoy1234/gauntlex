"""Codebase fingerprinting — lightweight signature of language, framework, and risk surface."""

from __future__ import annotations

import re


def fingerprint_spec(spec: str) -> str:
    """
    Produce a short fingerprint string for a spec or code snippet.
    Used as metadata in the Knowledge Forge to cluster similar codebases.
    """
    signals = []

    # Framework detection
    if re.search(r"\bdjango\b|\bDjango\b|from django", spec):
        signals.append("django")
    elif re.search(r"\bflask\b|\bFlask\b|from flask", spec):
        signals.append("flask")
    elif re.search(r"\bfastapi\b|\bFastAPI\b|from fastapi", spec):
        signals.append("fastapi")
    elif re.search(r"\bspring\b|@Controller|@RestController|@SpringBootApplication", spec):
        signals.append("spring")
    elif re.search(r"require\(['\"]express['\"]\)|from ['\"]express['\"]", spec):
        signals.append("express")
    elif re.search(r"from ['\"]next|import.*next/|NextApiRequest", spec):
        signals.append("nextjs")
    elif re.search(r"from ['\"]react|import React|jsx|tsx", spec):
        signals.append("react")
    elif re.search(r"@Injectable|@Component|@NgModule|NestFactory", spec):
        signals.append("nestjs")
    elif re.search(r'import.*"github\.com/gin-gonic|fiber\.New\(\)|chi\.NewRouter', spec):
        signals.append("go_web")

    # Python async
    if re.search(r"\basync\s+def\b|\basyncio\b", spec):
        signals.append("async")

    # JS/TS async patterns
    if re.search(r"\bPromise\b|\bthen\s*\(|\bawait\b", spec):
        signals.append("promise_async")

    # Prototype pollution surface (JS/TS)
    if re.search(r"__proto__|prototype\s*\[|constructor\.prototype|\bObject\.assign\b", spec):
        signals.append("proto_surface")

    # SQL access
    if re.search(r"sqlite3|psycopg2|sqlalchemy|cursor\.execute|PreparedStatement|db\.query|knex\(", spec):
        signals.append("sql_direct")

    # HTTP client
    if re.search(r"\brequests\.get\b|\bhttpx\b|\baiohttp\b|fetch\(|axios\.|got\(|RestTemplate", spec):
        signals.append("http_client")

    # Shell execution
    if re.search(r"subprocess|os\.system|os\.popen|shell=True|exec\.Command|Runtime\.exec", spec):
        signals.append("shell_exec")

    # Deserialization
    if re.search(r"pickle|yaml\.load\b|json\.loads|ObjectInputStream|XStream|JSON\.parse", spec):
        signals.append("deserialization")

    # Credentials surface
    if re.search(r"password|secret|token|api_key|credential|jwt|bearer", spec, re.IGNORECASE):
        signals.append("credentials")

    # eval / dynamic code
    if re.search(r"\beval\s*\(|new\s+Function\s*\(|vm\.runIn|exec\s*\(", spec):
        signals.append("dynamic_exec")

    # Filesystem access
    if re.search(r"fs\.readFile|fs\.writeFile|open\s*\(|filepath\.|readFileSync", spec):
        signals.append("filesystem")

    lang = _detect_language(spec)
    signals.insert(0, lang)

    return ":".join(signals) if signals else "unknown"


def _detect_language(text: str) -> str:
    # TypeScript: explicit type annotations — check before JavaScript
    if re.search(r":\s*(string|number|boolean|void|never|any)\b|interface\s+\w+\s*\{|<\w+>\s*\(", text):
        if re.search(r"\bfunction\b|\bconst\b|\blet\b|\bvar\b|=>|import\s+\w", text):
            return "typescript"
    # JavaScript: ES module imports, require(), arrow functions, const/let/var
    if re.search(r"require\s*\(|from\s+['\"]|export\s+(default|const|function)", text):
        return "javascript"
    if re.search(r"\bfunction\b|\bconst\b|\blet\b|\bvar\b|=>", text):
        # Only label as JS if no Python def/class: syntax visible
        if not re.search(r"\bdef\s+\w+\s*\(|\bclass\s+\w+.*:", text):
            return "javascript"
    # Java: must have public class or System.out or @Annotation patterns
    if re.search(r"\bpublic\s+class\b|\bSystem\.out\b|@Override|@Controller|@Service", text):
        return "java"
    # Go: func keyword with parens or package main
    if re.search(r"\bfunc\s+\w+\s*\(|\bpackage\s+main\b|\bpackage\s+\w+\b.*\bimport\b", text):
        return "go"
    # Python: def with colon, Python-style imports (from X import Y or bare import X)
    if re.search(r"\bdef\s+\w+\s*\(|\bclass\s+\w+.*:|from\s+\w+\s+import\b", text):
        return "python"
    return "unknown"
