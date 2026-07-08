"""
Language profiles — per-language CWE priority lists and attack context hints.

When the codebase fingerprint identifies a language, the Breaker receives
language-specific CWE priorities and an attack context block that guides it
toward the most likely vulnerability classes for that ecosystem.

Each profile has:
  priority_cwes  — top CWEs to bias toward in this language (rotate within these first)
  attack_context — additional prose added to Breaker's policy section
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class LanguageProfile:
    language: str
    priority_cwes: list[str]
    attack_context: str


PROFILES: dict[str, LanguageProfile] = {
    "javascript": LanguageProfile(
        language="javascript",
        priority_cwes=[
            "CWE-79",    # XSS — innerHTML, document.write, dangerouslySetInnerHTML
            "CWE-1321",  # Prototype pollution — obj[key] = val without __proto__ check
            "CWE-94",    # eval / new Function / vm.runInContext
            "CWE-352",   # CSRF — missing tokens in Express/Fastify routes
            "CWE-601",   # Open redirect — res.redirect(req.query.url)
            "CWE-918",   # SSRF — fetch/axios with unvalidated user-supplied URL
            "CWE-362",   # Async race conditions — Promise.all, shared mutable state
            "CWE-346",   # CORS misconfiguration — origin: * or reflecting Origin header
        ],
        attack_context="""\
JavaScript/TypeScript-specific attack surface (prioritize these):
- Prototype pollution: look for object property assignment using dynamic keys (obj[key] = val)
  without filtering __proto__, constructor, or prototype — especially in merge/extend utilities
- XSS via DOM APIs: innerHTML, outerHTML, document.write, eval, setTimeout(string),
  dangerouslySetInnerHTML, insertAdjacentHTML — look for React/Vue/Angular bypasses
- SSRF via fetch/axios: any server-side fetch/axios/got call using a URL derived from
  user input without allowlist validation
- CSRF: Express/Fastify/Next.js routes that mutate state (POST/PUT/DELETE) without
  CSRF token middleware (csurf or equivalent)
- Open redirect: res.redirect() or window.location using req.query/req.body values
  without URL validation or allowlist
- async race conditions: shared mutable state accessed in Promise.all or concurrent
  async functions without locks or atomic operations
- eval injection: eval(), new Function(), vm.runInContext(), require(userInput)
- CORS: wildcard origin (*) on credentialed routes, or reflect Origin header without
  allowlist check
""",
    ),

    "typescript": LanguageProfile(
        language="typescript",
        priority_cwes=[
            "CWE-79",    # XSS — same as JS but TypeScript type assertions bypass runtime checks
            "CWE-1321",  # Prototype pollution
            "CWE-94",    # eval / new Function — type system does NOT prevent runtime eval
            "CWE-352",   # CSRF
            "CWE-601",   # Open redirect
            "CWE-918",   # SSRF
            "CWE-362",   # Race conditions with async/await
            "CWE-346",   # CORS
            "CWE-285",   # Authorization bypass — TypeScript interfaces don't enforce runtime ACL
        ],
        attack_context="""\
TypeScript-specific attack surface (prioritize these):
- TypeScript's type system provides NO runtime protection — all JS attack vectors apply.
  Type assertions (as any, as unknown as X) commonly strip type safety at critical boundaries.
- Prototype pollution: same as JS — TypeScript does not prevent __proto__ mutation at runtime
- Type confusion: (input as MyType).sensitiveField — if input is user-controlled JSON the
  type assertion bypasses validation entirely
- Unsafe JSON.parse: TypeScript code that JSON.parse()s user input and immediately casts
  the result to a typed interface without runtime validation (use zod/io-ts/ajv checks)
- Express/NestJS/Next.js: route handlers with @Body() or req.body casts to typed objects
  without runtime schema validation — bypass by supplying unexpected properties
- Prisma/TypeORM raw queries: template literal interpolation in $queryRaw or query() calls
- async/await races: shared Map/Set/object state across concurrent request handlers
- eval/new Function: still dangerous regardless of TypeScript types
""",
    ),

    "python": LanguageProfile(
        language="python",
        priority_cwes=[
            "CWE-89",    # SQL injection — f-string/format() in queries
            "CWE-78",    # OS command injection — subprocess with shell=True, os.system
            "CWE-502",   # Deserialization — pickle, yaml.load, marshal
            "CWE-22",    # Path traversal — open(user_input)
            "CWE-94",    # Code injection — eval(), exec(), compile()
            "CWE-611",   # XXE — lxml, xml.etree with external entities
            "CWE-918",   # SSRF — requests.get(user_url)
            "CWE-330",   # Weak randomness — random.random() for tokens
        ],
        attack_context="""\
Python-specific attack surface (prioritize these):
- SQL injection: f-strings or .format() in cursor.execute(), SQLAlchemy text()
- Pickle/YAML deserialization: pickle.loads(user_input), yaml.load(data) without Loader=
- Shell injection: subprocess.run(cmd, shell=True), os.system(cmd) with user input
- Path traversal: open(user_path) without os.path.abspath + prefix check
- eval/exec: any use with untrusted input; also compile() and importlib.import_module(user)
- SSRF: requests.get/post/put where URL contains user-controlled host
- Weak randomness: random module for secrets, tokens, CSRF values (use secrets module)
- Template injection: Jinja2 render_template_string(user_input) or Environment(user_loader)
""",
    ),

    "java": LanguageProfile(
        language="java",
        priority_cwes=[
            "CWE-89",    # SQL injection — JDBC concatenation, JPA native queries
            "CWE-502",   # Java deserialization — ObjectInputStream, XStream, Jackson polymorphic
            "CWE-78",    # OS command injection — Runtime.exec(), ProcessBuilder with user input
            "CWE-611",   # XXE — SAXParser, DocumentBuilder without feature disabling
            "CWE-918",   # SSRF — HttpURLConnection, RestTemplate, WebClient with user URLs
            "CWE-863",   # Authorization bypass — missing @PreAuthorize, Spring Security gaps
            "CWE-362",   # Race conditions — non-atomic operations on shared objects
            "CWE-22",    # Path traversal — new File(basePath + userInput)
        ],
        attack_context="""\
Java/Spring-specific attack surface (prioritize these):
- JDBC SQL injection: Statement.executeQuery(query) where query uses string concatenation
  instead of PreparedStatement with parameterized queries
- Java deserialization: ObjectInputStream.readObject() on untrusted streams; XStream without
  security framework; Jackson polymorphic deserialization (@JsonTypeInfo + DefaultTyping)
- XXE: SAXParserFactory/DocumentBuilderFactory without disabling external entities
  (setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true))
- SSRF: RestTemplate.getForObject(userUrl), WebClient.get().uri(userUrl)
- Spring Security gaps: missing @PreAuthorize on @RestController methods; URL pattern
  mismatches between Spring Security config and @RequestMapping
- EL injection: Spring Expression Language (#{userInput}) in annotation values
- Path traversal: Paths.get(base, userInput) without normalize() + startsWith(base)
- Log4j-style injection: user input flowing into logger.info/debug without sanitization
""",
    ),

    "go": LanguageProfile(
        language="go",
        priority_cwes=[
            "CWE-89",    # SQL injection — fmt.Sprintf in db.Query
            "CWE-78",    # OS command injection — exec.Command with user-controlled args
            "CWE-362",   # Race conditions — goroutine access to shared maps/slices without mutex
            "CWE-476",   # Nil pointer dereference — unchecked error returns, interface nil
            "CWE-22",    # Path traversal — filepath.Join without Clean + prefix check
            "CWE-918",   # SSRF — http.Get(userURL) without URL validation
            "CWE-770",   # Goroutine leak — unbounded goroutine spawning
            "CWE-674",   # Uncontrolled recursion
        ],
        attack_context="""\
Go-specific attack surface (prioritize these):
- SQL injection: db.Query(fmt.Sprintf("SELECT ... %s", userInput)) — use ? placeholders
- Race conditions: concurrent goroutine access to shared map or slice without sync.Mutex
  or sync.RWMutex; the Go race detector catches these but production builds often omit -race
- Nil dereference: err returns ignored (if err != nil skipped), or interface{} nil check
  bypassed with typed nil
- Goroutine leaks: go func() that blocks forever if a channel is never closed; HTTP
  handlers that launch goroutines without context cancellation
- Path traversal: filepath.Join(baseDir, userInput) — Join does not prevent ../../../
  use filepath.Clean + strings.HasPrefix(result, baseDir)
- SSRF: http.Get(req.URL.Query().Get("url")) without scheme/host allowlist validation
- Command injection: exec.Command("sh", "-c", userInput) — supply args individually
  or use shlex-equivalent parsing
- Integer overflow: int/uint arithmetic in 32-bit contexts when input comes from 64-bit source
""",
    ),
}


def get_profile(language: str) -> LanguageProfile | None:
    """Return the profile for a language, or None if not recognized."""
    return PROFILES.get(language.lower())


def language_from_fingerprint(fingerprint: str) -> str:
    """Extract the language token from a GAUNTLEX fingerprint string."""
    if not fingerprint:
        return "unknown"
    return fingerprint.split(":")[0]


def priority_cwes_for_spec(spec: str) -> list[str]:
    """
    Detect the language in spec text and return its priority CWE list.
    Returns empty list if language is unrecognized (Breaker uses full pool).
    """
    from .fingerprint import _detect_language
    lang = _detect_language(spec)
    profile = get_profile(lang)
    return profile.priority_cwes if profile else []


def attack_context_for_spec(spec: str) -> str:
    """
    Detect the language in spec text and return the language-specific
    attack context string to append to the Breaker's policy section.
    Returns empty string if language is unrecognized.
    """
    from .fingerprint import _detect_language
    lang = _detect_language(spec)
    profile = get_profile(lang)
    return profile.attack_context if profile else ""
