"""Static analysis of application code (SAST).

Python is analysed on its AST, which lets rules tell a constant string from
one built out of user data. Other languages use line rules that require a
dangerous sink *and* an untrusted or dynamic argument on the same line, which
keeps precision acceptable without a full parser per language.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Iterator

from rempart.engine import ScanContext, is_comment, line_of
from rempart.models import Finding, Rule
from rempart.registry import A01, A02, A04, A05, A06, A07, A08, A10, C, H, L, M, rule

JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".svelte", ".vue")
PY = (".py",)
GO = (".go",)
JAVA = (".java", ".kt", ".scala")
PHP = (".php",)
RB = (".rb", ".erb")
CS = (".cs",)
C_CPP = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp")
ALL_CODE = JS + PY + GO + JAVA + PHP + RB + CS + C_CPP

# ------------------------------------------------------------------ shared rules
R_CODE_INJ = rule("CODE-EVAL", "Dynamic code evaluation", H, "code", cwe="CWE-94", owasp=A05,
                  fix="Never evaluate strings as code. Parse data with a real parser (JSON, ast.literal_eval) or dispatch through an allow-list.")
R_CMD_INJ = rule("CODE-CMD-INJECTION", "OS command built from dynamic input", C, "code", cwe=("CWE-78", "CWE-77"), owasp=A05,
                 fix="Call the program with an argument list and no shell (subprocess.run([...]), execFile, exec.Command with separate args). Validate inputs against an allow-list.")
R_SHELL_TRUE = rule("CODE-SHELL-TRUE", "Subprocess started through a shell", M, "code", cwe="CWE-78", owasp=A05,
                    fix="Pass an argument list with shell=False. A shell adds a second parsing layer that turns any interpolated value into code.",
                    confidence=0.6)
R_SQLI = rule("CODE-SQL-INJECTION", "SQL query built by string interpolation", C, "code", cwe="CWE-89", owasp=A05,
              fix="Use parameterised queries (placeholders + bound values) or the ORM's query builder. Never interpolate values into SQL text.")
R_NOSQLI = rule("CODE-NOSQL-INJECTION", "NoSQL query accepting raw request objects or $where", H, "code", cwe="CWE-943", owasp=A05,
                fix="Cast every query field to the expected primitive type (String(x)), reject keys starting with `$`, and never use `$where`. Libraries such as mongo-sanitize help.")
R_XSS = rule("CODE-XSS-SINK", "Untrusted HTML written to the DOM", M, "code", cwe="CWE-79", owasp=A05,
             fix="Render text with textContent or the framework's escaped interpolation. When HTML is required, sanitise it with DOMPurify first.",
             confidence=0.55)
R_DESER = rule("CODE-UNSAFE-DESERIALIZATION", "Deserialization of untrusted data", H, "code", cwe="CWE-502", owasp=A08,
               fix="Use a data-only format (JSON) or a safe loader (yaml.safe_load). Native object deserializers execute code chosen by whoever controls the bytes.")
R_TLS = rule("CODE-TLS-VERIFY-DISABLED", "TLS certificate verification disabled", H, "code", cwe="CWE-295", owasp=A04,
             fix="Keep verification on. For private CAs, pass the CA bundle explicitly instead of disabling checks.")
R_WEAK_HASH = rule("CODE-WEAK-HASH", "Broken hash algorithm (MD5/SHA-1)", M, "code", cwe="CWE-327", owasp=A04,
                   fix="Use SHA-256 or better for integrity. If the hash is not security-relevant (cache keys, ETags), mark it explicitly (usedforsecurity=False) and suppress.",
                   confidence=0.5)
R_WEAK_CIPHER = rule("CODE-WEAK-CIPHER", "Weak cipher or mode (DES, RC4, ECB, no IV)", H, "code", cwe="CWE-327", owasp=A04,
                     fix="Use an AEAD cipher: AES-256-GCM or ChaCha20-Poly1305 with a fresh random nonce per message.")
R_PWD_HASH = rule("CODE-WEAK-PASSWORD-HASH", "Password hashed with a fast hash", H, "code", cwe="CWE-916", owasp=A04,
                  fix="Store passwords with Argon2id, scrypt or bcrypt. Fast hashes (MD5, SHA-*) are brute-forced at billions of guesses per second.",
                  confidence=0.7)
R_RANDOM = rule("CODE-WEAK-RANDOM", "Non-cryptographic RNG used for a security value", M, "code", cwe="CWE-338", owasp=A04,
                fix="Use secrets.token_urlsafe / crypto.randomUUID / crypto.getRandomValues / crypto/rand for tokens, salts, OTPs and IDs.",
                confidence=0.6)
R_JWT = rule("CODE-JWT-UNVERIFIED", "JWT accepted without signature or expiry verification", C, "code", cwe=("CWE-347", "CWE-287"), owasp=A07,
             fix="Verify with an explicit algorithm allow-list (e.g. ['RS256']), never 'none', and keep expiry checks on.")
R_SSRF = rule("CODE-SSRF", "Server-side request to a user-supplied URL", H, "code", cwe="CWE-918", owasp=A01,
              fix="Resolve the host, reject private/link-local/metadata ranges (169.254.169.254, fd00::/8...), allow-list schemes and domains, and disable redirects.",
              refs=("https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",))
R_PATH = rule("CODE-PATH-TRAVERSAL", "File path built from user input", H, "code", cwe="CWE-22", owasp=A01,
              fix="Resolve the final path and check it stays under the intended base directory, or map user input to an allow-listed set of files.")
R_REDIRECT = rule("CODE-OPEN-REDIRECT", "Redirect target taken from user input", M, "code", cwe="CWE-601", owasp=A01,
                  fix="Only redirect to relative paths you validate, or to an allow-list of hosts.", confidence=0.7)
R_MASS = rule("CODE-MASS-ASSIGNMENT", "Request body written straight into a model", M, "code", cwe="CWE-915", owasp=A01,
              fix="Pick the allowed fields explicitly (or validate with a schema such as zod/pydantic) so a client cannot set role, isAdmin, credits or ownerId.",
              confidence=0.6)
R_PROTO = rule("CODE-PROTOTYPE-POLLUTION", "Deep merge of untrusted object", M, "code", cwe="CWE-1321", owasp=A08,
               fix="Validate the object against a schema first, and use merges that skip __proto__/constructor/prototype keys.", confidence=0.5)
R_COOKIE = rule("CODE-COOKIE-FLAGS", "Session cookie without Secure/HttpOnly", M, "code", cwe=("CWE-614", "CWE-1004"), owasp=A07,
                fix="Set Secure, HttpOnly and SameSite=Lax (or Strict) on session and auth cookies.", confidence=0.7)
R_CSRF = rule("CODE-CSRF-DISABLED", "CSRF protection disabled", H, "code", cwe="CWE-352", owasp=A01,
              fix="Keep the framework's CSRF / origin check on. If an endpoint must accept cross-site posts, scope the exemption to that route and authenticate it another way.",
              confidence=0.6)
R_CORS = rule("CODE-CORS-PERMISSIVE", "CORS reflects any origin with credentials", H, "code", cwe="CWE-942", owasp=A02,
              fix="Allow-list exact origins. Never combine credentials: true with origin: true or '*'.")
R_DEBUG = rule("CODE-DEBUG-ENABLED", "Debug mode enabled in application code", H, "code", cwe=("CWE-489", "CWE-215"), owasp=A02,
               fix="Drive debug from an environment variable that defaults to off. A debug server in production exposes stack traces and, for Werkzeug, a code console.",
               confidence=0.7)
R_DEFAULT_SECRET = rule("CODE-FALLBACK-SECRET", "Secret falls back to a hard-coded default", H, "code", cwe=("CWE-798", "CWE-1188"), owasp=(A07, A10),
                        fix="Fail at startup when the secret is missing. A fallback silently ships a known key to every environment where the variable is unset.")
R_REDOS = rule("CODE-REDOS", "Regular expression vulnerable to catastrophic backtracking", M, "code", cwe=("CWE-1333", "CWE-400"), owasp=A06,
               fix="Remove nested quantifiers such as (a+)+ or (.*)*, bound repetition, or use a linear-time engine (RE2).", confidence=0.5)
R_REGEX_INJ = rule("CODE-REGEX-INJECTION", "Regular expression built from user input", M, "code", cwe=("CWE-1333", "CWE-625"), owasp=A05,
                   fix="Escape user input before building a pattern, or match with plain string functions.", confidence=0.6)
R_TOKEN_STORAGE = rule("CODE-TOKEN-LOCALSTORAGE", "Auth token stored in localStorage", M, "code", cwe="CWE-922", owasp=A07,
                       fix="Keep session tokens in Secure, HttpOnly cookies. Anything in localStorage is readable by any script that runs on the page, so one XSS steals every session.",
                       confidence=0.6)
R_POSTMESSAGE = rule("CODE-POSTMESSAGE-ORIGIN", "postMessage handler without origin check", M, "code", cwe="CWE-346", owasp=A01,
                     fix="Check event.origin against an allow-list before using event.data, and never post sensitive data to '*'.", confidence=0.6)
R_XXE = rule("CODE-XXE", "XML parser without external-entity protection", M, "code", cwe="CWE-611", owasp=A02,
             fix="Disable DTDs/external entities (disallow-doctype-decl) or use a hardened parser such as defusedxml.", confidence=0.5)
R_TEMPFILE = rule("CODE-INSECURE-TEMPFILE", "Predictable temporary file", M, "code", cwe="CWE-377", owasp=A02,
                  fix="Use tempfile.mkstemp/NamedTemporaryFile, which create the file atomically.")
R_TEMPLATE = rule("CODE-TEMPLATE-AUTOESCAPE-OFF", "Template auto-escaping disabled or bypassed", M, "code", cwe=("CWE-79", "CWE-1336"), owasp=A05,
                  fix="Keep autoescape on and avoid marking dynamic strings as safe. Never render a template string that users can influence (SSTI).",
                  confidence=0.6)
R_BIDI = rule("CODE-TROJAN-SOURCE", "Bidirectional or invisible Unicode control characters in source", H, "code", cwe=("CWE-1007", "CWE-451"), owasp=A08,
              fix="Remove the characters. They make code render differently from how it compiles (Trojan Source, CVE-2021-42574) and hide instructions from human reviewers.",
              refs=("https://trojansource.codes/",))
R_SANDBOX = rule("CODE-WEAK-SANDBOX", "Untrusted code run in a non-isolating sandbox", H, "code", cwe="CWE-94", owasp=A05,
                 fix="`vm`/`vm2` are not security boundaries (vm2 is discontinued after repeated escapes). Run untrusted code in a separate process or container, or use isolated-vm.")
R_UPLOAD = rule("CODE-UNRESTRICTED-UPLOAD", "File upload without type, name or size restrictions", H, "code", cwe=("CWE-434", "CWE-770"), owasp=A06,
                fix="Validate type by content (magic bytes), cap size, generate the stored filename yourself, store outside the web root or in object storage, and serve with Content-Disposition: attachment.",
                confidence=0.6)
R_BANNED_C = rule("CODE-UNSAFE-C-FUNCTION", "Unbounded C string/memory function", H, "code", cwe=("CWE-120", "CWE-121", "CWE-122", "CWE-787"), owasp=A06,
                  fix="Use bounded variants (snprintf, strlcpy/strncpy with explicit termination, fgets) and compile with -D_FORTIFY_SOURCE=3 -fstack-protector-strong; consider a memory-safe language for parsers.",
                  confidence=0.7)
R_IDOR = rule("CODE-IDOR-CANDIDATE", "Object fetched by client-supplied ID with no visible ownership check", L, "code", cwe=("CWE-639", "CWE-862", "CWE-863"), owasp=A01,
              frameworks=("OWASP API1:2023 BOLA",),
              fix="Scope the query to the caller (where: { id, ownerId: session.userId }) or check ownership before returning. This rule is a review queue: triage it so Rempart learns your codebase's patterns.",
              confidence=0.35)


@dataclass(frozen=True)
class LineRule:
    rule: Rule
    suffixes: tuple[str, ...]
    pattern: re.Pattern[str]
    message: str
    unless: re.Pattern[str] | None = None
    file_unless: re.Pattern[str] | None = None


def lr(r: Rule, suffixes: tuple[str, ...], pattern: str, message: str, unless: str | None = None, file_unless: str | None = None) -> LineRule:
    return LineRule(r, suffixes, re.compile(pattern), message,
                    re.compile(unless) if unless else None, re.compile(file_unless) if file_unless else None)


_USER = r"(?:req|request|ctx\.request|event\.request)\.(?:query|body|params|headers|cookies)|url\.searchParams\.get|searchParams\.get|params\.\w+"
_SECRETY = r"(?i)token|secret|passw|otp|nonce|salt|session|api_?key|reset|verif|invite|csrf|code\b"

LINE_RULES: list[LineRule] = [
    # ---- JavaScript / TypeScript / Svelte / Vue
    lr(R_CODE_INJ, JS, r"(?<![\w.])eval\s*\((?!\s*[\"'][^\"'$]*[\"']\s*\))", "eval() on a non-constant value."),
    lr(R_CODE_INJ, JS, r"\bnew\s+Function\s*\(", "new Function() compiles a string into code."),
    lr(R_CODE_INJ, JS, r"\bset(?:Timeout|Interval)\s*\(\s*(?:`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+)", "Timer called with a code string."),
    lr(R_CMD_INJ, JS, r"\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|[^,)]*\+\s*\w)", "Shell command built by interpolation."),
    lr(R_SHELL_TRUE, JS, r"\bspawn(?:Sync)?\s*\([^)]*shell\s*:\s*true", "spawn() with shell: true."),
    lr(R_SQLI, JS, r"(?:\.query|\.execute|\.raw|\$queryRawUnsafe|\$executeRawUnsafe|sequelize\.query|knex\.raw|\.prepare|sql\.unsafe)\s*\(\s*`[^`]*\$\{", "SQL text built with a template literal."),
    lr(R_SQLI, JS + JAVA + GO + CS + PY, r"[\"'`]\s*(?:SELECT\s[^\"'`]*\sFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b[^\"'`]*[\"'`]\s*\+\s*[\w(]", "SQL text concatenated with a variable."),
    lr(R_SQLI, JS, r"\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(\s*(?!`[^`$]*`\s*[,)])", "Prisma *Unsafe raw query with a non-constant string."),
    lr(R_NOSQLI, JS, r"[\"']?\$where[\"']?\s*:", "MongoDB $where executes JavaScript on the server."),
    lr(R_NOSQLI, JS, r"\.(?:find|findOne|findOneAndUpdate|updateOne|updateMany|deleteOne|deleteMany|countDocuments)\(\s*(?:req|request)\.(?:body|query|params)\b", "Request object passed directly as a query filter (operator injection)."),
    lr(R_XSS, JS, r"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)\s*(?![\"'][^\"'$]*[\"']\s*;?\s*$)", "innerHTML/outerHTML assigned a dynamic value.", unless=r"DOMPurify|sanitize"),
    lr(R_XSS, JS, r"\.insertAdjacentHTML\s*\(|document\.write(?:ln)?\s*\(", "Raw HTML inserted into the document.", unless=r"DOMPurify|sanitize"),
    lr(R_XSS, JS, r"dangerouslySetInnerHTML", "React dangerouslySetInnerHTML.", unless=r"DOMPurify|sanitize"),
    lr(R_XSS, (".svelte",), r"\{@html\s", "Svelte {@html} renders unescaped markup.", unless=r"DOMPurify|sanitize|purify",
       file_unless=r"u003c|DOMPurify|sanitize-html|sanitizeHtml|xss\("),
    lr(R_XSS, (".vue",), r"\bv-html\s*=", "Vue v-html renders unescaped markup.", unless=r"DOMPurify|sanitize"),
    lr(R_DESER, JS, r"require\(\s*[\"']node-serialize[\"']\s*\)|\bunserialize\s*\(", "node-serialize unserialize() executes embedded functions."),
    lr(R_SANDBOX, JS, r"\bvm\.runIn(?:New|This)?Context\s*\(|require\(\s*[\"']vm2[\"']\s*\)|from\s+[\"']vm2[\"']", "vm/vm2 used as a sandbox."),
    lr(R_TLS, JS, r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0|strictSSL\s*:\s*false", "TLS verification turned off."),
    lr(R_WEAK_HASH, JS, r"createHash\(\s*[\"'](?:md5|md4|sha1)[\"']", "MD5/SHA-1 via crypto.createHash.", unless=r"(?i)etag|cache|checksum|fingerprint"),
    lr(R_WEAK_CIPHER, JS, r"createCipher\s*\(|createCipheriv\(\s*[\"'](?:[^\"']*-ecb|des[^\"']*|rc4|bf[^\"']*)[\"']", "Weak cipher or ECB mode."),
    lr(R_PWD_HASH, JS, r"createHash\(\s*[\"'](?:md5|sha1|sha256|sha512)[\"']\s*\)\s*\.update\([^)]*(?i:passw)", "Password run through a fast hash."),
    lr(R_RANDOM, JS, r"Math\.random\s*\(\s*\)", "Math.random() is predictable.", unless=r"(?i)color|delay|jitter|backoff|anim|shuffle|sample|position|width|height|opacity"),
    lr(R_JWT, JS, r"algorithms\s*:\s*\[[^\]]*[\"']none[\"']", "JWT 'none' algorithm accepted."),
    lr(R_JWT, JS, r"ignoreExpiration\s*:\s*true", "JWT expiry ignored."),
    lr(R_SSRF, JS, r"\b(?:fetch|axios(?:\.(?:get|post|put|request))?|got|needle|superagent\.get|https?\.(?:get|request))\s*\(\s*(?:" + _USER + r")", "Outbound request to a URL taken from the request."),
    lr(R_PATH, JS, r"(?:readFile(?:Sync)?|createReadStream|sendFile|download|unlink(?:Sync)?|writeFile(?:Sync)?|readdir(?:Sync)?)\s*\([^)]*(?:" + _USER + r")", "Filesystem access with a path from the request.", unless=r"basename\("),
    lr(R_REDIRECT, JS, r"\bredirect\s*\(\s*(?:\d{3}\s*,\s*)?(?:" + _USER + r")", "Redirect target read from the request."),
    lr(R_MASS, JS, r"\.(?:create|update|insertOne|updateOne|findByIdAndUpdate|findOneAndUpdate|upsert)\(\s*(?:[^,()]*,\s*)?(?:req|request)\.body\s*\)|\{\s*\.\.\.(?:req|request)\.body\s*\}|data\s*:\s*(?:req|request)\.body\b|data\s*:\s*await\s+request\.json\(\)", "Whole request body persisted."),
    lr(R_PROTO, JS, r"\b(?:merge|mergeWith|defaultsDeep|extend|deepmerge|setWith)\s*\([^)]*(?:req|request)\.(?:body|query)", "Deep merge of request data."),
    lr(R_COOKIE, JS, r"httpOnly\s*:\s*false", "Cookie readable from JavaScript."),
    lr(R_COOKIE, JS, r"\bsecure\s*:\s*false", "Cookie sent over plain HTTP.", unless=r"(?i)smtp|mail|tls|port"),
    lr(R_CSRF, JS, r"checkOrigin\s*:\s*false|trustedOrigins\s*:\s*\[\s*[\"']\*[\"']", "Origin/CSRF check disabled."),
    lr(R_DEFAULT_SECRET, JS, r"process\.env\.\w*(?:SECRET|KEY|TOKEN|PASSWORD|SALT)\w*\s*(?:\|\||\?\?)\s*[\"'`][^\"'`]{3,}[\"'`]", "Secret with a hard-coded fallback."),
    lr(R_REGEX_INJ, JS, r"new\s+RegExp\s*\(\s*(?:" + _USER + r")", "RegExp built from request input."),
    lr(R_TOKEN_STORAGE, JS, r"localStorage\.setItem\(\s*[\"'`][^\"'`]*(?i:token|jwt|session|auth|access|refresh)", "Token written to localStorage."),
    lr(R_POSTMESSAGE, JS, r"\.postMessage\([^)]*,\s*[\"']\*[\"']\s*\)", "postMessage to any origin ('*')."),
    lr(R_DEBUG, JS, r"\bdebugger\s*;", "debugger statement left in code."),
    # ---- Go
    lr(R_TLS, GO, r"InsecureSkipVerify\s*:\s*true", "InsecureSkipVerify disables certificate checks."),
    lr(R_SQLI, GO, r"\.(?:Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext|Raw|Select|Get)\s*\(\s*(?:ctx\s*,\s*)?fmt\.Sprintf\(", "SQL built with fmt.Sprintf."),
    lr(R_CMD_INJ, GO, r"exec\.Command(?:Context)?\([^)]*[\"'`](?:sh|bash|/bin/sh|/bin/bash|cmd|cmd\.exe)[\"'`]\s*,\s*[\"'`](?:-c|/c)[\"'`]", "Command run through a shell."),
    lr(R_WEAK_HASH, GO, r"\b(?:md5|sha1)\.(?:New|Sum)\s*\(", "MD5/SHA-1 in use."),
    lr(R_RANDOM, GO, r"\brand\.(?:Int|Intn|Int63|Read|Uint32|Uint64)\s*\(", "math/rand used for a security value."),
    # ---- Java / Kotlin
    lr(R_SQLI, JAVA, r"\.(?:executeQuery|executeUpdate|execute|prepareStatement|createQuery|createNativeQuery|addBatch)\s*\(\s*(?:[\"'][^\"']*[\"']\s*\+|\w+\s*\+\s*[\"']|String\.format\()", "JDBC/JPA query concatenated."),
    lr(R_DESER, JAVA, r"new\s+ObjectInputStream\s*\(|\bXMLDecoder\b|enableDefaultTyping\s*\(|activateDefaultTyping\s*\(|new\s+Yaml\s*\(\s*\)", "Unsafe Java deserialization."),
    lr(R_CMD_INJ, JAVA, r"Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+", "Runtime.exec with a concatenated command."),
    lr(R_WEAK_CIPHER, JAVA, r"Cipher\.getInstance\(\s*\"(?:DES|DESede|RC2|RC4|Blowfish|AES)(?:\"|/ECB)", "Weak cipher, or AES defaulting to ECB."),
    lr(R_WEAK_HASH, JAVA, r"MessageDigest\.getInstance\(\s*\"(?:MD5|MD2|SHA-?1)\"", "MD5/SHA-1 in use."),
    lr(R_TLS, JAVA, r"NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier\([^)]*->\s*true|TrustAllCerts|trustAllCerts", "Hostname or certificate verification bypassed."),
    lr(R_CSRF, JAVA, r"csrf\(\)\s*\.disable\(\)|csrf\(\s*\w+\s*->\s*\w+\.disable\(\)\s*\)|csrf\(\s*AbstractHttpConfigurer::disable\s*\)", "Spring Security CSRF disabled."),
    lr(R_RANDOM, JAVA, r"new\s+(?:java\.util\.)?Random\s*\(", "java.util.Random for a security value."),
    # ---- PHP
    lr(R_CODE_INJ, PHP, r"(?<![\w>])(?:eval|assert|create_function)\s*\(", "Dynamic code evaluation."),
    lr(R_CMD_INJ, PHP, r"(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\([^;]*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)", "Shell command with request data."),
    lr(R_DESER, PHP, r"unserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)|unserialize\s*\(\s*base64_decode", "unserialize() on request data."),
    lr(R_SQLI, PHP, r"(?:mysqli_query|mysql_query|pg_query|->query|->exec)\s*\([^;]*\$_(?:GET|POST|REQUEST|COOKIE)", "SQL built with request data."),
    lr(R_PATH, PHP, r"(?:include|require)(?:_once)?\s*\(?\s*[^;]*\$_(?:GET|POST|REQUEST|COOKIE)", "include/require with request data (LFI/RFI)."),
    lr(R_XSS, PHP, r"(?:echo|print)\s+[^;]*\$_(?:GET|POST|REQUEST|COOKIE)", "Request data echoed without escaping.", unless=r"htmlspecialchars|htmlentities|esc_html"),
    lr(R_PWD_HASH, PHP, r"(?:md5|sha1|hash\(\s*[\"']sha\d+[\"']\s*,)\s*\(?\s*\$\w*pass", "Password hashed with a fast hash."),
    # ---- Ruby
    lr(R_CODE_INJ, RB, r"(?<![\w.])(?:eval|instance_eval|class_eval)\s*[\(\s][^#]*(?:params|#\{)", "eval on dynamic input."),
    lr(R_CMD_INJ, RB, r"(?:system|exec|spawn|`|%x\{)[^\n]*#\{[^}]*params", "Shell command with request data."),
    lr(R_DESER, RB, r"Marshal\.load|YAML\.(?:unsafe_)?load\s*\(", "Unsafe Ruby deserialization.", unless=r"safe_load|permitted_classes"),
    lr(R_SQLI, RB, r"\.(?:where|find_by_sql|order|group|having|joins|pluck|exists\?)\s*\(\s*[\"'][^\"']*#\{", "ActiveRecord query with interpolation."),
    lr(R_XSS, RB, r"\.html_safe\b|\braw\s*\(", "Output marked HTML-safe."),
    lr(R_MASS, RB, r"params\.permit!", "permit! allows every attribute."),
    # ---- uploads
    lr(R_UPLOAD, JS, r"\bmulter\s*\(\s*\)|\bmulter\s*\(\s*\{(?![^}]*(?:limits|fileFilter))[^}]*\}\s*\)", "multer configured without limits or fileFilter."),
    lr(R_UPLOAD, PY, r"\.save\s*\(\s*(?:os\.path\.join\([^)]*)?[^)]*\.filename\b", "Uploaded file saved under its client-supplied filename.", unless=r"secure_filename|uuid|token_hex"),
    lr(R_UPLOAD, PHP, r"move_uploaded_file\s*\([^,]+,\s*[^)]*\$_FILES\[[^\]]+\]\[[\"']name[\"']\]", "Upload stored under its client-supplied name."),
    # ---- C / C++
    lr(R_BANNED_C, C_CPP, r"(?<![\w.>])(?:gets|strcpy|strcat|sprintf|vsprintf|wcscpy|wcscat|stpcpy)\s*\(", "Unbounded copy/format function."),
    lr(R_BANNED_C, C_CPP, r"\bscanf\s*\(\s*\"[^\"]*%s", "scanf(\"%s\") without a field width."),
    # ---- C#
    lr(R_DESER, CS, r"\bBinaryFormatter\b|\bNetDataContractSerializer\b|\bLosFormatter\b|TypeNameHandling\.(?:All|Auto|Objects|Arrays)", "Unsafe .NET deserialization."),
    lr(R_SQLI, CS, r"new\s+SqlCommand\s*\(\s*(?:\$\"|[\"'][^\"']*[\"']\s*\+)", "SqlCommand text built dynamically."),
    lr(R_TLS, CS, r"ServerCertificateValidationCallback\s*=\s*[^;]*=>\s*true|ServerCertificateCustomValidationCallback\s*=\s*[^;]*=>\s*true|DangerousAcceptAnyServerCertificateValidator", "Certificate validation bypassed."),
]
_SECRET_CTX = re.compile(_SECRETY)
_SESSION_CTX = re.compile(r"(?i)sess|auth|token|jwt|\bsid\b|login|remember|refresh|csrf")

_REGEX_LITERAL = re.compile(r"(?:new\s+RegExp\(\s*[\"'`]|re\.(?:compile|match|search|fullmatch|findall|sub)\(\s*r?[\"']|(?<![\w)\]])/(?=[^/*\s]))((?:[^\"'`/\\\n]|\\.){3,200})")
_QUANT_GROUP = re.compile(r"\((?:\?:)?((?:[^()\\]|\\.)*)\)(?:[+*]|\{\d+,\})")
_LEADING_STAR = re.compile(r"^(?:\\.|\[(?:[^\]\\]|\\.)*\]|\.|[^\\()\[\]|^$])(?:[+*]|\{\d+,\})")


_ATOM = re.compile(r"\\.|\[(?:[^\]\\]|\\.)*\]|\.|[^\\()\[\]|^$+*?{}]")


def _atom_accepts(atom: str, ch: str) -> bool:
    """Rough membership test: can `atom` (a, \\w, [a-z], .) match character `ch`?"""
    if atom == ".":
        return ch != "\n"
    if atom.startswith("\\") and len(atom) == 2:
        k = atom[1]
        word = ch.isalnum() or ch == "_"
        return {"w": word, "W": not word, "d": ch.isdigit(), "D": not ch.isdigit(), "s": ch.isspace(), "S": not ch.isspace()}.get(k, ch == k)
    if atom.startswith("["):
        inner, neg = atom[1:-1], atom.startswith("[^")
        if neg:
            inner = inner[1:]
        hit = False
        i = 0
        while i < len(inner):
            if inner[i] == "\\" and i + 1 < len(inner):
                hit |= _atom_accepts(inner[i:i + 2], ch)
                i += 2
            elif i + 2 < len(inner) and inner[i + 1] == "-":
                hit |= inner[i] <= ch <= inner[i + 2]
                i += 3
            else:
                hit |= inner[i] == ch
                i += 1
        return hit != neg
    return atom == ch


_PROBES = "aZ_09 \t.-/@:,;|#&=+?!'\"<>()[]{}"


def _disjoint(a: str, b: str) -> bool:
    return not any(_atom_accepts(a, c) and _atom_accepts(b, c) for c in _PROBES)


def _catastrophic(pattern: str) -> bool:
    """Star height 2 where the inner repetition leads the group and nothing
    forces a split point: (a+)+, (\\w+\\s?)*, (.*)*. A group that ends in a
    mandatory separator its leading repetition cannot consume, like (\\w+\\.)*
    or (\\.[^.]+)+, has only one way to match and stays linear."""
    for m in _QUANT_GROUP.finditer(pattern):
        body = m.group(1)
        branches = body.split("|")
        if len(branches) > 1 and len(set(branches)) < len(branches):
            return True  # (a|a)* : duplicate alternatives
        lead = _LEADING_STAR.match(body)
        if not lead:
            continue
        atoms = [(a.group(0), a.end()) for a in _ATOM.finditer(body)]
        if not atoms:
            return True
        last, end = atoms[-1]
        trailing_quant = body[end:end + 1] in ("+", "*", "?", "{")
        lead_atom = _ATOM.match(body)
        if trailing_quant or lead_atom is None or len(atoms) == 1:
            return True
        if not _disjoint(lead_atom.group(0), last):
            return True
    return False


_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069\u200b-\u200f\u2060-\u2064\ufeff\U000e0000-\U000e007f]")


class CodeScanner:
    name = "code"

    def scan(self, ctx: ScanContext) -> Iterator[Finding]:
        for rel in ctx.by_suffix(*ALL_CODE):
            text = ctx.text(rel)
            if not text:
                continue
            if rel.endswith(PY):
                yield from PythonAnalyzer(rel, text).run()
            yield from self._line_rules(rel, text)
            yield from self._file_rules(rel, text)

    def _line_rules(self, rel: str, text: str) -> Iterator[Finding]:
        lower = rel.lower()
        applicable = [r for r in LINE_RULES if lower.endswith(r.suffixes)]
        if not applicable:
            return
        uses_math_rand = '"math/rand' in text
        applicable = [r for r in applicable if not (r.file_unless and r.file_unless.search(text))]
        all_lines = text.splitlines()
        for i, line in enumerate(all_lines, 1):
            if len(line) > 1500 or is_comment(line):
                continue
            for r in applicable:
                if not r.pattern.search(line):
                    continue
                if r.unless and r.unless.search(line):
                    continue
                if r.rule is R_RANDOM and not _SECRET_CTX.search(line):
                    continue
                if r.rule is R_RANDOM and lower.endswith(GO) and not uses_math_rand:
                    continue
                if r.rule is R_COOKIE and not _SESSION_CTX.search("\n".join(all_lines[max(0, i - 8): i + 3])):
                    continue
                yield Finding(r.rule, rel, i, r.message, snippet=line.strip()[:240])

    def _file_rules(self, rel: str, text: str) -> Iterator[Finding]:
        # Trojan Source / invisible characters
        for m in _BIDI.finditer(text):
            if m.group(0) == "\ufeff" and m.start() == 0:
                continue
            ln = line_of(text, m.start())
            yield Finding(R_BIDI, rel, ln, f"Invisible/bidi control character U+{ord(m.group(0)):04X}.", snippet=f"U+{ord(m.group(0)):04X}")
            break
        # ReDoS-prone literals
        for m in _REGEX_LITERAL.finditer(text):
            body = m.group(1)
            if _catastrophic(body):
                ln = line_of(text, m.start())
                yield Finding(R_REDOS, rel, ln, "Nested quantifier in a regular expression.", snippet=body[:120])
        if rel.endswith(JS) and re.search(r"(?:^|/)(?:api|routes?|server|controllers?|handlers?|app)/|\+(?:page\.)?server\.[jt]s$|route\.[jt]s$", rel):
            lines = text.splitlines()
            for i, line in enumerate(lines, 1):
                if re.search(r"\.(?:findById|findByPk|findUnique|findFirst|findOne|get|delete|update|findOneAndUpdate|findByIdAndUpdate|findByIdAndDelete|deleteOne|updateOne)\s*\([^)]*(?:req\.params|params)\.\w*[iI]d\b", line):
                    window = "\n".join(lines[max(0, i - 15): i + 10])
                    if not re.search(r"(?i)owner|user_?id\b|userId|session\.user|locals\.user|req\.user|request\.user|getSession|requireUser|tenant|org(?:anization)?_?Id|account_?id|createdBy|author_?id|can\(|authorize\(|assertOwner|ensureOwner", window):
                        yield Finding(R_IDOR, rel, i, "Lookup by a client-supplied id with no owner/session reference nearby.", snippet=line.strip()[:200])
        if rel.endswith(JS):
            # CORS: credentials with reflected/any origin, typically split across lines
            for m in re.finditer(r"origin\s*:\s*(?:true|[\"']\*[\"'])", text):
                window = text[max(0, m.start() - 300): m.end() + 300]
                if re.search(r"credentials\s*:\s*true", window):
                    yield Finding(R_CORS, rel, line_of(text, m.start()), "CORS allows any origin with credentials.",
                                  snippet=text[m.start(): m.end()])
            # message listener with no origin check anywhere in the file
            m = re.search(r"addEventListener\(\s*[\"']message[\"']", text)
            if m and ".origin" not in text:
                yield Finding(R_POSTMESSAGE, rel, line_of(text, m.start()), "message event handled without checking event.origin.",
                              snippet="addEventListener('message', ...)")
        if rel.endswith(JAVA) and re.search(r"(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory)\.newInstance\(", text) \
                and not re.search(r"disallow-doctype-decl|FEATURE_SECURE_PROCESSING|SUPPORT_DTD|ACCESS_EXTERNAL_DTD", text):
            m = re.search(r"(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory)\.newInstance\(", text)
            assert m
            yield Finding(R_XXE, rel, line_of(text, m.start()), "XML factory created without disabling DTDs.", snippet=m.group(0))


# ------------------------------------------------------------------ Python AST analysis

_PY_SQL_SINKS = {"execute", "executemany", "executescript", "raw", "mogrify", "extra"}
_PY_DESER = {
    ("pickle", "loads"), ("pickle", "load"), ("cPickle", "loads"), ("cPickle", "load"), ("dill", "loads"), ("dill", "load"),
    ("marshal", "loads"), ("marshal", "load"), ("shelve", "open"), ("jsonpickle", "decode"), ("yaml", "unsafe_load"),
    ("joblib", "load"), ("torch", "load"), ("pandas", "read_pickle"), ("pd", "read_pickle"),
}
_REQUESTS_FUNCS = {"get", "post", "put", "patch", "delete", "head", "request", "options"}


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        parts.append(_dotted(node.func) + "()")
    return ".".join(reversed(parts))


def _is_dynamic_str(node: ast.AST | None) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return isinstance(node.left, (ast.Constant, ast.JoinedStr, ast.BinOp)) or isinstance(node.right, (ast.Constant, ast.JoinedStr))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return isinstance(node.func.value, ast.Constant)
    return False


def _is_constant(node: ast.AST | None) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.JoinedStr):
        return not any(isinstance(v, ast.FormattedValue) for v in node.values)
    return False


def _touches_request(node: ast.AST | None) -> bool:
    if node is None:
        return False
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and _dotted(sub).split(".")[0] in ("request", "req"):
            return True
        if isinstance(sub, ast.Name) and sub.id in ("user_input", "user_url", "untrusted"):
            return True
    return False


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _kw_is(call: ast.Call, name: str, value: object) -> bool:
    v = _kw(call, name)
    return isinstance(v, ast.Constant) and v.value == value


class PythonAnalyzer(ast.NodeVisitor):
    def __init__(self, rel: str, text: str) -> None:
        self.rel = rel
        self.text = text
        self.lines = text.splitlines()
        self.out: list[Finding] = []
        self.is_settings = rel.endswith(("settings.py", "config.py")) or "/settings/" in rel

    def run(self) -> list[Finding]:
        try:
            tree = ast.parse(self.text, filename=self.rel)
        except (SyntaxError, ValueError):
            return []
        self.visit(tree)
        return self.out

    def add(self, r: Rule, node: ast.AST, message: str) -> None:
        ln = getattr(node, "lineno", 1)
        snippet = self.lines[ln - 1].strip()[:240] if 0 < ln <= len(self.lines) else ""
        self.out.append(Finding(r, self.rel, ln, message, snippet=snippet))

    def visit_Assign(self, node: ast.Assign) -> None:
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        names += [t.attr for t in node.targets if isinstance(t, ast.Attribute)]
        for name in names:
            v = node.value
            if self.is_settings and name == "DEBUG" and isinstance(v, ast.Constant) and v.value is True:
                self.add(R_DEBUG, node, "DEBUG = True in a settings module.")
            if self.is_settings and name in ("SESSION_COOKIE_SECURE", "CSRF_COOKIE_SECURE", "SESSION_COOKIE_HTTPONLY") \
                    and isinstance(v, ast.Constant) and v.value is False:
                self.add(R_COOKIE, node, f"{name} = False.")
            if name in ("CORS_ALLOW_ALL_ORIGINS", "CORS_ORIGIN_ALLOW_ALL") and isinstance(v, ast.Constant) and v.value is True:
                self.add(R_CORS, node, f"{name} = True accepts every origin.")
            if re.search(_SECRETY, name) and any(isinstance(s, ast.Call) and _dotted(s.func).startswith("random.") for s in ast.walk(v)):
                self.add(R_RANDOM, node, f"`{name}` generated with the random module.")
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for dec in node.decorator_list:
            name = _dotted(dec.func if isinstance(dec, ast.Call) else dec)
            if name.endswith("csrf_exempt"):
                self.add(R_CSRF, dec, f"@csrf_exempt on {node.name}().")
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Call(self, node: ast.Call) -> None:
        name = _dotted(node.func)
        short = name.split(".")[-1]
        mod = name.split(".")[0] if "." in name else ""
        arg0 = node.args[0] if node.args else None

        if name in ("eval", "exec") and arg0 is not None and not _is_constant(arg0):
            self.add(R_CODE_INJ, node, f"{name}() on a non-constant value.")
        if mod == "subprocess" or name in ("Popen", "check_output", "check_call"):
            if _kw_is(node, "shell", True):
                if _is_dynamic_str(arg0) or _touches_request(arg0):
                    self.add(R_CMD_INJ, node, "shell=True with an interpolated command.")
                else:
                    self.add(R_SHELL_TRUE, node, "subprocess call with shell=True.")
        if name in ("os.system", "os.popen", "commands.getoutput") and arg0 is not None and not _is_constant(arg0):
            self.add(R_CMD_INJ, node, f"{name}() with a non-constant command.")
        if (mod, short) in _PY_DESER or name in {f"{a}.{b}" for a, b in _PY_DESER}:
            if not (short == "load" and mod == "torch" and _kw_is(node, "weights_only", True)):
                self.add(R_DESER, node, f"{name}() can execute code embedded in the data.")
        if name in ("yaml.load", "yaml.load_all"):
            loader = _kw(node, "Loader") or (node.args[1] if len(node.args) > 1 else None)
            if loader is None or "Safe" not in _dotted(loader):
                self.add(R_DESER, node, "yaml.load without SafeLoader.")
        if short in _PY_SQL_SINKS and isinstance(node.func, ast.Attribute) and (_is_dynamic_str(arg0)):
            self.add(R_SQLI, node, f".{short}() with an interpolated SQL string.")
        if name in ("text", "sqlalchemy.text", "sa.text") and _is_dynamic_str(arg0):
            self.add(R_SQLI, node, "sqlalchemy text() with an interpolated string.")
        if _kw_is(node, "verify", False) and mod in ("requests", "httpx", "session", "client", "s", "aiohttp", ""):
            self.add(R_TLS, node, "verify=False disables certificate checks.")
        if name in ("ssl._create_unverified_context",) or (isinstance(node.func, ast.Attribute) and short == "_create_unverified_context"):
            self.add(R_TLS, node, "Unverified SSL context.")
        if name in ("hashlib.md5", "hashlib.sha1", "md5", "sha1") and not _kw_is(node, "usedforsecurity", False):
            arg_src = ast.unparse(arg0) if arg0 is not None else ""
            if re.search(r"(?i)passw", arg_src):
                self.add(R_PWD_HASH, node, f"Password hashed with {short}.")
            else:
                self.add(R_WEAK_HASH, node, f"{name}() in use.")
        if name in ("hashlib.sha256", "hashlib.sha512") and arg0 is not None and re.search(r"(?i)passw", ast.unparse(arg0)):
            self.add(R_PWD_HASH, node, f"Password hashed with {short}.")
        if mod in ("jwt",) and short == "decode":
            opts = _kw(node, "options")
            algs = _kw(node, "algorithms")
            if (opts is not None and re.search(r"verify_signature['\"]?\s*:\s*False", ast.unparse(opts))) or _kw_is(node, "verify", False):
                self.add(R_JWT, node, "jwt.decode with signature verification off.")
            if algs is not None and "none" in ast.unparse(algs).lower():
                self.add(R_JWT, node, "jwt.decode accepts the 'none' algorithm.")
        if short == "run" and _kw_is(node, "debug", True):
            self.add(R_DEBUG, node, "app.run(debug=True).")
        if name == "tempfile.mktemp" or name == "mktemp":
            self.add(R_TEMPFILE, node, "tempfile.mktemp() is race-prone.")
        if short == "Environment" and _kw_is(node, "autoescape", False):
            self.add(R_TEMPLATE, node, "Jinja2 autoescape=False.")
        if short in ("mark_safe", "Markup") and arg0 is not None and not _is_constant(arg0):
            self.add(R_TEMPLATE, node, f"{short}() on a dynamic value.")
        if short == "render_template_string" and arg0 is not None and not _is_constant(arg0):
            self.add(R_TEMPLATE, node, "render_template_string with a dynamic template (SSTI).")
        if mod in ("requests", "httpx", "urllib", "urllib.request", "aiohttp") or name == "urlopen":
            if (short in _REQUESTS_FUNCS or short == "urlopen") and _touches_request(arg0):
                self.add(R_SSRF, node, f"{name}() to a URL taken from the request.")
        if name in ("open", "send_file", "send_from_directory", "FileResponse", "os.remove", "shutil.rmtree") and _touches_request(arg0):
            self.add(R_PATH, node, f"{name}() with a path from the request.")
        if short == "redirect" and _touches_request(arg0):
            self.add(R_REDIRECT, node, "redirect() to a URL from the request.")
        if name in ("re.compile", "re.match", "re.search") and _touches_request(arg0):
            self.add(R_REGEX_INJ, node, "Regular expression built from request input.")
        if name in ("xml.etree.ElementTree.parse", "ET.parse", "ET.fromstring", "etree.parse", "etree.fromstring", "minidom.parse", "minidom.parseString", "xml.dom.minidom.parseString"):
            self.add(R_XXE, node, f"{name}() without defusedxml.")
        self.generic_visit(node)
