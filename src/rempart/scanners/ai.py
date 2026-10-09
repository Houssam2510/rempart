"""LLM application and AI-agent security, mapped to the OWASP Top 10 for LLM
Applications 2025 (LLMxx) and the OWASP Top 10 for Agentic Applications 2026
(ASIxx).

Covers the attack surface that grew fastest in 2025-2026: MCP server configs
auto-executed by IDEs (SANDWORM_MODE planted rogue MCP servers through npm),
unpinned `npx -y` servers that can turn hostile on the next release (rug
pull), invisible-Unicode instructions hidden in agent rule files, model
output flowing into code/HTML/SQL sinks, and agent tools that run shell
commands.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Iterator

from rempart.engine import ScanContext, is_comment
from rempart.models import Finding, Severity
from rempart.registry import A03, A05, A07, A08, C, H, L, M, rule

LLM01, LLM02, LLM05, LLM06, LLM07, LLM10 = (
    "LLM01:2025 Prompt Injection", "LLM02:2025 Sensitive Information Disclosure", "LLM05:2025 Improper Output Handling",
    "LLM06:2025 Excessive Agency", "LLM07:2025 System Prompt Leakage", "LLM10:2025 Unbounded Consumption",
)
LLM03 = "LLM03:2025 Supply Chain"
ASI01, ASI02, ASI03, ASI04, ASI05 = (
    "ASI01:2026 Agent Goal Hijack", "ASI02:2026 Tool Misuse & Exploitation", "ASI03:2026 Identity & Privilege Abuse",
    "ASI04:2026 Agentic Supply Chain", "ASI05:2026 Unexpected Code Execution",
)

R_MCP_UNPINNED = rule("AI-MCP-UNPINNED-SERVER", "MCP server launched from an unpinned package", H, "ai", cwe=("CWE-829", "CWE-494"), owasp=A03, frameworks=(ASI04, LLM03),
                      fix="Pin an exact version (`npx -y pkg@1.4.2`, `uvx pkg==1.4.2`) and review updates: a server that changes its tool descriptions after approval is a rug pull.")
R_MCP_SECRET = rule("AI-MCP-SECRET-IN-CONFIG", "Credential written in an MCP config", C, "ai", cwe="CWE-798", owasp=A07, frameworks=(ASI03,),
                    fix="Reference environment variables (`${GITHUB_TOKEN}`) and scope tokens to the minimum the server needs.")
R_MCP_HTTP = rule("AI-MCP-PLAINTEXT-TRANSPORT", "Remote MCP server over plain HTTP", M, "ai", cwe="CWE-319", owasp=A08, frameworks=(ASI04,),
                  fix="Use https:// for remote MCP servers; tool descriptions and results can be tampered with in transit.")
R_MCP_BROAD = rule("AI-MCP-BROAD-ACCESS", "MCP server given broad filesystem or shell access", M, "ai", cwe="CWE-250", owasp=A07, frameworks=(ASI02, ASI03, LLM06),
                   fix="Scope filesystem servers to the project directory and avoid generic shell/exec servers; a single prompt injection then reaches everything the server can.",
                   confidence=0.6)
R_HIDDEN = rule("AI-HIDDEN-INSTRUCTIONS", "Invisible Unicode in agent instructions or tool metadata", H, "ai", cwe=("CWE-1007", "CWE-451"), owasp=A08, frameworks=(ASI01, LLM01),
                fix="Remove zero-width, bidi and Unicode tag characters. They hide instructions the model reads but reviewers cannot see.")
R_SUSPICIOUS_RULES = rule("AI-INJECTED-RULE-FILE", "Agent instruction file contains exfiltration-style directives", H, "ai", cwe="CWE-94", owasp=A08, frameworks=(ASI01, LLM01),
                          fix="Review the file's history; instructions that read credentials or contact unknown hosts are a sign of a poisoned repository or package.",
                          confidence=0.6)
R_OUTPUT_SINK = rule("AI-OUTPUT-TO-SINK", "Model output flows into a code, shell, HTML or SQL sink", H, "ai", cwe=("CWE-94", "CWE-79", "CWE-89"), owasp=A05, frameworks=(LLM05, ASI05),
                     fix="Treat model output as untrusted input: validate against a schema, escape for the target context, never eval/exec it.",
                     confidence=0.6)
R_PROMPT_CONCAT = rule("AI-PROMPT-INJECTION-SURFACE", "Untrusted input concatenated into the system prompt", M, "ai", cwe="CWE-77", owasp=A05, frameworks=(LLM01, ASI01),
                       fix="Keep the system prompt static. Put user/retrieved content in a separate user message, delimit it, and never grant it authority over tools.",
                       confidence=0.5)
R_AGENT_SHELL = rule("AI-AGENT-SHELL-TOOL", "Agent tool executes shell commands or code", H, "ai", cwe=("CWE-78", "CWE-94"), owasp=A05, frameworks=(ASI05, ASI02, LLM06),
                     fix="Replace generic exec tools with narrow, typed tools. If execution is required, run it in an isolated sandbox (container/microVM) with no credentials and human approval.",
                     confidence=0.6)
R_NO_MAX_TOKENS = rule("AI-UNBOUNDED-GENERATION", "LLM call with no output limit", L, "performance", cwe=("CWE-770", "CWE-400"), frameworks=(LLM10,),
                       fix="Set max_tokens / max_output_tokens and a per-user rate limit so a single request cannot run up cost or latency.", confidence=0.4)
R_SECRET_IN_PROMPT = rule("AI-SECRET-IN-PROMPT", "Secret or credential placed in a prompt", H, "ai", cwe=("CWE-200", "CWE-532"), owasp=A07, frameworks=(LLM02, LLM07),
                          fix="System prompts leak. Keep keys in code paths the model cannot read and enforce authorization outside the model.", confidence=0.6)

# MCP client configs are matched by shape, not by product name: any *mcp*.json, any
# desktop-assistant config, and the settings files of IDE assistants.
MCP_FILES = re.compile(r"(?:^|/)(?:\.?[\w-]*mcp[\w-]*\.json|[\w-]*desktop_config\.json|\.[\w-]+/(?:mcp|settings|mcp_config)\.json)$")
# Assistant instruction files, also matched by shape so new assistants are covered:
# AGENTS.md and any other upper-case <NAME>.md that is not a standard project document,
# *rules dot-files, and agents/commands/skills/rules folders under any dot-directory
# (documentation folders excluded).
_STANDARD_DOCS = "README|LICENSE|LICENCE|CHANGELOG|CHANGES|HISTORY|CONTRIBUTING|SECURITY|CODE_OF_CONDUCT|AUTHORS|NOTICE|SUPPORT|GOVERNANCE|MAINTAINERS|TODO|ROADMAP|UPGRADING|MIGRATION|FAQ|INSTALL|USAGE"
AGENT_RULE_FILES = re.compile(
    r"^(?!(?:[^/]*/)*docs?/)(?:.*/)?(?:(?-i:(?!(?:" + _STANDARD_DOCS + r")\.md$)[A-Z]{3,15}\.md)|\.[\w-]*rules|copilot-instructions\.md"
    r"|\.[\w-]+/(?:rules|instructions)/[^/]+\.mdc?|\.[\w-]+/(?:agents|commands|skills|rules)/.+\.mdc?)$"
)
INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]")
# Directive-shaped text only: an action on a credential store followed by a transfer verb,
# an instruction override, or concealment from the user. Mentioning ".env" in prose is not enough.
EXFIL = re.compile(
    r"(?i)\b(?:read|cat|open|copy|collect|include|send|upload)\b[^\n]{0,40}(?:~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.npmrc|\.git-credentials|keychain|wallet|private key|seed phrase)"
    r"[^\n]{0,80}\b(?:send|post|upload|curl|exfiltrat\w*|transmit|webhook|to https?://)"
    r"|(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions"
    r"|(?:do not|don't|never)\s+(?:tell|mention|inform|reveal\s+(?:this\s+)?to)\s+the\s+user"
)

_LLM_OUT = r"(?:choices\[0\]\.message\.content|\.output_text|completion\.content|response\.content\[0\]\.text|\.text\(\)|result\.content|llm_output|model_output|ai_response|generated_code|completion\b)"
_SINKS = r"(?:\beval\s*\(|\bexec\s*\(|new\s+Function\s*\(|\.innerHTML\s*=|dangerouslySetInnerHTML|\{@html|v-html|subprocess\.|os\.system\(|child_process|execSync\(|\.execute\(|\$queryRawUnsafe\()"
LLM_CALL = re.compile(r"\b(?:chat\.completions\.create|responses\.create|messages\.create|generateContent|generateText|streamText|ChatCompletion\.create)\s*\(")


def _mcp_servers(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, dict):
        return {}
    for key in ("mcpServers", "servers", "mcp_servers"):
        v = doc.get(key)
        if isinstance(v, dict):
            return v
    mcp = doc.get("mcp")
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        return mcp["servers"]
    return {}


class AIScanner:
    name = "ai"

    def scan(self, ctx: ScanContext) -> Iterator[Finding]:
        for rel in ctx.files:
            if MCP_FILES.search(rel):
                yield from self.mcp(ctx, rel)
            if AGENT_RULE_FILES.search(rel) or MCP_FILES.search(rel):
                yield from self.instruction_file(ctx, rel)
            if rel.endswith((".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".svelte", ".vue")):
                yield from self.code(ctx, rel)

    def mcp(self, ctx: ScanContext, rel: str) -> Iterator[Finding]:
        text = ctx.text(rel) or ""
        try:
            doc = json.loads(text)
        except ValueError:
            return
        lines = text.splitlines()

        def ln(needle: str) -> int:
            return next((i for i, l in enumerate(lines, 1) if needle in l), 1)

        for name, srv in _mcp_servers(doc).items():
            if not isinstance(srv, dict):
                continue
            cmd = str(srv.get("command", ""))
            args = [str(a) for a in srv.get("args") or []]
            full = " ".join([cmd] + args)
            if os.path.basename(cmd) in ("npx", "bunx", "pnpx", "uvx", "pipx") or re.search(r"\b(?:npx|bunx|uvx|pnpm dlx|yarn dlx)\b", full):
                pkgs = [a for a in args if not a.startswith("-") and a not in ("dlx", "run", "exec")]
                pkg = pkgs[0] if pkgs else ""
                pinned = bool(re.search(r"@\d+\.\d+\.\d+|==\d+\.\d+", pkg))
                if pkg and not pinned:
                    yield Finding(R_MCP_UNPINNED, rel, ln(pkg), f"server `{name}` runs `{pkg}` at whatever version is published next.", snippet=full[:200])
            if re.search(r"(?:docker\s+run|podman\s+run)", full) and not re.search(r"@sha256:|:\d", full):
                yield Finding(R_MCP_UNPINNED, rel, ln(name), f"server `{name}` runs an unpinned container image.", snippet=full[:200], severity=Severity.MEDIUM)
            for k, v in (srv.get("env") or {}).items():
                sv = str(v)
                if re.search(r"(?i)token|secret|key|password|pat\b", str(k)) and sv and not sv.startswith(("${", "$", "<", "{{")) and len(sv) >= 12:
                    yield Finding(R_MCP_SECRET, rel, ln(str(k)), f"server `{name}` has {k} in plain text.", snippet=f'"{k}": "****"')
            for k, v in (srv.get("headers") or {}).items():
                if str(k).lower() in ("authorization", "x-api-key") and not str(v).startswith(("${", "Bearer ${")):
                    yield Finding(R_MCP_SECRET, rel, ln(str(k)), f"server `{name}` sends a literal {k} header.", snippet=f'"{k}": "****"')
            url = str(srv.get("url") or srv.get("serverUrl") or "")
            if url.startswith("http://") and not re.match(r"http://(?:localhost|127\.0\.0\.1|\[::1\])", url):
                yield Finding(R_MCP_HTTP, rel, ln(url), f"server `{name}` at {url}.", snippet=url)
            if re.search(r"server-filesystem\S*\s+(?:/|~|\$HOME|C:\\\\)\s*$|server-filesystem\S*\s+/(?:\s|$)", full) or re.search(r"(?i)mcp[-_]?(?:shell|exec|terminal|commands?)\b|desktop-commander", full):
                yield Finding(R_MCP_BROAD, rel, ln(name), f"server `{name}` reaches the whole filesystem or a shell.", snippet=full[:200])

    def instruction_file(self, ctx: ScanContext, rel: str) -> Iterator[Finding]:
        text = ctx.text(rel) or ""
        for m in INVISIBLE.finditer(text):
            if m.group(0) == "\ufeff" and m.start() == 0:
                continue
            count = len(INVISIBLE.findall(text))
            yield Finding(R_HIDDEN, rel, text.count("\n", 0, m.start()) + 1,
                          f"{count} invisible/bidi character(s), first U+{ord(m.group(0)):04X}.", snippet=f"U+{ord(m.group(0)):04X}")
            break
        for i, line in enumerate(text.splitlines(), 1):
            if EXFIL.search(line):
                yield Finding(R_SUSPICIOUS_RULES, rel, i, "Instruction reads secrets, overrides prior instructions, or hides actions from the user.", snippet=line.strip()[:200])

    def code(self, ctx: ScanContext, rel: str) -> Iterator[Finding]:
        text = ctx.text(rel) or ""
        if not re.search(r"(?i)openai|anthropic|langchain|llamaindex|@ai-sdk|ai/rsc|google\.genai|generativeai|ollama|mistral|litellm|bedrock|\bmcp\b|tool\(", text):
            return
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            if is_comment(line) or len(line) > 1500:
                continue
            if re.search(_LLM_OUT, line) and re.search(_SINKS, line):
                yield Finding(R_OUTPUT_SINK, rel, i, "LLM output reaches a dangerous sink on this line.", snippet=line.strip()[:200])
            if re.search(r"role[\"']?\s*:\s*[\"']system[\"']", line) or re.search(r"\bsystem(?:_prompt|Prompt)?\s*[=:]", line):
                window = " ".join(lines[i - 1:i + 3])
                if re.search(r"(?:\$\{|\{|\+\s*)\s*(?:req|request|body|input|user(?:Input|_input|Message|_message)?|query|params|message)\b", window) and re.search(r"`|f[\"']|\+|format\(", window):
                    yield Finding(R_PROMPT_CONCAT, rel, i, "System prompt built from request/user data.", snippet=line.strip()[:200])
                if re.search(r"(?i)(?:api[_-]?key|secret|password|token)\s*[:=]\s*[\"'`]?[A-Za-z0-9_\-]{12,}", window):
                    yield Finding(R_SECRET_IN_PROMPT, rel, i, "Prompt appears to contain a credential.", snippet=line.strip()[:120])
        # agent tools that execute commands
        for m in re.finditer(r"(?m)^\s*@(?:\w+\.)?tool\b.*\n(?:\s*@.*\n)*\s*(?:async\s+)?def\s+(\w+)\(.*?(?=^\s*(?:@|def |class )|\Z)", text, re.S):
            body = m.group(0)
            if re.search(r"subprocess\.|os\.system|os\.popen|\beval\(|\bexec\(", body):
                yield Finding(R_AGENT_SHELL, rel, text.count("\n", 0, m.start()) + 1, f"tool `{m.group(1)}` runs shell commands or evaluates code.", snippet=f"@tool def {m.group(1)}(...)")
        for m in re.finditer(r"tool\(\s*\{[\s\S]{0,1500}?execute\s*:\s*async[\s\S]{0,800}?(?:exec(?:Sync)?\(|spawn\(|eval\(|new Function\()", text):
            yield Finding(R_AGENT_SHELL, rel, text.count("\n", 0, m.start()) + 1, "AI SDK tool executes a shell command or code.", snippet="tool({ execute: ... exec(...) })")
        for m in LLM_CALL.finditer(text):
            window = text[m.end(): m.end() + 900]
            if not re.search(r"max_tokens|max_output_tokens|maxTokens|maxOutputTokens|max_completion_tokens", window):
                yield Finding(R_NO_MAX_TOKENS, rel, text.count("\n", 0, m.start()) + 1, "LLM request without an output token limit.", snippet=m.group(0))
