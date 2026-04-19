"""
NexusRE Vulnerability Scanner

Walks decompiled functions looking for dangerous code patterns:
- Unchecked memcpy/strcpy/sprintf (buffer overflows)
- Format string vulnerabilities
- Use-after-free patterns
- Integer overflow candidates
- Unvalidated pointer dereferences
- Hardcoded credentials/keys

Returns a severity-ranked report.
"""
import re
import logging

logger = logging.getLogger("NexusRE")

# ── Pattern Definitions ────────────────────────────────────────────────────────

VULN_PATTERNS = [
    # Critical — Buffer Overflows
    {
        "id": "BOF-001",
        "name": "Unchecked memcpy",
        "severity": "CRITICAL",
        "pattern": r'\bmemcpy\s*\([^)]*\)',
        "description": "memcpy without bounds checking — potential buffer overflow",
        "check_fn": lambda code, match: "sizeof" not in code[max(0,match.start()-100):match.end()+100]
    },
    {
        "id": "BOF-002",
        "name": "Unchecked strcpy",
        "severity": "CRITICAL",
        "pattern": r'\bstrcpy\s*\([^)]*\)',
        "description": "strcpy without length limit — use strncpy or strlcpy instead",
        "check_fn": None
    },
    {
        "id": "BOF-003",
        "name": "Unchecked sprintf",
        "severity": "CRITICAL",
        "pattern": r'\bsprintf\s*\([^)]*\)',
        "description": "sprintf without bounds — use snprintf instead",
        "check_fn": None
    },
    {
        "id": "BOF-004",
        "name": "gets() usage",
        "severity": "CRITICAL",
        "pattern": r'\bgets\s*\([^)]*\)',
        "description": "gets() is always exploitable — use fgets instead",
        "check_fn": None
    },
    {
        "id": "BOF-005",
        "name": "Stack buffer with loop write",
        "severity": "HIGH",
        "pattern": r'(char|BYTE|byte)\s+\w+\s*\[\s*\d+\s*\].*\bfor\s*\(',
        "description": "Fixed-size stack buffer with loop — potential overflow if loop unchecked",
        "check_fn": None
    },

    # High — Format Strings
    {
        "id": "FMT-001",
        "name": "Format string vulnerability",
        "severity": "HIGH",
        "pattern": r'\b(printf|fprintf|syslog|err|warn)\s*\(\s*[a-zA-Z_]\w*\s*\)',
        "description": "User-controlled format string — attacker can read/write stack",
        "check_fn": None
    },
    {
        "id": "FMT-002",
        "name": "snprintf with user-controlled format",
        "severity": "HIGH",
        "pattern": r'\bsnprintf\s*\([^,]+,[^,]+,\s*[a-zA-Z_]\w*\s*\)',
        "description": "snprintf with format arg from variable — check if user-controlled",
        "check_fn": None
    },

    # High — Memory Safety
    {
        "id": "UAF-001",
        "name": "Potential use-after-free",
        "severity": "HIGH",
        "pattern": r'\bfree\s*\([^)]+\).*?\b\1',
        "description": "Variable used after free() — potential use-after-free",
        "check_fn": None
    },
    {
        "id": "MEM-001",
        "name": "Unchecked malloc return",
        "severity": "MEDIUM",
        "pattern": r'=\s*\(?\s*\w+\s*\*?\s*\)?\s*malloc\s*\([^)]*\)',
        "description": "malloc() without NULL check — could dereference NULL",
        "check_fn": lambda code, match: "if" not in code[match.end():match.end()+80] and "NULL" not in code[match.end():match.end()+80]
    },
    {
        "id": "MEM-002",
        "name": "Double free potential",
        "severity": "HIGH",
        "pattern": r'\bfree\s*\(\s*(\w+)\s*\).*\bfree\s*\(\s*\1\s*\)',
        "description": "Same pointer freed twice — heap corruption",
        "check_fn": None
    },

    # Medium — Integer Issues
    {
        "id": "INT-001",
        "name": "Integer overflow in allocation",
        "severity": "MEDIUM",
        "pattern": r'\b(malloc|calloc|realloc)\s*\([^)]*\*[^)]*\)',
        "description": "Multiplication in allocation size — potential integer overflow",
        "check_fn": None
    },
    {
        "id": "INT-002",
        "name": "Signed/unsigned comparison",
        "severity": "LOW",
        "pattern": r'\b(int|long|short)\s+\w+.*[<>]=?\s*.*\b(unsigned|size_t|uint)',
        "description": "Signed vs unsigned comparison — may wrap unexpectedly",
        "check_fn": None
    },

    # Medium — Crypto/Secrets
    {
        "id": "SEC-001",
        "name": "Hardcoded key/password",
        "severity": "MEDIUM",
        "pattern": r'(password|passwd|secret|key|token|api_key)\s*=\s*["\'][^"\']{4,}["\']',
        "description": "Hardcoded credential or key in binary",
        "check_fn": None
    },
    {
        "id": "SEC-002",
        "name": "XOR with constant (weak crypto)",
        "severity": "LOW",
        "pattern": r'\^=?\s*(0x[0-9a-fA-F]{2,}|\d{2,})',
        "description": "XOR with constant — likely weak/custom encryption",
        "check_fn": None
    },
    {
        "id": "SEC-003",
        "name": "Hardcoded IP/URL",
        "severity": "MEDIUM",
        "pattern": r'["\']https?://[^"\']+["\']|["\'](\d{1,3}\.){3}\d{1,3}["\']',
        "description": "Hardcoded URL or IP address — potential C2 or exfil endpoint",
        "check_fn": None
    },

    # Low — Code Quality
    {
        "id": "QUA-001",
        "name": "Unrestricted system() call",
        "severity": "HIGH",
        "pattern": r'\bsystem\s*\([^)]*\)',
        "description": "system() call — potential command injection if input is user-controlled",
        "check_fn": None
    },
    {
        "id": "QUA-002",
        "name": "Dangerous exec family",
        "severity": "HIGH",
        "pattern": r'\b(execl|execle|execlp|execv|execve|execvp)\s*\(',
        "description": "exec() family call — spawns new process, check for command injection",
        "check_fn": None
    },
]

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def scan_function(func_name: str, func_address: str, decompiled_code: str) -> list:
    """Scan a single decompiled function for vulnerability patterns."""
    findings = []
    if not decompiled_code or len(decompiled_code) < 10:
        return findings

    for vuln in VULN_PATTERNS:
        try:
            for match in re.finditer(vuln["pattern"], decompiled_code, re.DOTALL | re.IGNORECASE):
                # If there's a custom check function, run it
                if vuln.get("check_fn"):
                    if not vuln["check_fn"](decompiled_code, match):
                        continue

                # Find the line number
                line_no = decompiled_code[:match.start()].count('\n') + 1
                snippet = decompiled_code[max(0, match.start()-20):match.end()+20].strip()
                if len(snippet) > 100:
                    snippet = snippet[:100] + "..."

                findings.append({
                    "id": vuln["id"],
                    "name": vuln["name"],
                    "severity": vuln["severity"],
                    "function": func_name,
                    "address": func_address,
                    "line": line_no,
                    "snippet": snippet,
                    "description": vuln["description"]
                })
        except Exception:
            continue

    return findings


def generate_report(all_findings: list) -> dict:
    """Generate a severity-ranked vulnerability report."""
    # Sort by severity
    all_findings.sort(key=lambda x: SEVERITY_RANK.get(x["severity"], 99))

    # Count by severity
    counts = {}
    for f in all_findings:
        sev = f["severity"]
        counts[sev] = counts.get(sev, 0) + 1

    # Group by function
    by_function = {}
    for f in all_findings:
        fname = f["function"]
        if fname not in by_function:
            by_function[fname] = []
        by_function[fname].append(f)

    return {
        "total_findings": len(all_findings),
        "by_severity": counts,
        "findings": all_findings[:100],  # Cap at 100 for readability
        "functions_with_issues": len(by_function),
        "hotspots": sorted(
            [{"function": k, "count": len(v), "worst_severity": v[0]["severity"]}
             for k, v in by_function.items()],
            key=lambda x: (SEVERITY_RANK.get(x["worst_severity"], 99), -x["count"])
        )[:20]
    }
