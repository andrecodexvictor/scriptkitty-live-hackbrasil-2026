import os
import re
from typing import List, Dict, Any, Optional


class CodeVulnerabilityScanner:
    """Static Application Security Testing (SAST) engine for code vulnerability discovery."""

    # Security rules for code pattern detection across languages
    RULES = [
        {
            "id": "SK-SAST-001",
            "cwe_id": "CWE-78",
            "category": "Command Injection",
            "severity": "HIGH",
            "pattern": (
                r"(os\.system\(|subprocess\.(?:Popen|run|call)\(.*shell\s*=\s*True|"
                r"eval\(|exec\(|child_process\.exec\(|execSync\()"
            ),
            "description": "Potentially unsafe command execution or dynamic code evaluation.",
            "remediation": "Avoid passing raw untrusted strings to shell execution functions. Use parameterized argument arrays with shell=False."
        },
        {
            "id": "SK-SAST-002",
            "cwe_id": "CWE-89",
            "category": "SQL Injection",
            "severity": "HIGH",
            "pattern": (
                r"(SELECT\s+.*\s+FROM\s+.*(?:(?:\+|%|\.format\(|\$\{).*)|"
                r"f['\"]\s*SELECT\s+.*\s+FROM\s+.*\{|"
                r"(?:db\.query|cursor\.execute)\(.*(?:['\"].*\+|f['\"].*\{))"
            ),
            "description": "SQL query built via raw string concatenation or interpolation.",
            "remediation": "Use parameterized queries, prepared statements, or ORM abstraction layers."
        },
        {
            "id": "SK-SAST-003",
            "cwe_id": "CWE-327",
            "category": "Insecure Cryptography / Hash",
            "severity": "MEDIUM",
            "pattern": r"(hashlib\.md5\(|hashlib\.sha1\(|crypto\.createHash\(['\"]md5['\"]|crypto\.createHash\(['\"]sha1['\"])",
            "description": "Use of broken/weak cryptographic hash algorithms (MD5 or SHA-1).",
            "remediation": "Upgrade to secure hashing algorithms such as SHA-256, SHA-512, or Argon2 / bcrypt for credentials."
        },
        {
            "id": "SK-SAST-004",
            "cwe_id": "CWE-22",
            "category": "Path Traversal Risk",
            "severity": "MEDIUM",
            "pattern": r"(open\(.*req\.(?:query|params|body)|fs\.readFile\(.*req\.)",
            "description": "File system access using unsanitized request input.",
            "remediation": "Validate path against allowlists and resolve relative paths securely using path.resolve / os.path.realpath."
        },
        {
            "id": "SK-SAST-005",
            "cwe_id": "CWE-942",
            "category": "Overly Permissive CORS",
            "severity": "LOW",
            "pattern": r"Access-Control-Allow-Origin['\"]\s*:\s*['\"]\*",
            "description": "Access-Control-Allow-Origin set to wildcard '*'.",
            "remediation": "Restrict CORS origin allowlist to explicit trusted domains."
        }
    ]

    SCANNED_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".php", ".rs", ".java", ".c", ".cpp"}
    IGNORED_DIRS = {".git", "node_modules", "dist", "target", "venv", ".venv", "__pycache__"}

    def scan_content(self, content: str, file_path: str = "<memory>") -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        norm_path = file_path.replace("\\", "/")

        for line_num, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//")):
                continue
            for rule in self.RULES:
                if re.search(rule["pattern"], line):
                    findings.append({
                        "finding_id": f"{rule['id']}-{len(findings)+1:03d}",
                        "cwe_id": rule["cwe_id"],
                        "category": rule["category"],
                        "severity": rule["severity"],
                        "file": norm_path,
                        "line": line_num,
                        "snippet": stripped[:120],
                        "description": rule["description"],
                        "remediation": rule["remediation"],
                        "recheck_plan": f"script-kitty scan-code {norm_path}"
                    })
        return findings

    def scan_file(self, filepath: str, root_dir: Optional[str] = None) -> List[Dict[str, Any]]:
        rel_path = os.path.relpath(filepath, root_dir) if root_dir else filepath
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return []
        return self.scan_content(content, rel_path)

    def scan_workspace(self, root_dir: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        if os.path.isfile(root_dir):
            return self.scan_file(root_dir, os.path.dirname(root_dir) or ".")

        for root, dirs, files in os.walk(root_dir):
            dirs[:] = [d for d in dirs if d not in self.IGNORED_DIRS]
            for file in sorted(files):
                ext = os.path.splitext(file)[1].lower()
                if ext in self.SCANNED_EXTENSIONS:
                    filepath = os.path.join(root, file)
                    rel_path = os.path.relpath(filepath, root_dir).replace("\\", "/")
                    for item in self.scan_file(filepath, root_dir):
                        item["finding_id"] = f"{item['finding_id'].rsplit('-', 1)[0]}-{len(findings)+1:03d}"
                        item["file"] = rel_path
                        findings.append(item)
        return findings
