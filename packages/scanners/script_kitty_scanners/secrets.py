import re
import os
from typing import List, Dict, Any


class SecretScanner:
    """Scans codebases and configurations for hardcoded secrets, API keys, and private tokens."""

    PATTERNS = {
        "AWS Access Key": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        "OpenAI / Provider Secret Key": r"\bsk-(?:proj-|ant-api\d+-)?[A-Za-z0-9_-]{16,}\b",
        "Generic Secret Token": r"(?i)\b(?:secret|password|passwd|api_key|token|auth_secret)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
        "Private Key Header": r"-----BEGIN\s+(?:(?:RSA|EC|DSA|OPENSSH)\s+)?PRIVATE KEY-----",
        "GitHub Personal Access Token": r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b",
        "Slack Bot Token": r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
    }

    IGNORED_DIRS = {".git", "node_modules", "dist", "target", "venv", ".venv", "__pycache__"}

    @staticmethod
    def _redact_match(value: str) -> str:
        if len(value) <= 8:
            return "[REDACTED]"
        return f"{value[:4]}...{value[-4:]}"

    def scan_content(self, content: str, file_path: str = "<memory>") -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        norm_path = file_path.replace("\\", "/")

        for line_idx, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//")):
                continue
            # Ignore placeholders that already read from environment variables
            if "os.environ" in stripped or "process.env" in stripped:
                continue
            for secret_type, pattern in self.PATTERNS.items():
                match = re.search(pattern, line)
                if match:
                    redacted = self._redact_match(match.group(0))
                    findings.append({
                        "finding_id": f"SK-SECRET-{len(findings)+1:03d}",
                        "cwe_id": "CWE-798",
                        "category": "Hardcoded Secret / Credential Leak",
                        "severity": "HIGH",
                        "file": norm_path,
                        "line": line_idx,
                        "type": secret_type,
                        "redacted_preview": redacted,
                        "evidence": f"Potential {secret_type} detected on line {line_idx} ({redacted})",
                        "remediation": "Move secrets to environment variables or secret vaults (AWS Secrets Manager, HashiCorp Vault).",
                        "recheck_plan": f"script-kitty scan-secrets {norm_path}",
                    })
                    break
        return findings

    def scan_directory(self, root_dir: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        if os.path.isfile(root_dir):
            try:
                with open(root_dir, "r", encoding="utf-8", errors="ignore") as f:
                    return self.scan_content(f.read(), os.path.basename(root_dir))
            except Exception:
                return []

        for root, dirs, files in os.walk(root_dir):
            dirs[:] = [d for d in dirs if d not in self.IGNORED_DIRS]
            for file in sorted(files):
                filepath = os.path.join(root, file)
                rel_path = os.path.relpath(filepath, root_dir).replace("\\", "/")
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        for item in self.scan_content(f.read(), rel_path):
                            item["finding_id"] = f"SK-SECRET-{len(findings)+1:03d}"
                            findings.append(item)
                except Exception:
                    continue
        return findings
