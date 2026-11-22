from typing import Dict, Any, List
from urllib.parse import urlparse
import urllib.request

try:
    import requests
except ImportError:  # pragma: no cover - stdlib fallback when requests is absent
    requests = None  # type: ignore[assignment]


BLOCKED_IMDS_HOSTS = {
    "169.254.169.254",
    "169.254.169.253",
    "169.254.170.2",
    "100.100.100.200",
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
}


class HeaderSecurityScanner:
    """Evaluates security headers and SSL configuration of HTTP endpoints."""

    RECOMMENDED_HEADERS = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'",
        "X-Permitted-Cross-Domain-Policies": "none",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }

    def evaluate_headers(self, target_url: str) -> Dict[str, Any]:
        parsed = urlparse(target_url)
        scheme = (parsed.scheme or "").lower()
        hostname = (parsed.hostname or "").lower()

        if scheme not in {"http", "https"}:
            return {
                "status": "BLOCKED",
                "error": f"Unsupported or unsafe URL scheme '{scheme}'",
                "findings": [],
            }

        if hostname in BLOCKED_IMDS_HOSTS or hostname.startswith("169.254."):
            return {
                "status": "BLOCKED",
                "error": f"Blocked SSRF/IMDS host '{hostname}'",
                "findings": [],
            }

        findings: List[Dict[str, Any]] = []
        try:
            headers = self._fetch_headers(target_url)
            normalized_headers = {k.lower(): v for k, v in headers.items()}

            for header_name, expected in self.RECOMMENDED_HEADERS.items():
                if header_name.lower() not in normalized_headers:
                    findings.append({
                        "finding_id": f"SK-HDR-{len(findings)+1:03d}",
                        "category": "Insecure HTTP Headers",
                        "cwe_id": "CWE-693",
                        "severity": "MEDIUM",
                        "target": target_url,
                        "missing_header": header_name,
                        "recommended_value": expected,
                        "evidence": f"Header '{header_name}' is absent from server response.",
                        "remediation": f"Configure web server to include '{header_name}: {expected}'.",
                        "recheck_plan": f"curl -I {target_url}",
                    })
        except Exception as e:
            return {"status": "ERROR", "error": str(e), "findings": []}

        return {
            "status": "COMPLETED",
            "target": target_url,
            "missing_headers_count": len(findings),
            "findings": findings,
        }

    def _fetch_headers(self, target_url: str) -> Dict[str, str]:
        if requests is not None:
            response = requests.head(target_url, timeout=5, allow_redirects=True)
            return dict(response.headers)

        req = urllib.request.Request(target_url, method="HEAD")
        with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310 - scheme/IMDS checked above
            return dict(resp.headers.items())
