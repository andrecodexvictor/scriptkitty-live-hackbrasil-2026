"""Script Kitty Agent Runtime — 5-Stage PREVC Security Workflow & Custody Engine.

Implements:
1. 5-stage PREVC lifecycle: Plan -> Reproduce -> Execute-Fix -> Verify -> Certify.
2. Integration with ``script_kitty_scanners``, ``AIGuardrailValidator``, and
   ``PatchCatRemediationEngine`` (always preserving ``auto_apply_allowed=False``).
3. Tri-Party Separation of Duties (A_discoverer != A_verifier != A_authorizer),
   raising ``SeparationOfDutiesError`` on any identity collision or self-certification.
4. RFC 8785 canonical SHA-256 hash chaining & binary Merkle custody proof tree.
"""

from __future__ import annotations

import hashlib
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

# Ensure sibling workspace packages are importable even without editable pip install
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_PACKAGES_ROOT = os.path.abspath(os.path.join(_CURRENT_DIR, "..", ".."))
for _subpkg in ("scanners", "validators", "remediation", "plugin_sdk", "agent_runtime"):
    _candidate = os.path.join(_PACKAGES_ROOT, _subpkg)
    if os.path.isdir(_candidate) and _candidate not in sys.path:
        sys.path.insert(0, _candidate)

try:
    from pydantic import BaseModel
except ImportError:  # pragma: no cover - stdlib fallback when pydantic is absent
    from script_kitty_plugin_sdk import BaseModel  # type: ignore[no-redef]

from script_kitty_remediation.patcher import PatchCatRemediationEngine
from script_kitty_scanners.code_vulnerabilities import CodeVulnerabilityScanner
from script_kitty_scanners.headers import HeaderSecurityScanner
from script_kitty_scanners.secrets import SecretScanner
from script_kitty_validators.guardrails import (
    AIGuardrailValidator,
    compute_rfc8785_digest,
)

GENESIS_HASH = "GENESIS_" + ("0" * 64)
EMPTY_MERKLE_ROOT = "0" * 64


class SeparationOfDutiesError(ValueError):
    """Raised when Tri-Party Separation of Duties invariants are violated."""

    def __init__(self, message: str, violation_codes: Sequence[str] = ()) -> None:
        super().__init__(message)
        self.violation_codes = list(violation_codes)


class AuditLogItem(BaseModel):
    index: int
    timestamp: str
    stage: str = "AUDIT"
    agent_id: str
    action: str
    target: str
    payload: str
    policy_status: str
    previous_hash: str
    hash: str
    canonical_digest: str = ""


def _hash_merkle_pair(left_hex: str, right_hex: str) -> str:
    return hashlib.sha256((left_hex + right_hex).encode("utf-8")).hexdigest()


def compute_merkle_root(leaf_hashes: Sequence[str]) -> str:
    """Computes a deterministic binary SHA-256 Merkle root over hex leaf hashes."""
    if not leaf_hashes:
        return EMPTY_MERKLE_ROOT
    level = list(leaf_hashes)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level: List[str] = []
        for idx in range(0, len(level), 2):
            next_level.append(_hash_merkle_pair(level[idx], level[idx + 1]))
        level = next_level
    return level[0]


def generate_merkle_proof(leaf_hashes: Sequence[str], index: int) -> List[Dict[str, str]]:
    """Builds a binary Merkle inclusion proof for ``leaf_hashes[index]``."""
    if not leaf_hashes:
        raise ValueError("Cannot generate Merkle proof for an empty leaf list")
    if index < 0 or index >= len(leaf_hashes):
        raise IndexError(f"Leaf index {index} out of bounds for {len(leaf_hashes)} leaves")

    proof: List[Dict[str, str]] = []
    level = list(leaf_hashes)
    cur_idx = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        is_right_child = (cur_idx % 2) == 1
        sibling_idx = cur_idx - 1 if is_right_child else cur_idx + 1
        proof.append(
            {
                "position": "left" if is_right_child else "right",
                "hash": level[sibling_idx],
            }
        )
        next_level: List[str] = []
        for i in range(0, len(level), 2):
            next_level.append(_hash_merkle_pair(level[i], level[i + 1]))
        level = next_level
        cur_idx //= 2
    return proof


def verify_merkle_proof(
    leaf_hash: str,
    proof: Sequence[Mapping[str, str]],
    expected_root: str,
) -> bool:
    """Verifies a binary Merkle inclusion proof against ``expected_root``."""
    current = leaf_hash
    for step in proof:
        sibling = step.get("hash", "")
        position = step.get("position", "")
        if position == "left":
            current = _hash_merkle_pair(sibling, current)
        elif position == "right":
            current = _hash_merkle_pair(current, sibling)
        else:
            return False
    return current == expected_root


def _compute_entry_hash(entry_dict: Mapping[str, Any]) -> str:
    canonical_body = {
        "index": entry_dict["index"],
        "timestamp": entry_dict["timestamp"],
        "stage": entry_dict.get("stage", "AUDIT"),
        "agent_id": entry_dict["agent_id"],
        "action": entry_dict["action"],
        "target": entry_dict["target"],
        "payload": entry_dict["payload"],
        "policy_status": entry_dict["policy_status"],
        "previous_hash": entry_dict["previous_hash"],
    }
    return compute_rfc8785_digest(canonical_body)


def verify_custody_chain(
    entries: Sequence[Union[AuditLogItem, Mapping[str, Any]]],
    expected_merkle_root: Optional[str] = None,
) -> Dict[str, Any]:
    """Cryptographically verifies hash links, canonical entry digests, and Merkle root."""
    if not entries:
        valid_empty = expected_merkle_root in (None, EMPTY_MERKLE_ROOT)
        return {
            "valid": valid_empty,
            "entry_count": 0,
            "merkle_root": EMPTY_MERKLE_ROOT,
            "error": None if valid_empty else "Empty chain does not match non-empty Merkle root",
        }

    prev_hash = GENESIS_HASH
    leaf_hashes: List[str] = []
    for expected_idx, raw_entry in enumerate(entries):
        if isinstance(raw_entry, Mapping):
            entry = dict(raw_entry)
        elif hasattr(raw_entry, "model_dump"):
            entry = raw_entry.model_dump()
        elif hasattr(raw_entry, "dict"):
            entry = raw_entry.dict()
        else:
            entry = vars(raw_entry)

        if entry.get("index") != expected_idx:
            return {
                "valid": False,
                "entry_count": len(entries),
                "merkle_root": "",
                "error": f"Index discontinuity at position {expected_idx}: got {entry.get('index')}",
            }
        if entry.get("previous_hash") != prev_hash:
            return {
                "valid": False,
                "entry_count": len(entries),
                "merkle_root": "",
                "error": f"Previous hash mismatch at index {expected_idx}",
            }

        recomputed_hash = _compute_entry_hash(entry)
        if entry.get("hash") != recomputed_hash:
            return {
                "valid": False,
                "entry_count": len(entries),
                "merkle_root": "",
                "error": f"Entry digest mismatch (tampered payload) at index {expected_idx}",
            }
        prev_hash = recomputed_hash
        leaf_hashes.append(recomputed_hash)

    computed_root = compute_merkle_root(leaf_hashes)
    if expected_merkle_root is not None and computed_root != expected_merkle_root:
        return {
            "valid": False,
            "entry_count": len(entries),
            "merkle_root": computed_root,
            "error": f"Merkle root mismatch: expected {expected_merkle_root}, got {computed_root}",
        }

    return {
        "valid": True,
        "entry_count": len(entries),
        "merkle_root": computed_root,
        "error": None,
    }


class SeparationOfDutiesValidator:
    """Enforces Tri-Party Separation of Duties: A_disc != A_veri != A_auth."""

    @staticmethod
    def validate(
        discoverer_id: str,
        verifier_id: str,
        authorizer_id: str,
        *,
        raise_on_violation: bool = True,
    ) -> Dict[str, Any]:
        disc = (discoverer_id or "").strip()
        veri = (verifier_id or "").strip()
        auth = (authorizer_id or "").strip()

        violations: List[str] = []
        if not disc or not veri or not auth:
            violations.append("SOD_MISSING_IDENTITY")
        if disc and veri and disc == veri:
            violations.append("SOD_DISCOVERER_VERIFIER_COLLISION")
        if veri and auth and veri == auth:
            violations.append("SOD_VERIFIER_AUTHORIZER_COLLISION")
        if disc and auth and disc == auth:
            violations.append("SOD_DISCOVERER_AUTHORIZER_COLLISION")

        valid = len(violations) == 0 and len({disc, veri, auth}) == 3
        if not valid and raise_on_violation:
            raise SeparationOfDutiesError(
                "Tri-Party Separation of Duties violation ("
                + ", ".join(violations or ["SOD_IDENTITY_COLLISION"])
                + "): discoverer, verifier, and authorizer must be strictly distinct.",
                violation_codes=violations,
            )

        return {
            "valid": valid,
            "discoverer_id": disc,
            "verifier_id": veri,
            "authorizer_id": auth,
            "violation_codes": violations,
        }


def _infer_cwe_from_finding(finding: Mapping[str, Any]) -> Optional[str]:
    cwe = str(finding.get("cwe_id", "")).upper()
    if cwe in ("CWE-89", "CWE-78", "CWE-639", "CWE-798"):
        return cwe
    ftype = str(finding.get("type", "")).upper()
    if "SQL" in ftype:
        return "CWE-89"
    if "COMMAND" in ftype or "OS_COMMAND" in ftype or "EXEC" in ftype:
        return "CWE-78"
    if "IDOR" in ftype or "ACCESS" in ftype:
        return "CWE-639"
    if "SECRET" in ftype or "KEY" in ftype or "TOKEN" in ftype or "AWS" in ftype or "GITHUB" in ftype or "OPENAI" in ftype:
        return "CWE-798"
    return None


class ScriptKittyAgentRuntime:
    """Deterministic 5-stage PREVC security runtime with SoD & Merkle custody."""

    STAGES = ("PLAN", "REPRODUCE", "EXECUTE_FIX", "VERIFY", "CERTIFY")

    def __init__(
        self,
        workspace_root: str,
        *,
        discoverer_id: str = "agent-discoverer",
        verifier_id: str = "agent-verifier",
        authorizer_id: str = "human-authorizer",
        pinned_tools: Optional[Mapping[str, str]] = None,
    ) -> None:
        self.workspace_root = os.path.abspath(workspace_root)
        self.default_discoverer_id = discoverer_id
        self.default_verifier_id = verifier_id
        self.default_authorizer_id = authorizer_id

        self.guardrail = AIGuardrailValidator(
            workspace_root=self.workspace_root,
            pinned_tools=pinned_tools,
        )
        self.patcher = PatchCatRemediationEngine()
        self.code_scanner = CodeVulnerabilityScanner()
        self.secret_scanner = SecretScanner()
        self.header_scanner = HeaderSecurityScanner()

        self.audit_log: List[AuditLogItem] = []
        self.last_hash = GENESIS_HASH
        self.merkle_root = EMPTY_MERKLE_ROOT

    def validate_policy(
        self,
        target: str,
        action: str,
        is_state_changing: bool,
        *,
        prompt: Optional[str] = None,
        arguments: Optional[Any] = None,
        tool_definition: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Evaluates scope boundaries, AI guardrails, and lab-authorization rules."""
        is_http = target.lower().startswith(("http://", "https://"))
        resource_paths = None if is_http else [target]

        guardrail_res = self.guardrail.evaluate(
            prompt=prompt,
            tool_name=action,
            tool_definition=tool_definition,
            arguments=arguments if arguments is not None else {"target": target, "action": action},
            resource_paths=resource_paths,
        )

        if guardrail_res["verdict"] == "BLOCKED":
            return {
                "allowed": False,
                "status": "BLOCKED",
                "reason": "Blocked by AIGuardrailValidator: "
                + ", ".join(guardrail_res["violation_codes"]),
                "violation_codes": guardrail_res["violation_codes"],
                "requires_human_approval": True,
                "guardrail": guardrail_res,
            }

        lowered_target = target.lower()
        if any(blocked in lowered_target for blocked in (".gov", ".mil")):
            return {
                "allowed": False,
                "status": "BLOCKED",
                "reason": "Scope Enforcement Failed: Public-sector domains (.gov/.mil) are strictly forbidden.",
                "violation_codes": ["FORBIDDEN_TARGET_SCOPE"],
                "requires_human_approval": True,
                "guardrail": guardrail_res,
            }

        if is_state_changing:
            return {
                "allowed": True,
                "status": "APPROVED_REQUIRES_SIGN_OFF",
                "reason": "Action allowed within lab scope; automatic patch/state apply remains disabled pending human sign-off.",
                "violation_codes": [],
                "requires_human_approval": True,
                "guardrail": guardrail_res,
            }

        return {
            "allowed": True,
            "status": "APPROVED",
            "reason": "Read-only inspection allowed within lab scope.",
            "violation_codes": [],
            "requires_human_approval": False,
            "guardrail": guardrail_res,
        }

    def append_audit_entry(
        self,
        agent_id: str,
        action: str,
        target: str,
        payload: Any,
        policy_status: str,
        *,
        stage: str = "AUDIT",
    ) -> AuditLogItem:
        """Appends a tamper-evident RFC 8785 + SHA-256 entry and updates Merkle root."""
        index = len(self.audit_log)
        timestamp = datetime.now(timezone.utc).isoformat()
        payload_str = (
            payload if isinstance(payload, str) else compute_rfc8785_digest(payload)
        )
        entry_fields = {
            "index": index,
            "timestamp": timestamp,
            "stage": stage,
            "agent_id": agent_id,
            "action": action,
            "target": target,
            "payload": payload_str,
            "policy_status": policy_status,
            "previous_hash": self.last_hash,
        }
        entry_hash = _compute_entry_hash(entry_fields)
        entry = AuditLogItem(
            **entry_fields,
            hash=entry_hash,
            canonical_digest=entry_hash,
        )
        self.audit_log.append(entry)
        self.last_hash = entry_hash
        self.merkle_root = compute_merkle_root([item.hash for item in self.audit_log])
        return entry

    def _resolve_target_path(self, target: str) -> str:
        if os.path.isabs(target):
            return os.path.realpath(target)
        return os.path.realpath(os.path.join(self.workspace_root, target))

    def _collect_target_files(self, resolved_target: str) -> List[str]:
        if os.path.isfile(resolved_target):
            return [resolved_target]
        if os.path.isdir(resolved_target):
            files: List[str] = []
            for root, dirs, filenames in os.walk(resolved_target):
                dirs[:] = sorted(
                    d
                    for d in dirs
                    if d not in {"node_modules", ".git", "__pycache__", "dist", ".venv"}
                )
                for fn in sorted(filenames):
                    files.append(os.path.join(root, fn))
            return files
        return []

    def run_prevc_workflow(
        self,
        target: str,
        mode: str = "Audit",
        *,
        discoverer_id: Optional[str] = None,
        verifier_id: Optional[str] = None,
        authorizer_id: Optional[str] = None,
        prompt: Optional[str] = None,
        tool_definition: Optional[Mapping[str, Any]] = None,
        is_state_changing: bool = False,
        enable_network_header_scan: bool = False,
    ) -> Dict[str, Any]:
        """Executes the full 5-stage PREVC workflow with Tri-Party SoD & Merkle custody."""
        disc_id = discoverer_id if discoverer_id is not None else self.default_discoverer_id
        veri_id = verifier_id if verifier_id is not None else self.default_verifier_id
        auth_id = authorizer_id if authorizer_id is not None else self.default_authorizer_id

        # Enforce Tri-Party Separation of Duties BEFORE executing workflow
        sod_check = SeparationOfDutiesValidator.validate(
            disc_id, veri_id, auth_id, raise_on_violation=False
        )
        if not sod_check["valid"]:
            self.append_audit_entry(
                agent_id=disc_id or "UNKNOWN",
                action="SOD_ENFORCEMENT_REJECTED",
                target=target,
                payload={"violation_codes": sod_check["violation_codes"]},
                policy_status="BLOCKED",
                stage="PLAN",
            )
            raise SeparationOfDutiesError(
                "Tri-Party Separation of Duties violation: "
                + ", ".join(sod_check["violation_codes"]),
                violation_codes=sod_check["violation_codes"],
            )

        stages_completed: List[str] = []

        # ------------------------------------------------------------------
        # Stage 1: PLAN (Guardrails + Scope Validation)
        # ------------------------------------------------------------------
        policy = self.validate_policy(
            target=target,
            action=f"PREVC_PLAN:{mode}",
            is_state_changing=is_state_changing,
            prompt=prompt,
            tool_definition=tool_definition,
        )
        self.append_audit_entry(
            agent_id=disc_id,
            action="PREVC_PLAN",
            target=target,
            payload={
                "mode": mode,
                "allowed": policy["allowed"],
                "violation_codes": policy["violation_codes"],
            },
            policy_status="PASSED" if policy["allowed"] else "BLOCKED",
            stage="PLAN",
        )
        stages_completed.append("PLAN")

        if not policy["allowed"]:
            custody_check = verify_custody_chain(self.audit_log, self.merkle_root)
            return {
                "status": "BLOCKED",
                "blocked_stage": "PLAN",
                "target": target,
                "mode": mode,
                "stages_completed": stages_completed,
                "separation_of_duties": sod_check,
                "policy": policy,
                "findings": [],
                "patch_proposals": [],
                "verification": {"passed": False, "reason": policy["reason"]},
                "certification": {"certified": False, "reason": "Blocked in PLAN stage"},
                "merkle_root": self.merkle_root,
                "custody_verified": custody_check["valid"],
                "custody_chain": [item.model_dump() for item in self.audit_log],
            }

        # ------------------------------------------------------------------
        # Stage 2: REPRODUCE (Deterministic Scanners)
        # ------------------------------------------------------------------
        is_http = target.lower().startswith(("http://", "https://"))
        resolved_files: List[str] = []
        findings: List[Dict[str, Any]] = []

        if is_http:
            if enable_network_header_scan:
                hdr_res = self.header_scanner.evaluate_headers(target)
                hdr_findings = (
                    hdr_res if isinstance(hdr_res, list) else hdr_res.get("findings", [])
                )
                findings.extend(hdr_findings)
        else:
            resolved = self._resolve_target_path(target)
            resolved_files = self._collect_target_files(resolved)
            if resolved_files:
                base_dir = resolved if os.path.isdir(resolved) else os.path.dirname(resolved)
                code_res = self.code_scanner.scan_workspace(resolved)
                secret_res = self.secret_scanner.scan_directory(resolved)
                raw_findings: List[Dict[str, Any]] = []
                raw_findings.extend(
                    code_res if isinstance(code_res, list) else code_res.get("findings", [])
                )
                raw_findings.extend(
                    secret_res if isinstance(secret_res, list) else secret_res.get("findings", [])
                )
                for item in raw_findings:
                    normalized_item = dict(item)
                    rel_or_abs = str(normalized_item.get("file", ""))
                    if rel_or_abs and not os.path.isabs(rel_or_abs):
                        candidate = os.path.realpath(os.path.join(base_dir, rel_or_abs))
                        if os.path.isfile(candidate):
                            normalized_item["file"] = candidate
                    findings.append(normalized_item)

        self.append_audit_entry(
            agent_id=disc_id,
            action="PREVC_REPRODUCE",
            target=target,
            payload={
                "files_scanned": len(resolved_files),
                "findings_count": len(findings),
            },
            policy_status="PASSED",
            stage="REPRODUCE",
        )
        stages_completed.append("REPRODUCE")

        # ------------------------------------------------------------------
        # Stage 3: EXECUTE_FIX (Signed Remediation Proposals, no auto-apply)
        # ------------------------------------------------------------------
        patch_proposals: List[Dict[str, Any]] = []
        patched_file_pairs: Dict[str, Tuple[str, str]] = {}

        # Group findings per file so cumulative CWEs on one file patch cleanly
        file_cwes: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}
        for fnd in findings:
            inferred_cwe = _infer_cwe_from_finding(fnd)
            f_path = str(fnd.get("file", ""))
            if inferred_cwe and f_path and os.path.isfile(f_path):
                file_cwes.setdefault(f_path, []).append((inferred_cwe, fnd))

        for f_path, cwe_entries in file_cwes.items():
            with open(f_path, "r", encoding="utf-8", errors="ignore") as fh:
                orig_source = fh.read()
            current_source = orig_source
            applied_cwes: List[str] = []
            seen_cwes: set[str] = set()
            for cwe_id, fnd in cwe_entries:
                if cwe_id in seen_cwes:
                    continue
                seen_cwes.add(cwe_id)
                proposal = self.patcher.remediate(
                    cwe_id=cwe_id,
                    file_path=os.path.relpath(f_path, self.workspace_root),
                    source_code=current_source,
                    finding=fnd,
                )
                if proposal["unified_diff"]:
                    current_source = proposal["patched_content"]
                    applied_cwes.append(cwe_id)
                    patch_proposals.append(proposal)
            if current_source != orig_source:
                patched_file_pairs[f_path] = (orig_source, current_source)

        self.append_audit_entry(
            agent_id=disc_id,
            action="PREVC_EXECUTE_FIX",
            target=target,
            payload={
                "proposals_generated": len(patch_proposals),
                "auto_apply_allowed": False,
                "signatures": [p["patch_signature"] for p in patch_proposals],
            },
            policy_status="PASSED",
            stage="EXECUTE_FIX",
        )
        stages_completed.append("EXECUTE_FIX")

        # ------------------------------------------------------------------
        # Stage 4: VERIFY (Independent Verifier != Discoverer != Authorizer)
        # ------------------------------------------------------------------
        post_fix_findings: List[Dict[str, Any]] = []
        all_signatures_valid = True
        all_roundtrips_valid = True

        for proposal in patch_proposals:
            if not self.patcher.verify_patch_signature(proposal):
                all_signatures_valid = False
            if proposal.get("auto_apply_allowed") is not False:
                all_signatures_valid = False
            try:
                re_patched = self.patcher.apply_unified_diff(
                    proposal["original_content"], proposal["unified_diff"]
                )
                re_original = self.patcher.apply_unified_diff(
                    re_patched, proposal["reverse_diff"]
                )
                if re_patched != proposal["patched_content"] or re_original != proposal["original_content"]:
                    all_roundtrips_valid = False
            except ValueError:
                all_roundtrips_valid = False

        files_with_initial_findings = {
            str(f.get("file", "")) for f in findings if f.get("file")
        }
        for f_path, (_, patched_src) in patched_file_pairs.items():
            post_fix_findings.extend(self.code_scanner.scan_content(patched_src, file_path=f_path))
            post_fix_findings.extend(self.secret_scanner.scan_content(patched_src, file_path=f_path))
        for f_path in sorted(files_with_initial_findings - set(patched_file_pairs.keys())):
            if os.path.isfile(f_path):
                with open(f_path, "r", encoding="utf-8", errors="ignore") as fh:
                    unpatched_src = fh.read()
                post_fix_findings.extend(
                    self.code_scanner.scan_content(unpatched_src, file_path=f_path)
                )
                post_fix_findings.extend(
                    self.secret_scanner.scan_content(unpatched_src, file_path=f_path)
                )

        # Files that were scanned and unchanged (clean) keep 0 findings
        remediated_count = max(0, len(findings) - len(post_fix_findings))
        verification_passed = (
            all_signatures_valid
            and all_roundtrips_valid
            and (len(post_fix_findings) == 0 or len(post_fix_findings) < len(findings))
        )
        if not findings:
            verification_passed = all_signatures_valid and all_roundtrips_valid

        verification_summary = {
            "verified_by": veri_id,
            "passed": verification_passed,
            "signatures_valid": all_signatures_valid,
            "diff_roundtrips_valid": all_roundtrips_valid,
            "initial_findings": len(findings),
            "remaining_findings": len(post_fix_findings),
            "remediated_findings": remediated_count,
        }

        self.append_audit_entry(
            agent_id=veri_id,
            action="PREVC_VERIFY",
            target=target,
            payload=verification_summary,
            policy_status="PASSED" if verification_passed else "FAILED",
            stage="VERIFY",
        )
        stages_completed.append("VERIFY")

        # ------------------------------------------------------------------
        # Stage 5: CERTIFY (Independent Authorizer != Discoverer != Verifier)
        # ------------------------------------------------------------------
        # Re-assert Tri-Party SoD at certification gate
        SeparationOfDutiesValidator.validate(disc_id, veri_id, auth_id, raise_on_violation=True)

        cert_status = "CERTIFIED" if verification_passed else "REJECTED"
        self.append_audit_entry(
            agent_id=auth_id,
            action="PREVC_CERTIFY",
            target=target,
            payload={
                "certified_by": auth_id,
                "status": cert_status,
                "pre_cert_merkle_root": self.merkle_root,
            },
            policy_status="PASSED" if verification_passed else "REJECTED",
            stage="CERTIFY",
        )
        stages_completed.append("CERTIFY")

        leaf_hashes = [item.hash for item in self.audit_log]
        merkle_proofs = [
            {
                "index": idx,
                "stage": item.stage,
                "leaf_hash": item.hash,
                "proof": generate_merkle_proof(leaf_hashes, idx),
            }
            for idx, item in enumerate(self.audit_log)
        ]
        custody_check = verify_custody_chain(self.audit_log, self.merkle_root)

        final_status = "CERTIFIED" if (verification_passed and custody_check["valid"]) else "VERIFICATION_FAILED"
        return {
            "status": final_status,
            "target": target,
            "mode": mode,
            "stages_completed": stages_completed,
            "separation_of_duties": sod_check,
            "policy": policy,
            "findings": findings,
            "remaining_findings": post_fix_findings,
            "patch_proposals": patch_proposals,
            "auto_apply_allowed": False,
            "verification": verification_summary,
            "certification": {
                "certified": final_status == "CERTIFIED",
                "certified_by": auth_id,
                "merkle_root": self.merkle_root,
                "custody_verified": custody_check["valid"],
            },
            "merkle_root": self.merkle_root,
            "merkle_proofs": merkle_proofs,
            "custody_verified": custody_check["valid"],
            "custody_chain": [item.model_dump() for item in self.audit_log],
        }
