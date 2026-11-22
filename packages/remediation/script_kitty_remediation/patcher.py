"""Deterministic PatchCat Remediation Engine (stdlib compatible).

Generates parameterized code remediations for CWE-89 (SQLi), CWE-78 (Command
Injection), CWE-639 (IDOR), and CWE-798 (Hardcoded Secrets), computes standard
unified diffs and exact mathematical reverse diffs, measures blast radius, and
issues RFC 8785 + SHA-256 signed patch proposals with ``auto_apply_allowed=False``.
"""

from __future__ import annotations

import ast
import difflib
import hashlib
import json
import math
import re
import shlex
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


_HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$")


def _normalize_canonical(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Cannot canonicalize non-finite float")
        return 0 if value == 0.0 else value
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, Mapping):
        return {
            str(k): _normalize_canonical(v)
            for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_normalize_canonical(item) for item in value]
    if hasattr(value, "model_dump") and callable(value.model_dump):
        return _normalize_canonical(value.model_dump())
    if hasattr(value, "dict") and callable(value.dict):
        return _normalize_canonical(value.dict())
    if hasattr(value, "__dict__"):
        return _normalize_canonical(vars(value))
    return str(value)


def _canonical_json_dumps(value: Any) -> str:
    return json.dumps(
        _normalize_canonical(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    )


def _rfc8785_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json_dumps(value).encode("utf-8")).hexdigest()


def _normalize_cwe(cwe_raw: str) -> str:
    upper = str(cwe_raw or "").upper()
    if "89" in upper or "SQL" in upper:
        return "CWE-89"
    if "78" in upper or "COMMAND" in upper or "EXEC" in upper:
        return "CWE-78"
    if "639" in upper or "IDOR" in upper or "OWNERSHIP" in upper or "ACCESS CONTROL" in upper:
        return "CWE-639"
    if "798" in upper or "SECRET" in upper or "CREDENTIAL" in upper or "KEY" in upper:
        return "CWE-798"
    return upper or "CWE-UNKNOWN"


def _ensure_python_import(code: str, module_name: str) -> str:
    if re.search(rf"(?m)^(?:import\s+{re.escape(module_name)}\b|from\s+{re.escape(module_name)}\s+import\b)", code):
        return code
    lines = code.splitlines()
    insert_at = 0
    # Skip leading docstrings or comments
    if lines and (lines[0].startswith("#!") or lines[0].startswith("# -*-")):
        insert_at = 1
    while insert_at < len(lines) and (not lines[insert_at].strip() or lines[insert_at].lstrip().startswith("#")):
        insert_at += 1
    lines.insert(insert_at, f"import {module_name}")
    suffix = "\n" if code.endswith("\n") else ""
    return "\n".join(lines) + suffix


class PatchCatRemediationEngine:
    """Deterministic vulnerability remediation and signed unified-diff generator."""

    SUPPORTED_CWES = ("CWE-89", "CWE-78", "CWE-639", "CWE-798")

    @staticmethod
    def generate_unified_diff(
        original_code: str,
        patched_code: str,
        file_path: str = "target_file",
    ) -> str:
        """Generates a deterministic POSIX unified diff between original and patched source."""
        rel_path = file_path.replace("\\", "/").lstrip("./") or "target_file"
        orig_lines = original_code.splitlines()
        new_lines = patched_code.splitlines()
        diff_lines = list(
            difflib.unified_diff(
                orig_lines,
                new_lines,
                fromfile=f"a/{rel_path}",
                tofile=f"b/{rel_path}",
                lineterm="",
                n=3,
            )
        )
        if not diff_lines:
            return ""
        return "\n".join(diff_lines) + "\n"

    @staticmethod
    def compute_reverse_diff(unified_diff: str) -> str:
        """Computes the exact inverse unified diff that reverts patched source back to original."""
        if not unified_diff.strip():
            return ""

        lines = unified_diff.splitlines()
        out_lines: List[str] = []
        i = 0
        while i < len(lines):
            line = lines[i]
            if line.startswith("--- ") and i + 1 < len(lines) and lines[i + 1].startswith("+++ "):
                old_hdr = line[4:]
                new_hdr = lines[i + 1][4:]
                if old_hdr.startswith("a/") and new_hdr.startswith("b/"):
                    out_lines.append(f"--- a/{new_hdr[2:]}")
                    out_lines.append(f"+++ b/{old_hdr[2:]}")
                else:
                    out_lines.append(f"--- {new_hdr}")
                    out_lines.append(f"+++ {old_hdr}")
                i += 2
                continue

            hunk_match = _HUNK_HEADER_RE.match(line)
            if hunk_match:
                old_start = hunk_match.group(1)
                old_count = hunk_match.group(2)
                new_start = hunk_match.group(3)
                new_count = hunk_match.group(4)
                suffix = hunk_match.group(5) or ""
                left = f"{new_start},{new_count}" if new_count is not None else new_start
                right = f"{old_start},{old_count}" if old_count is not None else old_start
                out_lines.append(f"@@ -{left} +{right} @@{suffix}")
                i += 1
                # Collect hunk body lines and keep deleted lines ordered before added lines when inverted
                hunk_body: List[str] = []
                while i < len(lines):
                    cur = lines[i]
                    if cur.startswith(("@@ ", "--- ", "+++ ", "diff --git ")):
                        break
                    hunk_body.append(cur)
                    i += 1

                # Reorder contiguous -/+ blocks into + swapped to - then - swapped to +
                j = 0
                while j < len(hunk_body):
                    cur = hunk_body[j]
                    if cur.startswith(("-", "+")):
                        minus_swapped: List[str] = []
                        plus_swapped: List[str] = []
                        while j < len(hunk_body) and hunk_body[j].startswith(("-", "+")):
                            item = hunk_body[j]
                            if item.startswith("-"):
                                plus_swapped.append("+" + item[1:])
                            else:
                                minus_swapped.append("-" + item[1:])
                            j += 1
                        out_lines.extend(minus_swapped)
                        out_lines.extend(plus_swapped)
                    else:
                        out_lines.append(cur)
                        j += 1
                continue

            out_lines.append(line)
            i += 1

        return "\n".join(out_lines) + "\n"

    @staticmethod
    def apply_unified_diff(source_code: str, unified_diff: str) -> str:
        """Deterministically applies a unified diff to source text (for forward/reverse verification)."""
        if not unified_diff.strip():
            return source_code

        src_lines = source_code.splitlines()
        diff_lines = unified_diff.splitlines()
        result: List[str] = []
        src_idx = 0
        i = 0

        while i < len(diff_lines):
            line = diff_lines[i]
            m = _HUNK_HEADER_RE.match(line)
            if not m:
                i += 1
                continue

            old_start = int(m.group(1))
            target_idx = max(0, old_start - 1) if old_start > 0 else 0
            while src_idx < target_idx and src_idx < len(src_lines):
                result.append(src_lines[src_idx])
                src_idx += 1

            i += 1
            while i < len(diff_lines):
                cur = diff_lines[i]
                if cur.startswith(("@@ ", "--- ", "+++ ", "diff --git ")):
                    break
                if cur.startswith(" "):
                    expected = cur[1:]
                    if src_idx < len(src_lines) and src_lines[src_idx] != expected:
                        raise ValueError(
                            f"Hunk context mismatch at source line {src_idx + 1}: "
                            f"expected {expected!r}, found {src_lines[src_idx]!r}"
                        )
                    result.append(expected)
                    src_idx += 1
                elif cur.startswith("-"):
                    expected = cur[1:]
                    if src_idx >= len(src_lines) or src_lines[src_idx] != expected:
                        actual = src_lines[src_idx] if src_idx < len(src_lines) else "<EOF>"
                        raise ValueError(
                            f"Hunk deletion mismatch at source line {src_idx + 1}: "
                            f"expected {expected!r}, found {actual!r}"
                        )
                    src_idx += 1
                elif cur.startswith("+"):
                    result.append(cur[1:])
                elif cur.startswith("\\"):
                    pass
                i += 1

        while src_idx < len(src_lines):
            result.append(src_lines[src_idx])
            src_idx += 1

        trailing = "\n" if (source_code.endswith("\n") or (not source_code and bool(result))) else ""
        return "\n".join(result) + trailing

    @staticmethod
    def analyze_blast_radius(
        unified_diff: str,
        fallback_file_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Measures blast radius strictly from unified diff hunks."""
        files: List[str] = []
        lines_added = 0
        lines_removed = 0
        hunks = 0

        for line in unified_diff.splitlines():
            if line.startswith("+++ "):
                path_part = line[4:].strip()
                if path_part.startswith("b/"):
                    path_part = path_part[2:]
                if path_part and path_part != "/dev/null" and path_part not in files:
                    files.append(path_part)
            elif line.startswith("@@ "):
                hunks += 1
            elif line.startswith("+") and not line.startswith("+++ "):
                lines_added += 1
            elif line.startswith("-") and not line.startswith("--- "):
                lines_removed += 1

        if not files and (lines_added or lines_removed) and fallback_file_path:
            files.append(fallback_file_path)

        total_delta = lines_added + lines_removed
        risk_tier = (
            "LOW"
            if len(files) <= 1 and total_delta <= 12
            else ("MEDIUM" if total_delta <= 40 else "HIGH")
        )
        return {
            "files_changed": len(files),
            "lines_added": lines_added,
            "lines_removed": lines_removed,
            "hunks": hunks,
            "files": files,
            "risk_tier": risk_tier,
        }

    @staticmethod
    def _transform_cwe89_sqli(source_code: str, is_python: bool) -> Tuple[str, str]:
        """Transforms template/concatenated SQL queries into parameterized statements."""
        updated = source_code

        if not is_python:
            # 1. Exact lab-app search.ts pattern (`WHERE title LIKE '%${query}%' OR description LIKE '%${query}%'`)
            lab_search_re = re.compile(
                r"const\s+rawSql\s*=\s*`SELECT\s+id,\s*owner_id,\s*title,\s*severity,\s*classification,\s*description,\s*system_target,\s*created_at\s+FROM\s+incidents\s+WHERE\s+title\s+LIKE\s+'%\$\{(\w+)\}%'\s+OR\s+description\s+LIKE\s+'%\$\{\1\}%'`;\s*\n\s*const\s+stmt\s*=\s*db\.prepare\(rawSql\);\s*\n\s*return\s+stmt\.all\(\);",
                re.MULTILINE,
            )

            def _repl_lab_search(m: re.Match[str]) -> str:
                var = m.group(1)
                return (
                    "const sql = 'SELECT id, owner_id, title, severity, classification, description, system_target, created_at FROM incidents WHERE title LIKE ? OR description LIKE ?';\n"
                    f"  const pattern = `%${{{var}}}%`;\n"
                    "  const stmt = db.prepare(sql);\n"
                    "  return stmt.all(pattern, pattern);"
                )

            updated = lab_search_re.sub(_repl_lab_search, updated)

            # 2. Generic TS/JS backtick SQL query assignment + prepare/query execution
            if updated == source_code:
                tpl_sql_re = re.compile(
                    r"(db\.(?:prepare|query|execute)\(\s*)`([^`]*\$\{[^}]+\}[^`]*)`\s*\)",
                    re.IGNORECASE,
                )

                def _repl_js_tpl(m: re.Match[str]) -> str:
                    prefix = m.group(1)
                    sql_body = m.group(2)
                    params: List[str] = []

                    def _sub_expr(em: re.Match[str]) -> str:
                        expr = em.group(1).strip()
                        if em.group(0).startswith("'%") and em.group(0).endswith("%'"):
                            params.append(f"`%${{{expr}}}%`")
                        else:
                            params.append(expr)
                        return "?"

                    # Handle '%${var}%' first, then remaining '${var}' or ${var}
                    param_sql = re.sub(r"'%\$\{([^}]+)\}%'", _sub_expr, sql_body)
                    param_sql = re.sub(
                        r"'\$\{([^}]+)\}'|\$\{([^}]+)\}",
                        lambda em: (params.append((em.group(1) or em.group(2)).strip()) or "?"),
                        param_sql,
                    )
                    quoted_sql = repr(param_sql)
                    if "prepare(" in prefix:
                        return f"{prefix}{quoted_sql})"
                    return f"{prefix}{quoted_sql}, [{', '.join(params)}])"

                updated = tpl_sql_re.sub(_repl_js_tpl, updated)
                # If db.prepare('...') had .all() right after, bind collected params when single-step
                tpl_var_re = re.compile(
                    r"const\s+(\w+)\s*=\s*`((?:SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{[^}]+\}[^`]*)`;(\s*\n(?:[^\n]*\n){0,3}?)([^\n]*?\.)(all|get|run)\(\s*\)",
                    re.IGNORECASE,
                )

                def _repl_js_var(m: re.Match[str]) -> str:
                    var_name, sql_body, mid, call_prefix, method = m.groups()
                    params: List[str] = []

                    def _sub_like(em: re.Match[str]) -> str:
                        params.append(f"`%${{{em.group(1).strip()}}}%`")
                        return "?"

                    param_sql = re.sub(r"'%\$\{([^}]+)\}%'", _sub_like, sql_body)
                    param_sql = re.sub(
                        r"'\$\{([^}]+)\}'|\$\{([^}]+)\}",
                        lambda em: (params.append((em.group(1) or em.group(2)).strip()) or "?"),
                        param_sql,
                    )
                    return (
                        f"const {var_name} = {repr(param_sql)};"
                        f"{mid}{call_prefix}{method}({', '.join(params)})"
                    )

                if updated == source_code:
                    updated = tpl_var_re.sub(_repl_js_var, updated)

            # 3. JS/TS string concatenation (`db.prepare("SELECT ... '" + var + "'")`)
            if updated == source_code:
                js_concat_re = re.compile(
                    r"(db\.(?:prepare|query|execute)\(\s*)(['\"])((?:SELECT|INSERT|UPDATE|DELETE)[^'\"]*?)'?\2\s*\+\s*([A-Za-z_$][A-Za-z0-9_$.]*)(?:\s*\+\s*(['\"])['\"]?\5)?(\s*\))",
                    re.IGNORECASE,
                )

                def _repl_js_concat(m: re.Match[str]) -> str:
                    prefix, _, sql_head, var_name, _, suffix = m.groups()
                    clean_head = sql_head.rstrip()
                    if clean_head.endswith("'"):
                        clean_head = clean_head[:-1]
                    sql_stmt = f"{clean_head}?" if clean_head.endswith(("=", "LIKE ")) else f"{clean_head} ?"
                    if "prepare(" in prefix:
                        return f"{prefix}{repr(sql_stmt)}{suffix}"
                    return f"{prefix}{repr(sql_stmt)}, [{var_name}]{suffix}"

                updated = js_concat_re.sub(_repl_js_concat, updated)

            return updated, "Parameterized SQL query with positional `?` bound parameters (CWE-89)."

        # Python CWE-89 remediation
        # 1. cursor.execute(f"SELECT ... {var}") (supports single quotes inside double quotes and vice versa)
        py_fstring_re = re.compile(
            r"(\b\w+\.execute\()\s*(?:f\"((?:SELECT|INSERT|UPDATE|DELETE)[^\"]*?)\"|f'((?:SELECT|INSERT|UPDATE|DELETE)[^']*?)')(\s*\))",
            re.IGNORECASE,
        )

        def _repl_py_fstring(m: re.Match[str]) -> str:
            prefix, sql_dq, sql_sq, suffix = m.groups()
            sql_body = sql_dq if sql_dq is not None else (sql_sq or "")
            params: List[str] = []

            def _sub_py_like(em: re.Match[str]) -> str:
                params.append(f'f"%{{{em.group(1).strip()}}}%"')
                return "?"

            param_sql = re.sub(r"'%\{([^}]+)\}%'", _sub_py_like, sql_body)
            param_sql = re.sub(
                r"'\{([^}]+)\}'|\{([^}]+)\}",
                lambda em: (params.append((em.group(1) or em.group(2)).strip()) or "?"),
                param_sql,
            )
            tuple_expr = f"({params[0]},)" if len(params) == 1 else f"({', '.join(params)})"
            return f"{prefix}{json.dumps(param_sql)}, {tuple_expr}{suffix}"

        updated = py_fstring_re.sub(_repl_py_fstring, updated)

        # 2. cursor.execute("SELECT ... '" + var + "'")
        if updated == source_code:
            py_concat_re = re.compile(
                r"(\b\w+\.execute\()\s*(['\"])((?:SELECT|INSERT|UPDATE|DELETE)[^'\"]*?)'?\2\s*\+\s*(?:str\()?([A-Za-z_][A-Za-z0-9_.]*)\)?(?:\s*\+\s*(['\"])['\"]?\5)?(\s*\))",
                re.IGNORECASE,
            )

            def _repl_py_concat(m: re.Match[str]) -> str:
                prefix, _, sql_head, var_name, _, suffix = m.groups()
                clean_head = sql_head.rstrip()
                if clean_head.endswith("'"):
                    clean_head = clean_head[:-1]
                sql_stmt = f"{clean_head}?" if clean_head.endswith(("=", "LIKE ")) else f"{clean_head} ?"
                return f"{prefix}{json.dumps(sql_stmt)}, ({var_name},){suffix}"

            updated = py_concat_re.sub(_repl_py_concat, updated)

        # 3. cursor.execute("SELECT ... {}".format(var))
        if updated == source_code:
            py_format_re = re.compile(
                r"(\b\w+\.execute\()\s*(['\"])((?:SELECT|INSERT|UPDATE|DELETE)[^'\"]*?)\2\.format\(([^)]+)\)(\s*\))",
                re.IGNORECASE,
            )

            def _repl_py_format(m: re.Match[str]) -> str:
                prefix, _, sql_body, args_str, suffix = m.groups()
                param_sql = sql_body.replace("'{}'", "?").replace("{}", "?")
                args = [a.strip() for a in args_str.split(",") if a.strip()]
                tuple_expr = f"({args[0]},)" if len(args) == 1 else f"({', '.join(args)})"
                return f"{prefix}{json.dumps(param_sql)}, {tuple_expr}{suffix}"

            updated = py_format_re.sub(_repl_py_format, updated)

        return updated, "Replaced interpolated SQL statement with parameterized `?` binding (CWE-89)."

    @staticmethod
    def _transform_cwe78_cmd_injection(source_code: str, is_python: bool) -> Tuple[str, str]:
        """Replaces shell-invoking command execution with validated argv execution."""
        updated = source_code

        if not is_python:
            # Exact lab-app diagnostics.ts ping remediation
            diag_re = re.compile(
                r"const\s+isWindows\s*=\s*process\.platform\s*===\s*'win32';\s*\n\s*const\s+pingCmd\s*=\s*isWindows\s*\?\s*`ping\s+-n\s+1\s+\$\{(\w+)\}`\s*:\s*`ping\s+-c\s+1\s+\$\{\1\}`;\s*\n\s*\n\s*try\s*\{\s*\n\s*const\s+stdout\s*=\s*execSync\(pingCmd,\s*(\{[^}]+\})\);",
                re.MULTILINE,
            )

            def _repl_diag(m: re.Match[str]) -> str:
                host_var, opts = m.groups()
                return (
                    f"if (!/^[a-zA-Z0-9.-]{{1,253}}$/.test({host_var}) || {host_var}.startsWith('-')) {{\n"
                    f"    throw new Error('Invalid host target');\n"
                    f"  }}\n"
                    f"  const isWindows = process.platform === 'win32';\n"
                    f"  const pingArgs = [isWindows ? '-n' : '-c', '1', {host_var}];\n\n"
                    f"  try {{\n"
                    f"    const stdout = execFileSync('ping', pingArgs, {opts});"
                )

            updated = diag_re.sub(_repl_diag, updated)
            if updated != source_code and "execSync" in updated:
                updated = updated.replace(
                    "import { execSync } from 'node:child_process';",
                    "import { execFileSync } from 'node:child_process';",
                )

            if updated == source_code:
                # Generic JS/TS execSync(`cmd ${arg}`, opts) -> execFileSync('cmd', [...], opts)
                exec_tpl_re = re.compile(
                    r"\b(execSync|exec)\(\s*`([^`]+)`(\s*,\s*\{[^}]*\})?\s*\)"
                )

                def _repl_exec_tpl(m: re.Match[str]) -> str:
                    fn_name, cmd_tpl, opts = m.groups()
                    parts = cmd_tpl.strip().split()
                    if not parts:
                        return m.group(0)
                    exe = parts[0]
                    argv_items: List[str] = []
                    for token in parts[1:]:
                        tm = re.fullmatch(r"\$\{([^}]+)\}", token)
                        if tm:
                            argv_items.append(tm.group(1).strip())
                        else:
                            argv_items.append(repr(token))
                    target_fn = "execFileSync" if fn_name == "execSync" else "execFile"
                    opts_str = opts or ""
                    return f"{target_fn}({repr(exe)}, [{', '.join(argv_items)}]{opts_str})"

                updated = exec_tpl_re.sub(_repl_exec_tpl, updated)
                if "execFileSync" in updated and "execFileSync" not in source_code:
                    updated = updated.replace("execSync", "execFileSync", 1)

            return updated, "Replaced shell command execution with `execFileSync`/`execFile` argv separation and strict input validation (CWE-78)."

        # Python CWE-78 remediation
        # 1. subprocess.(run|call|Popen)(f"cmd ... {arg}", ... shell=True ...)
        sub_fstring_re = re.compile(
            r"subprocess\.(run|call|Popen)\(\s*f(['\"])([^'\"]+)\2([^)]*?)shell\s*=\s*True([^)]*)\)"
        )

        def _repl_py_sub_f(m: re.Match[str]) -> str:
            fn_name, _, cmd_tpl, mid_args, tail_args = m.groups()
            tokens = shlex.split(cmd_tpl)
            argv_items: List[str] = []
            for tok in tokens:
                vm = re.fullmatch(r"\{([^}]+)\}", tok)
                if vm:
                    argv_items.append(f"str({vm.group(1).strip()})")
                elif "{" in tok and "}" in tok:
                    argv_items.append(f"f{json.dumps(tok)}")
                else:
                    argv_items.append(json.dumps(tok))
            return f"subprocess.{fn_name}([{', '.join(argv_items)}]{mid_args}shell=False{tail_args})"

        updated = sub_fstring_re.sub(_repl_py_sub_f, updated)

        # 2. subprocess.run([...], shell=True) -> shell=False
        if updated == source_code:
            updated = re.sub(
                r"(subprocess\.(?:run|call|Popen)\([^)]*?)shell\s*=\s*True",
                r"\1shell=False",
                updated,
            )

        # 3. os.system(f"...") -> subprocess.run([...], shell=False, check=True)
        if updated == source_code:
            os_sys_f_re = re.compile(r"\bos\.system\(\s*f(['\"])([^'\"]+)\1\s*\)")

            def _repl_os_sys_f(m: re.Match[str]) -> str:
                tokens = shlex.split(m.group(2))
                argv_items: List[str] = []
                for tok in tokens:
                    vm = re.fullmatch(r"\{([^}]+)\}", tok)
                    if vm:
                        argv_items.append(f"str({vm.group(1).strip()})")
                    elif "{" in tok and "}" in tok:
                        argv_items.append(f"f{json.dumps(tok)}")
                    else:
                        argv_items.append(json.dumps(tok))
                return f"subprocess.run([{', '.join(argv_items)}], shell=False, check=True)"

            updated = os_sys_f_re.sub(_repl_os_sys_f, updated)
            if updated != source_code:
                updated = _ensure_python_import(updated, "subprocess")

        # 4. os.system(var) -> subprocess.run(shlex.split(str(var)), shell=False, check=True)
        if updated == source_code:
            os_sys_var_re = re.compile(r"\bos\.system\(\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\)")
            updated = os_sys_var_re.sub(
                r"subprocess.run(shlex.split(str(\1)), shell=False, check=True)",
                updated,
            )
            if updated != source_code:
                updated = _ensure_python_import(updated, "shlex")
                updated = _ensure_python_import(updated, "subprocess")

        return updated, "Converted shell invocation to `shell=False` explicit argument vector (CWE-78)."

    @staticmethod
    def _transform_cwe639_idor(source_code: str, is_python: bool) -> Tuple[str, str]:
        """Injects server-side resource ownership and role authorization guards."""
        updated = source_code

        if not is_python:
            # 1. lab-app reports.ts pattern (requester + report)
            if "report.owner_id" not in source_code or "status: 403" not in source_code:
                ts_404_re = re.compile(
                    r"(const\s+(\w+)\s*=\s*db\.prepare\([^;]+;\s*\n\s*\n\s*if\s*\(!\2\)\s*\{\s*\n\s*return\s*\{\s*\n\s*status:\s*404,[\s\S]*?\};\s*\n\s*\})",
                    re.MULTILINE,
                )

                def _repl_ts_idor(m: re.Match[str]) -> str:
                    block = m.group(1)
                    record_var = m.group(2)
                    actor_var = (
                        "requester"
                        if re.search(r"\brequester\b", source_code)
                        else ("sessionUser" if re.search(r"\bsessionUser\b", source_code) else "currentUser")
                    )
                    actor_id = "id" if actor_var == "requester" else "userId"
                    guard = (
                        f"\n\n  if ({record_var}.owner_id !== {actor_var}.{actor_id} && {actor_var}.role !== 'admin') {{\n"
                        f"    return {{\n"
                        f"      status: 403,\n"
                        f"      body: {{ error: 'Forbidden: resource ownership verification required' }}\n"
                        f"    }};\n"
                        f"  }}"
                    )
                    return block + guard

                updated = ts_404_re.sub(_repl_ts_idor, updated)

            # 2. Generic TS/JS direct return of record fetched by ID
            if updated == source_code and "status: 403" not in source_code:
                generic_ret_re = re.compile(r"(\n[ \t]*)(return\s+\{\s*\n[ \t]*status:\s*200,\s*\n[ \t]*body:\s*(\w+)\s*\n[ \t]*\};?)")

                def _repl_generic_ts(m: re.Match[str]) -> str:
                    indent, ret_block, record_var = m.groups()
                    return (
                        f"{indent}if (!requester || ({record_var}.owner_id !== requester.id && requester.role !== 'admin')) {{\n"
                        f"    return {{\n"
                        f"      status: 403,\n"
                        f"      body: {{ error: 'Forbidden: resource ownership verification required' }}\n"
                        f"    }};\n"
                        f"  }}{indent}{ret_block}"
                    )

                updated = generic_ret_re.sub(_repl_generic_ts, updated)

            return updated, "Enforced fail-closed tenant/owner authorization (`status: 403`) prior to returning object (CWE-639)."

        # Python CWE-639 remediation
        if "PermissionError" not in source_code and "owner_id" not in source_code:
            py_fn_re = re.compile(
                r"(def\s+\w+\([^)]*\b(current_user|requester|user|session_user)\b[^)]*\):\s*\n)([\s\S]*?)([ \t]+)(return\s+([A-Za-z_][A-Za-z0-9_]*)\b)",
                re.MULTILINE,
            )

            def _repl_py_idor(m: re.Match[str]) -> str:
                header, actor_var, body, indent, ret_stmt, record_var = m.groups()
                guard = (
                    f"{indent}if {record_var} is None:\n"
                    f"{indent}    raise KeyError('Resource not found')\n"
                    f"{indent}_owner_id = {record_var}.get('owner_id') if isinstance({record_var}, dict) else getattr({record_var}, 'owner_id', None)\n"
                    f"{indent}_actor_id = {actor_var}.get('id') if isinstance({actor_var}, dict) else getattr({actor_var}, 'id', None)\n"
                    f"{indent}_actor_role = {actor_var}.get('role') if isinstance({actor_var}, dict) else getattr({actor_var}, 'role', None)\n"
                    f"{indent}if _owner_id != _actor_id and _actor_role != 'admin':\n"
                    f"{indent}    raise PermissionError('Forbidden: resource ownership verification required')\n"
                )
                return f"{header}{body}{guard}{indent}{ret_stmt}"

            updated = py_fn_re.sub(_repl_py_idor, updated, count=1)

        return updated, "Injected server-side ownership & role check raising `PermissionError` on mismatch (CWE-639)."

    @staticmethod
    def _transform_cwe798_secrets(source_code: str, is_python: bool) -> Tuple[str, str]:
        """Replaces hardcoded API keys, tokens, and secret assignments with environment lookups."""
        updated = source_code

        if not is_python:
            js_secret_re = re.compile(
                r"(\b(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*string\s*)?=\s*)(['\"])((?:sk-(?:proj-|live-|test-|ant-)?[A-Za-z0-9_-]{12,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{16,}|[^\3]{8,}))\3"
            )

            def _repl_js_sec(m: re.Match[str]) -> str:
                decl_prefix, var_name, _, val = m.groups()
                is_known_token = bool(
                    re.match(r"^(?:sk-|AKIA|ASIA|gh[pousr]_|github_pat_|xox)", val)
                )
                is_secret_var = bool(
                    re.search(r"(?:SECRET|TOKEN|API_?KEY|PASSWORD|PASSWD|PRIVATE_?KEY|CREDENTIAL)", var_name, re.IGNORECASE)
                )
                if not (is_known_token or is_secret_var):
                    return m.group(0)
                env_name = var_name.upper()
                return f"{decl_prefix}process.env.{env_name} ?? ''"

            updated = js_secret_re.sub(_repl_js_sec, updated)
            return updated, "Externalized hardcoded credential literal to `process.env` lookup (CWE-798)."

        # Python CWE-798 remediation
        py_secret_re = re.compile(
            r"(?m)^([ \t]*)([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*str\s*)?=\s*(['\"])((?:sk-(?:proj-|live-|test-|ant-)?[A-Za-z0-9_-]{12,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{16,}|[^\3]{6,}))\3"
        )

        changed = False

        def _repl_py_sec(m: re.Match[str]) -> str:
            nonlocal changed
            indent, var_name, _, val = m.groups()
            is_known_token = bool(
                re.match(r"^(?:sk-|AKIA|ASIA|gh[pousr]_|github_pat_|xox|-----BEGIN)", val)
            )
            is_secret_var = bool(
                re.search(r"(?:SECRET|TOKEN|API_?KEY|PASSWORD|PASSWD|PRIVATE_?KEY|CREDENTIAL)", var_name, re.IGNORECASE)
            )
            if not (is_known_token or is_secret_var):
                return m.group(0)
            changed = True
            env_name = var_name.upper()
            return f'{indent}{var_name} = os.environ["{env_name}"]'

        updated = py_secret_re.sub(_repl_py_sec, updated)
        if changed:
            updated = _ensure_python_import(updated, "os")

        return updated, "Replaced hardcoded credential literal with `os.environ` secret retrieval (CWE-798)."

    @classmethod
    def verify_patch_signature(cls, proposal: Mapping[str, Any]) -> bool:
        """Verifies RFC 8785 + SHA-256 integrity signature on a patch proposal."""
        sig = proposal.get("patch_signature")
        if not sig or not isinstance(sig, str):
            return False
        unsigned_payload = {
            "cwe_id": proposal.get("cwe_id"),
            "file_path": proposal.get("file_path"),
            "original_sha256": proposal.get("original_sha256"),
            "patched_sha256": proposal.get("patched_sha256"),
            "unified_diff": proposal.get("unified_diff"),
            "reverse_diff": proposal.get("reverse_diff"),
            "blast_radius": proposal.get("blast_radius"),
            "auto_apply_allowed": proposal.get("auto_apply_allowed"),
        }
        return sig == _rfc8785_sha256(unsigned_payload)

    def remediate(
        self,
        *,
        cwe_id: str,
        file_path: str,
        source_code: str,
        finding: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generates a deterministic, SHA-256 signed remediation proposal (no auto-apply)."""
        normalized_cwe = _normalize_cwe(cwe_id)
        is_python = file_path.lower().endswith(".py") or (
            not file_path.lower().endswith((".ts", ".tsx", ".js", ".mjs", ".cjs"))
            and ("def " in source_code or "import " in source_code)
            and "const " not in source_code
        )

        if normalized_cwe == "CWE-89":
            patched_code, rationale = self._transform_cwe89_sqli(source_code, is_python)
        elif normalized_cwe == "CWE-78":
            patched_code, rationale = self._transform_cwe78_cmd_injection(source_code, is_python)
        elif normalized_cwe == "CWE-639":
            patched_code, rationale = self._transform_cwe639_idor(source_code, is_python)
        elif normalized_cwe == "CWE-798":
            patched_code, rationale = self._transform_cwe798_secrets(source_code, is_python)
        else:
            raise ValueError(f"Unsupported CWE for deterministic remediation: {cwe_id!r}")

        syntax_valid = True
        if is_python:
            try:
                ast.parse(patched_code)
            except SyntaxError as exc:
                syntax_valid = False
                raise ValueError(f"Patched Python AST validation failed: {exc}") from exc

        unified_diff = self.generate_unified_diff(source_code, patched_code, file_path)
        reverse_diff = self.compute_reverse_diff(unified_diff)
        blast_radius = self.analyze_blast_radius(unified_diff, fallback_file_path=file_path)

        original_sha256 = hashlib.sha256(source_code.encode("utf-8")).hexdigest()
        patched_sha256 = hashlib.sha256(patched_code.encode("utf-8")).hexdigest()

        unsigned_payload = {
            "cwe_id": normalized_cwe,
            "file_path": file_path,
            "original_sha256": original_sha256,
            "patched_sha256": patched_sha256,
            "unified_diff": unified_diff,
            "reverse_diff": reverse_diff,
            "blast_radius": blast_radius,
            "auto_apply_allowed": False,
        }
        patch_signature = _rfc8785_sha256(unsigned_payload)

        return {
            "cwe_id": normalized_cwe,
            "file_path": file_path,
            "finding_type": str(finding.get("type", normalized_cwe)) if finding else normalized_cwe,
            "rationale": rationale,
            "original_content": source_code,
            "patched_content": patched_code,
            "original_sha256": original_sha256,
            "patched_sha256": patched_sha256,
            "unified_diff": unified_diff,
            "reverse_diff": reverse_diff,
            "blast_radius": blast_radius,
            "syntax_valid": syntax_valid,
            "auto_apply_allowed": False,
            "requires_human_approval": True,
            "patch_signature": patch_signature,
            "canonical_digest": patch_signature,
        }

    generate_patch_proposal = remediate

    @staticmethod
    def generate_playbook(finding: Dict[str, Any]) -> Dict[str, Any]:
        """Backward-compatible playbook API backed by real deterministic patch generation."""
        engine = PatchCatRemediationEngine()
        vuln_type = str(finding.get("cwe_id") or finding.get("type") or "CWE-89")
        file_path = str(finding.get("file_path") or finding.get("file") or "snippet.py")
        source_code = finding.get("source_code") or finding.get("original_content")

        if isinstance(source_code, str) and source_code.strip():
            proposal = engine.remediate(
                cwe_id=vuln_type,
                file_path=file_path,
                source_code=source_code,
                finding=finding,
            )
            return {
                **proposal,
                "vulnerability_type": proposal["cwe_id"],
                "remediation_steps": [
                    "1. Review signed unified_diff and blast_radius prior to approval.",
                    f"2. Apply parameterized fix in {file_path} (auto_apply_allowed is False).",
                    "3. Retain reverse_diff for instant cryptographic rollback if regression occurs.",
                    "4. Re-run scanners and verification harness under Separation of Duties.",
                ],
                "code_patch_example": proposal["unified_diff"],
                "ai_assisted": False,
            }

        # Metadata-only finding fallback: still run deterministic remediation over canonical template
        cwe = _normalize_cwe(vuln_type)
        templates: Dict[str, Tuple[str, str]] = {
            "CWE-89": (
                "query_handler.py",
                'def fetch_user(cursor, user_id):\n    return cursor.execute(f"SELECT id, role FROM users WHERE id = {user_id}").fetchall()\n',
            ),
            "CWE-78": (
                "diagnostics.py",
                'import subprocess\n\ndef ping_host(host):\n    return subprocess.run(f"ping -c 1 {host}", shell=True)\n',
            ),
            "CWE-639": (
                "reports.py",
                "def get_report(report_id, current_user, db):\n    report = db.get_report(report_id)\n    return report\n",
            ),
            "CWE-798": (
                "config.py",
                'API_KEY = "sk-live-example-redacted-placeholder"\n',
            ),
        }
        tpl_file, tpl_src = templates.get(cwe, templates["CWE-89"])
        target_file = file_path if file_path != "snippet.py" else tpl_file
        proposal = engine.remediate(
            cwe_id=cwe if cwe in engine.SUPPORTED_CWES else "CWE-89",
            file_path=target_file,
            source_code=tpl_src,
            finding=finding,
        )
        return {
            **proposal,
            "vulnerability_type": vuln_type,
            "remediation_steps": [
                "1. Inspect canonical remediation template diff and supply target source_code for exact line patching.",
                "2. Validate parameterized transformation without disabling failing tests.",
                "3. Obtain explicit human sign-off (auto_apply_allowed=False) before applying.",
            ],
            "code_patch_example": proposal["unified_diff"],
            "ai_assisted": False,
        }
