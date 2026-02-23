"""
BlackRoad Compliance Framework – automated compliance checking engine.
Supports: CIS, OWASP Top-10, NIST CSF, SOC 2, PCI-DSS (check mapping).
SQLite persistence. Generates detailed compliance reports.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple


# ─────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────

@dataclass
class ComplianceControl:
    id: str                      # e.g. "CIS-1.1"
    framework: str               # CIS | OWASP | NIST | SOC2 | PCI
    category: str
    title: str
    description: str
    severity: str                # CRITICAL | HIGH | MEDIUM | LOW
    remediation: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class ComplianceResult:
    control_id: str
    status: str                  # PASS | FAIL | WARN | NA | SKIP
    evidence: str = ""
    detail: str = ""
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ComplianceReport:
    framework: str
    target: str
    generated: str
    controls_total: int
    controls_passed: int
    controls_failed: int
    controls_warn: int
    score: float
    results: List[ComplianceResult] = field(default_factory=list)
    findings: List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["results"] = [r.to_dict() for r in self.results]
        return d


# ─────────────────────────────────────────────
# Controls library
# ─────────────────────────────────────────────

CONTROLS: List[ComplianceControl] = [
    # ── CIS ───────────────────────────────────
    ComplianceControl("CIS-1.1", "CIS", "Inventory", "Maintain software inventory",
        "Maintain an active inventory of all software in the organization.",
        "MEDIUM", "Use SBOM tooling; track deps in requirements.txt / package.json."),
    ComplianceControl("CIS-2.1", "CIS", "Config", "No default credentials",
        "Ensure no default passwords are in use.",
        "CRITICAL", "Rotate default credentials; enforce password policy.",
        ["CWE-798"]),
    ComplianceControl("CIS-3.1", "CIS", "Data", "Encrypt data at rest",
        "Sensitive data must be encrypted at rest.",
        "HIGH", "Use AES-256 encryption for all sensitive data stores.",
        ["NIST-SC-28"]),
    ComplianceControl("CIS-4.1", "CIS", "Logging", "Enable audit logging",
        "Enable audit logging for all security-relevant events.",
        "HIGH", "Configure structured logging with retention policy.",
        ["NIST-AU-2"]),
    ComplianceControl("CIS-5.1", "CIS", "Access", "Enforce MFA",
        "Require multi-factor authentication for all administrative accounts.",
        "CRITICAL", "Enforce TOTP/FIDO2 MFA for all admin logins."),
    ComplianceControl("CIS-6.1", "CIS", "Secrets", "No hardcoded credentials",
        "No credentials, API keys, or secrets in source code.",
        "CRITICAL", "Use vault/secrets manager; scan with secret-scanner.",
        ["CWE-798"]),
    ComplianceControl("CIS-7.1", "CIS", "Updates", "Apply security patches",
        "Apply security patches within 30 days of availability.",
        "HIGH", "Enable Dependabot; subscribe to security advisories."),

    # ── OWASP ─────────────────────────────────
    ComplianceControl("OWASP-A01", "OWASP", "Access Control", "Broken Access Control",
        "Implement proper access controls; deny by default.",
        "CRITICAL", "Use RBAC; test with automated tools.",
        ["CWE-284"]),
    ComplianceControl("OWASP-A02", "OWASP", "Cryptography", "Cryptographic Failures",
        "Protect data in transit and at rest with strong cryptography.",
        "CRITICAL", "Use TLS 1.3; AES-256; PBKDF2/bcrypt for passwords.",
        ["CWE-327"]),
    ComplianceControl("OWASP-A03", "OWASP", "Injection", "Injection Prevention",
        "Prevent SQL, OS, LDAP injection via parameterised queries.",
        "CRITICAL", "Use ORMs; parameterised queries; input validation.",
        ["CWE-89", "CWE-78"]),
    ComplianceControl("OWASP-A04", "OWASP", "Design", "Insecure Design",
        "Apply threat modelling and security design patterns.",
        "HIGH", "Conduct threat modelling; implement defence in depth."),
    ComplianceControl("OWASP-A05", "OWASP", "Config", "Security Misconfiguration",
        "Harden configurations; disable defaults; review headers.",
        "HIGH", "Run config scans; enable CSP/HSTS; disable debug in prod.",
        ["CWE-16"]),
    ComplianceControl("OWASP-A06", "OWASP", "Components", "Vulnerable Components",
        "Identify and update vulnerable third-party components.",
        "HIGH", "Use Dependabot/Snyk; maintain SBOM.",
        ["CWE-1104"]),
    ComplianceControl("OWASP-A07", "OWASP", "Auth", "Authentication Failures",
        "Implement strong authentication and session management.",
        "CRITICAL", "Use short-lived tokens; enforce MFA; rate-limit logins."),
    ComplianceControl("OWASP-A09", "OWASP", "Logging", "Security Logging Failures",
        "Log security events; alert on anomalies; retain logs.",
        "MEDIUM", "Implement SIEM; structured logging; log integrity checks."),
    ComplianceControl("OWASP-A10", "OWASP", "SSRF", "Server-Side Request Forgery",
        "Validate and sanitise all server-side URL fetches.",
        "HIGH", "Whitelist allowed hosts; block internal address ranges."),

    # ── NIST CSF ──────────────────────────────
    ComplianceControl("NIST-ID.AM", "NIST", "Identify", "Asset Management",
        "Maintain inventory of hardware and software assets.",
        "MEDIUM", "Implement CMDB; tag cloud resources."),
    ComplianceControl("NIST-PR.AC", "NIST", "Protect", "Identity & Access Management",
        "Manage identities, credentials and access authorisations.",
        "HIGH", "Implement RBAC; review access quarterly."),
    ComplianceControl("NIST-PR.DS", "NIST", "Protect", "Data Security",
        "Protect data at rest and in transit.",
        "HIGH", "Encrypt all sensitive data; enforce TLS everywhere."),
    ComplianceControl("NIST-DE.CM", "NIST", "Detect", "Security Continuous Monitoring",
        "Monitor networks, systems and facilities.",
        "HIGH", "Deploy SIEM/IDS; alert on anomalies."),
    ComplianceControl("NIST-RS.RP", "NIST", "Respond", "Response Planning",
        "Maintain and test incident response plan.",
        "HIGH", "Document runbooks; conduct tabletop exercises."),

    # ── SOC 2 ─────────────────────────────────
    ComplianceControl("SOC2-CC6.1", "SOC2", "Logical Access", "Logical Access Controls",
        "Restrict logical access to information assets.",
        "CRITICAL", "Implement principle of least privilege; review quarterly."),
    ComplianceControl("SOC2-CC6.3", "SOC2", "Logical Access", "Access Revocation",
        "Remove access promptly upon role change or termination.",
        "HIGH", "Automate deprovisioning; review orphaned accounts."),
    ComplianceControl("SOC2-CC7.2", "SOC2", "System Operations", "System Monitoring",
        "Monitor system components for anomalies.",
        "HIGH", "Deploy APM and security monitoring; set up alerting."),
    ComplianceControl("SOC2-A1.1", "SOC2", "Availability", "Performance Monitoring",
        "Monitor and maintain system performance.",
        "MEDIUM", "Define SLAs; implement health checks and auto-scaling."),

    # ── PCI-DSS ───────────────────────────────
    ComplianceControl("PCI-1.1", "PCI", "Network", "Firewall Configuration",
        "Install and maintain a firewall configuration.",
        "CRITICAL", "Enforce default-deny; document all firewall rules."),
    ComplianceControl("PCI-6.3", "PCI", "Vulnerabilities", "Security Vulnerability Assessment",
        "Identify and remediate security vulnerabilities.",
        "HIGH", "Run quarterly ASV scans; patch within 30 days."),
    ComplianceControl("PCI-8.3", "PCI", "Authentication", "Strong Authentication",
        "Secure individual non-consumer user authentication.",
        "CRITICAL", "Enforce MFA for all admin accounts."),
    ComplianceControl("PCI-10.1", "PCI", "Logging", "Audit Trail",
        "Implement audit trails to link access to individual users.",
        "HIGH", "Log all privileged actions; retain for 12 months."),
]


# ─────────────────────────────────────────────
# Automated checks
# ─────────────────────────────────────────────

CheckFn = Callable[[str], Tuple[str, str]]   # (status, evidence)


def _check_no_hardcoded_secrets(target_dir: str) -> Tuple[str, str]:
    """CIS-6.1: scan for common secret patterns."""
    secret_re = re.compile(
        r"(?i)(api_key|apikey|secret|password)\s*[:=]\s*['\"][A-Za-z0-9_\-]{8,}['\"]"
    )
    found = []
    for fpath in Path(target_dir).rglob("*"):
        if not fpath.is_file() or fpath.suffix in (".pyc", ".lock"):
            continue
        if any(d in fpath.parts for d in (".git", "__pycache__", "venv", ".venv")):
            continue
        try:
            for i, line in enumerate(fpath.read_text(errors="replace").splitlines(), 1):
                if secret_re.search(line):
                    found.append(f"{fpath}:{i}")
                    if len(found) >= 5:
                        break
        except Exception:
            pass
        if len(found) >= 5:
            break
    if found:
        return "FAIL", f"Potential secrets in: {', '.join(found[:3])}"
    return "PASS", "No hardcoded secrets detected"


def _check_logging_configured(target_dir: str) -> Tuple[str, str]:
    py_files = list(Path(target_dir).rglob("*.py"))
    uses_logging = any(
        "import logging" in p.read_text(errors="replace") or
        "import structlog" in p.read_text(errors="replace")
        for p in py_files[:20]
    )
    if uses_logging:
        return "PASS", "Logging configuration found"
    if py_files:
        return "WARN", "No logging module detected in Python sources"
    return "NA", "No Python source files found"


def _check_encryption_used(target_dir: str) -> Tuple[str, str]:
    patterns = ["cryptography", "hashlib", "hmac", "AES", "encrypt", "decrypt"]
    for fpath in Path(target_dir).rglob("*.py"):
        try:
            text = fpath.read_text(errors="replace")
            if any(p in text for p in patterns):
                return "PASS", f"Encryption usage found in {fpath.name}"
        except Exception:
            pass
    return "WARN", "No obvious encryption usage found in Python sources"


def _check_requirements_present(target_dir: str) -> Tuple[str, str]:
    for name in ("requirements.txt", "requirements-dev.txt", "pyproject.toml", "setup.cfg"):
        if (Path(target_dir) / name).exists():
            return "PASS", f"{name} found"
    return "WARN", "No requirements file found – dependency inventory lacking"


def _check_env_gitignore(target_dir: str) -> Tuple[str, str]:
    gi = Path(target_dir) / ".gitignore"
    if gi.exists():
        content = gi.read_text(errors="replace")
        if ".env" in content:
            return "PASS", ".env listed in .gitignore"
        return "WARN", ".gitignore exists but does not exclude .env"
    return "FAIL", "No .gitignore found – .env files may be committed"


AUTOMATED_CHECKS: Dict[str, CheckFn] = {
    "CIS-6.1": _check_no_hardcoded_secrets,
    "CIS-4.1": _check_logging_configured,
    "CIS-3.1": _check_encryption_used,
    "CIS-1.1": _check_requirements_present,
    "OWASP-A02": _check_encryption_used,
    "OWASP-A09": _check_logging_configured,
    "OWASP-A06": _check_requirements_present,
}


# ─────────────────────────────────────────────
# SQLite persistence
# ─────────────────────────────────────────────

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_runs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    framework  TEXT NOT NULL,
    target     TEXT NOT NULL,
    score      REAL NOT NULL,
    total      INTEGER, passed INTEGER, failed INTEGER, warned INTEGER,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS control_results (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id     INTEGER REFERENCES scan_runs(id),
    control_id TEXT NOT NULL,
    status     TEXT NOT NULL,
    evidence   TEXT DEFAULT '',
    detail     TEXT DEFAULT '',
    checked_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS exceptions (
    control_id  TEXT PRIMARY KEY,
    reason      TEXT NOT NULL,
    approved_by TEXT DEFAULT '',
    expires_at  TEXT DEFAULT NULL,
    created_at  TEXT DEFAULT (datetime('now'))
);
"""


class ComplianceDB:
    def __init__(self, db_path: str = "compliance.db"):
        self.db_path = db_path
        with self._conn() as conn:
            conn.executescript(DB_SCHEMA)

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def save_report(self, report: ComplianceReport) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO scan_runs (framework,target,score,total,passed,failed,warned) "
                "VALUES (?,?,?,?,?,?,?)",
                (report.framework, report.target, report.score, report.controls_total,
                 report.controls_passed, report.controls_failed, report.controls_warn),
            )
            run_id = cur.lastrowid
            for r in report.results:
                conn.execute(
                    "INSERT INTO control_results (run_id,control_id,status,evidence,detail) "
                    "VALUES (?,?,?,?,?)",
                    (run_id, r.control_id, r.status, r.evidence, r.detail),
                )
        return run_id

    def list_runs(self, limit: int = 20) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_runs ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    def add_exception(self, control_id: str, reason: str, approved_by: str = "") -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO exceptions (control_id,reason,approved_by) VALUES (?,?,?)",
                (control_id, reason, approved_by),
            )

    def get_exceptions(self) -> Dict[str, Dict]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM exceptions").fetchall()
            return {r["control_id"]: dict(r) for r in rows}


# ─────────────────────────────────────────────
# Scanner engine
# ─────────────────────────────────────────────

class ComplianceEngine:
    def __init__(self, db_path: str = "compliance.db"):
        self.db = ComplianceDB(db_path)

    def run_scan(self, target: str, framework: str = "ALL") -> ComplianceReport:
        exceptions = self.db.get_exceptions()
        controls = CONTROLS if framework == "ALL" else [
            c for c in CONTROLS if c.framework == framework
        ]
        results: List[ComplianceResult] = []

        for ctrl in controls:
            if ctrl.id in exceptions:
                exc = exceptions[ctrl.id]
                results.append(ComplianceResult(
                    ctrl.id, "SKIP",
                    evidence=f"Exception: {exc['reason']}",
                    detail=f"Approved by {exc.get('approved_by','N/A')}",
                ))
                continue

            if ctrl.id in AUTOMATED_CHECKS:
                try:
                    status, evidence = AUTOMATED_CHECKS[ctrl.id](target)
                except Exception as e:
                    status, evidence = "WARN", f"Check failed: {e}"
            else:
                status, evidence = "NA", "Manual review required"

            results.append(ComplianceResult(ctrl.id, status, evidence=evidence))

        passed = sum(1 for r in results if r.status == "PASS")
        failed = sum(1 for r in results if r.status == "FAIL")
        warned = sum(1 for r in results if r.status == "WARN")
        total = len([r for r in results if r.status != "SKIP"])
        score = round((passed / total) * 100, 1) if total else 0.0

        report = ComplianceReport(
            framework=framework,
            target=target,
            generated=datetime.now(timezone.utc).isoformat(),
            controls_total=len(controls),
            controls_passed=passed,
            controls_failed=failed,
            controls_warn=warned,
            score=score,
            results=results,
        )
        self.db.save_report(report)
        return report


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="BlackRoad Compliance Framework")
    p.add_argument("--db", default="compliance.db")
    sub = p.add_subparsers(dest="cmd")

    sc = sub.add_parser("scan", help="Run compliance scan")
    sc.add_argument("target", nargs="?", default=".")
    sc.add_argument("--framework", default="ALL",
                    choices=["ALL","CIS","OWASP","NIST","SOC2","PCI"])
    sc.add_argument("--output", "-o", default=None)
    sc.add_argument("--format", choices=["text","json"], default="text")

    sub.add_parser("list-runs", help="List past scan runs")

    ex = sub.add_parser("add-exception", help="Add control exception")
    ex.add_argument("control_id")
    ex.add_argument("reason")
    ex.add_argument("--approved-by", default="")

    lc = sub.add_parser("list-controls", help="List all controls")
    lc.add_argument("--framework", default="ALL")

    args = p.parse_args(argv)
    engine = ComplianceEngine(args.db)

    if args.cmd == "scan":
        print(f"\n[*] Scanning '{args.target}' against {args.framework} controls...")
        report = engine.run_scan(args.target, args.framework)
        if args.format == "json":
            out = json.dumps(report.to_dict(), indent=2)
            if args.output:
                Path(args.output).write_text(out)
            else:
                print(out)
        else:
            print(f"\n{'='*60}")
            print(f"  Compliance Report – {args.framework}")
            print(f"{'='*60}")
            print(f"  Score     : {report.score:.1f}%")
            print(f"  Total     : {report.controls_total}")
            print(f"  ✅ PASS   : {report.controls_passed}")
            print(f"  ❌ FAIL   : {report.controls_failed}")
            print(f"  ⚠️  WARN   : {report.controls_warn}")
            print(f"{'='*60}\n")
            for r in sorted(report.results, key=lambda x: {"FAIL":0,"WARN":1,"PASS":2,"NA":3,"SKIP":4}.get(x.status,5)):
                icon = {"PASS":"✅","FAIL":"❌","WARN":"⚠️ ","NA":"➖","SKIP":"⏭️ "}.get(r.status,"  ")
                print(f"  {icon} [{r.status:<4}] {r.control_id:<15} {r.evidence[:60]}")
        return 1 if report.controls_failed > 0 else 0

    elif args.cmd == "list-runs":
        for run in engine.db.list_runs():
            print(f"  #{run['id']:<4} {run['created_at']}  {run['framework']:<8}  {run['score']:.1f}%  {run['target']}")

    elif args.cmd == "add-exception":
        engine.db.add_exception(args.control_id, args.reason, args.approved_by)
        print(f"✅ Exception added for {args.control_id}")

    elif args.cmd == "list-controls":
        fw = args.framework
        controls = CONTROLS if fw == "ALL" else [c for c in CONTROLS if c.framework == fw]
        for c in controls:
            print(f"  {c.id:<15} [{c.severity:<8}] {c.title}")

    else:
        p.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
