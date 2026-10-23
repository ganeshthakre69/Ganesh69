#!/usr/bin/env python3
"""
Enterprise Ransomware Assessment
A lightweight risk-register builder aligned to the NIST Cybersecurity Framework (CSF) 2.0.

This is an assessment aid, not a substitute for a formal enterprise risk process.
Review all scores, owners, controls, and target dates with the relevant stakeholders.
"""
from __future__ import annotations

import argparse
import csv
from dataclasses import asdict, dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import List

CSF_FUNCTIONS = {"GV": "Govern", "ID": "Identify", "PR": "Protect",
                 "DE": "Detect", "RS": "Respond", "RC": "Recover"}

@dataclass
class Risk:
    risk_id: str
    title: str
    scenario: str
    csf_function: str
    csf_category: str
    likelihood: int
    impact: int
    existing_controls: str
    recommended_treatment: str
    owner: str
    target_date: str
    status: str = "Open"

    @property
    def inherent_score(self) -> int:
        return self.likelihood * self.impact

    @property
    def rating(self) -> str:
        score = self.inherent_score
        if score >= 20:
            return "Critical"
        if score >= 15:
            return "High"
        if score >= 8:
            return "Moderate"
        return "Low"

def starter_risks() -> List[Risk]:
    """Illustrative starter risks; tailor likelihood and impact to your organization."""
    due = date.today() + timedelta(days=90)
    return [
        Risk("R-001", "Unmanaged privileged access",
             "An attacker compromises a privileged account and deploys ransomware across critical systems.",
             "PR", "PR.AA — Identity Management, Authentication, and Access Control",
             4, 5, "MFA on selected systems; periodic access reviews",
             "Enforce phishing-resistant MFA for administrators; use PAM/JIT elevation; review privileged access quarterly.",
             "Identity & Access Management", due.isoformat()),
        Risk("R-002", "Phishing and credential theft",
             "A user follows a malicious link or opens a weaponized attachment, enabling credential theft and initial access.",
             "PR", "PR.AT — Awareness and Training; PR.DS — Data Security",
             4, 4, "Email filtering; annual awareness training",
             "Run role-based phishing exercises; improve email authentication and attachment detonation; use conditional access.",
             "Security Awareness Lead", due.isoformat()),
        Risk("R-003", "Insufficient endpoint detection",
             "Ransomware executes on an endpoint without timely alerting, allowing lateral movement and encryption.",
             "DE", "DE.CM — Continuous Monitoring",
             3, 5, "Endpoint protection on managed laptops",
             "Deploy centrally monitored EDR to servers and endpoints; tune detections; test alert escalation and coverage.",
             "Security Operations", due.isoformat()),
        Risk("R-004", "Excessive network reachability",
             "An attacker moves laterally from a compromised workstation to server and backup networks.",
             "PR", "PR.IR — Technology Infrastructure Resilience",
             3, 5, "Core firewall rules; some network segmentation",
             "Segment user, server, identity, and backup networks; restrict east-west traffic; review rules and remote access.",
             "Network Security", due.isoformat()),
        Risk("R-005", "Backups exposed to ransomware",
             "Attackers delete or encrypt online backups, preventing timely restoration after a ransomware incident.",
             "RC", "RC.RP — Incident Recovery Plan Execution",
             3, 5, "Daily backups; limited restore testing",
             "Maintain immutable/offline copies; isolate backup credentials; test clean restores and recovery time objectives.",
             "Infrastructure & Backup", due.isoformat()),
        Risk("R-006", "Unverified incident response readiness",
             "Teams lack a practiced ransomware playbook, delaying containment, communications, and recovery decisions.",
             "RS", "RS.MA — Incident Management",
             3, 4, "General incident response policy",
             "Create a ransomware playbook with legal, privacy, communications, IT, and executive roles; conduct tabletop exercises.",
             "Incident Response Lead", due.isoformat()),
        Risk("R-007", "Critical asset inventory gaps",
             "An unknown or unsupported asset remains unpatched and becomes an entry point for ransomware.",
             "ID", "ID.AM — Asset Management",
             3, 4, "Partial endpoint inventory",
             "Reconcile endpoint, cloud, identity, and OT/IoT inventories; assign business criticality and system owners.",
             "IT Asset Management", due.isoformat()),
        Risk("R-008", "Weak third-party access governance",
             "A compromised supplier account or remote management tool is used to access enterprise systems.",
             "GV", "GV.SC — Cybersecurity Supply Chain Risk Management",
             3, 5, "Supplier questionnaires for selected vendors",
             "Inventory critical suppliers; constrain vendor access; require MFA, time-bound approvals, logging, and incident notice terms.",
             "Third-Party Risk", due.isoformat()),
        Risk("R-009", "Delayed vulnerability remediation",
             "An exploitable internet-facing or high-value system remains vulnerable and is used for initial access.",
             "ID", "ID.RA — Risk Assessment",
             3, 4, "Periodic vulnerability scans",
             "Prioritize remediation by exploitability and asset criticality; define SLAs; verify closure through rescanning.",
             "Vulnerability Management", due.isoformat()),
        Risk("R-010", "Recovery dependencies not validated",
             "Restoration fails because identity, DNS, certificates, or clean build dependencies are unavailable.",
             "RC", "RC.RP — Incident Recovery Plan Execution",
             2, 5, "Documented recovery steps for selected services",
             "Map service dependencies; maintain clean recovery credentials and golden images; test recovery in an isolated environment.",
             "Business Continuity", due.isoformat()),
    ]

def write_csv(risks: List[Risk], path: Path) -> None:
    fields = ["risk_id", "title", "scenario", "csf_function", "csf_category",
              "likelihood", "impact", "inherent_score", "rating", "existing_controls",
              "recommended_treatment", "owner", "target_date", "status"]
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for risk in risks:
            row = asdict(risk)
            row["inherent_score"] = risk.inherent_score
            row["rating"] = risk.rating
            writer.writerow(row)

def read_csv(path: Path) -> List[dict]:
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))

def main() -> None:
    parser = argparse.ArgumentParser(description="Generate an illustrative ransomware risk register.")
    parser.add_argument("--output", default="ransomware_risk_register.csv", help="Output CSV file path")
    parser.add_argument("--input", help="Optional CSV to recalculate scores for a user-maintained register")
    args = parser.parse_args()
    out = Path(args.output)
    if args.input:
        rows = read_csv(Path(args.input))
        fields = list(rows[0].keys()) if rows else []
        for row in rows:
            try:
                likelihood, impact = int(row["likelihood"]), int(row["impact"])
                if not (1 <= likelihood <= 5 and 1 <= impact <= 5):
                    raise ValueError
                score = likelihood * impact
                row["inherent_score"] = score
                row["rating"] = "Critical" if score >= 20 else "High" if score >= 15 else "Moderate" if score >= 8 else "Low"
            except (KeyError, ValueError):
                raise SystemExit("Each row must include integer likelihood and impact values from 1 to 5.")
        if "inherent_score" not in fields: fields.append("inherent_score")
        if "rating" not in fields: fields.append("rating")
        with out.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
        print(f"Recalculated {len(rows)} risk(s) -> {out.resolve()}")
    else:
        risks = starter_risks()
        write_csv(risks, out)
        print(f"Created {len(risks)} illustrative risks -> {out.resolve()}")
        print("Review each score, owner, control, treatment, and target date before using this register.")

if __name__ == "__main__":
    main()
