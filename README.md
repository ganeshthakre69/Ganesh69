# Enterprise Ransomware Assessment

**Project title:** Enterprise Ransomware Assessment: Drafted a corporate risk register mapped to the NIST CSF framework.

This educational project generates a CSV risk register with illustrative ransomware scenarios, 1–5 likelihood and impact scores, inherent risk ratings, proposed treatments, owners, and target dates. Risks are mapped to the six functions of **NIST Cybersecurity Framework (CSF) 2.0**: Govern, Identify, Protect, Detect, Respond, and Recover.

> **Important:** This is a starter assessment, not a formal audit or a statement of compliance. The sample scores and controls are illustrative. Validate them with system owners, security staff, legal/privacy stakeholders, and enterprise risk management before making decisions.

## Files

- `ransomware_assessment.py` — Python CLI risk-register generator / score recalculator.
- `requirements.txt` — dependency note (Python standard library only).
- `requirements.pdf` — printable environment and dependency requirements.
- `project_report.pdf` — project report with the supplied university logo.
- `university_logo.png` — supplied logo included in the report.
- `ransomware_risk_register.csv` — generated example register.

## Requirements

- Python 3.10 or newer.
- No third-party Python packages are required; the script uses the standard library.
- A spreadsheet editor (Excel, LibreOffice Calc, or equivalent) to review the CSV is optional.
- Organizational context: critical asset inventory, threat scenarios, control evidence, business impact analysis, risk owners, and risk acceptance criteria.

## Generate the sample register

```bash
python ransomware_assessment.py
```

This creates `ransomware_risk_register.csv` in the current directory.

Choose an output path:

```bash
python ransomware_assessment.py --output output/my_risk_register.csv
```

The parent directory must already exist.

## Recalculate an edited register

Edit the CSV's `likelihood` and `impact` columns with values from 1 to 5, then run:

```bash
python ransomware_assessment.py --input ransomware_risk_register.csv --output scored_register.csv
```

Risk score = likelihood × impact.

| Score | Illustrative rating |
|---:|---|
| 20–25 | Critical |
| 15–19 | High |
| 8–14 | Moderate |
| 1–7 | Low |

These bands are example thresholds only. Replace them with your organization's approved risk methodology if it differs. The score is an inherent-risk score; it does not calculate residual risk after controls.

## NIST CSF mapping

The register uses the CSF 2.0 functions:
- **GV — Govern:** policy, accountability, and supply-chain risk oversight.
- **ID — Identify:** assets, business context, and risk assessment.
- **PR — Protect:** identity/access, awareness, data security, and infrastructure safeguards.
- **DE — Detect:** monitoring and detection capabilities.
- **RS — Respond:** incident management and response coordination.
- **RC — Recover:** recovery execution and restoration planning.

Category labels are representative mappings to CSF 2.0 concepts. Verify exact subcategory applicability and wording against the official framework and your chosen profile.

## Suggested workflow

1. Identify critical business services, assets, data, and dependencies.
2. Conduct workshops to define ransomware scenarios and business consequences.
3. Rate likelihood and impact using a documented scale.
4. Record existing controls and evidence; do not assume a control is effective without validation.
5. Assign an accountable risk owner and treatment owner.
6. Agree on a treatment plan, due date, and measurable completion criteria.
7. Assess residual risk after implementation and document acceptance/escalation.
8. Review the register periodically and after major changes or incidents.

## Limitations and safety

- Starter scenarios and ratings are not organization-specific.
- The script does not connect to security products, scan systems, or execute ransomware.
- It does not estimate financial loss, calculate residual risk, or determine compliance.
- CSF mapping is a planning aid; the register alone does not establish NIST CSF conformance.
- Do not place sensitive architecture details or confidential incident information in a public repository.

## Reference

NIST Cybersecurity Framework 2.0: https://www.nist.gov/cyberframework
