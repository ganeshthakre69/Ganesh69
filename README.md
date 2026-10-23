# Ganesh69
validated",
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
