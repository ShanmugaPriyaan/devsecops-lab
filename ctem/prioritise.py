"""Risk-based prioritisation of vulnerability findings (CTEM "prioritisation" stage).

Usage: python3 prioritise.py findings_sample.csv
Input columns: cve, asset, asset_criticality (1-3, 3 = holds PHI / business critical),
internet_exposed (yes/no), cvss.
Enriches each CVE with live threat data:
  - CISA KEV: is it known to be exploited in the wild?
  - FIRST EPSS: probability it is exploited in the next 30 days.
The scoring weights are a simple, explainable example. Tune them with the business,
or replace them with a decision tree such as CISA SSVC.
"""
import csv
import sys

import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

# (minimum score, tier, remediation SLA)
TIERS = [(70, "P1", "72 hours"), (45, "P2", "14 days"), (25, "P3", "30 days"), (0, "P4", "next cycle")]

POLICY_P1 = "CISO policy: KEV + internet-exposed"

def assign_tier(row):
    """Return (tier, sla, reason). The model scores; policy rules run last and win."""
    tier, sla = next((t, s) for floor, t, s in TIERS if row["score"] >= floor)   # your existing next(...) line, moved here
    # TODO: if KEV is yes AND internet_exposed is yes AND the model didn't already say P1,
    #       return "P1", "72 hours", POLICY_P1
    return tier, sla, "score"

def load_kev():
    data = requests.get(KEV_URL, timeout=30).json()
    return {v["cveID"] for v in data["vulnerabilities"]}


def load_epss(cves):
    data = requests.get(EPSS_URL, params={"cve": ",".join(cves)}, timeout=30).json()
    return {d["cve"]: float(d["epss"]) for d in data["data"]}


def score(row, kev, epss):
    points = float(row["cvss"]) * 2                   # severity: up to 20
    points += 40 if row["cve"] in kev else 0          # exploited in the wild
    points += round(epss.get(row["cve"], 0) * 30)     # likely to be exploited: up to 30
    points += 20 if row["internet_exposed"] == "yes" else 0
    points += int(row["asset_criticality"]) * 5       # business impact: up to 15
    return points


def main():
    with open(sys.argv[1], newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    kev = load_kev()
    epss = load_epss([r["cve"] for r in rows])

    for row in rows:
        row["kev"] = "yes" if row["cve"] in kev else "no"
        row["epss"] = epss.get(row["cve"], 0)
        row["score"] = score(row, kev, epss)
        row["tier"], row["sla"], row["reason"] = assign_tier(row) # assign_tier(row) returns (tier, sla, reason), but we only want tier and sla here

    rows.sort(key=lambda r: r["score"], reverse=True)
    print(f'{"Tier":<5}{"Score":>6}  {"CVE":<16}{"CVSS":>5}{"EPSS":>7}  {"KEV":<4} {"Exposed":<8}Asset (SLA)')
    for r in rows:
        print(f'{r["tier"]:<5}{r["score"]:>6.0f}  {r["cve"]:<16}{float(r["cvss"]):>5}{r["epss"]:>7.2f}  '
              f'{r["kev"]:<4} {r["internet_exposed"]:<8}{r["asset"]} ({r["sla"]}) {r["reason"]}')


if __name__ == "__main__":
    main()
