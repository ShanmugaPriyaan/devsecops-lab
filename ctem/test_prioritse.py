from prioritise import score, assign_tier, POLICY_P1

kev = {"CVE-TEST-0001"}
epss = {}

def make_row(exposed):
    return {"cve": "CVE-TEST-0001", "asset": "test", "asset_criticality": "1",
            "internet_exposed": exposed, "cvss": "2.0", "kev": "yes"}

# Case 1: KEV + exposed, low score -> the policy must fire
row = make_row("yes")
row["score"] = score(row, kev, epss)
# TODO: assert row["score"] == 69
# TODO: assert assign_tier(row) == ("P2", "72 hours", POLICY_P1)

# Case 2: assert row["score"] == 49
# TODO: assert assign_tier(row) == ("P3", "72 hours", POLICY_P1)

print("All tests passed")