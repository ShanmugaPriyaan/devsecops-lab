from prioritise import score, assign_tier, POLICY_P1

kev = {"CVE-TEST-0001"}
epss = {}

def make_row(exposed):
    return {"cve": "CVE-TEST-0001", "asset": "test", "asset_criticality": "1",
            "internet_exposed": exposed, "cvss": "2.0", "kev": "yes"}

# Case 1: KEV + exposed, low score -> the policy must fire
row = make_row("yes")
row["score"] = score(row, kev, epss)
assert row["score"] == 69
assert assign_tier(row) == ("P2", "72 hours", POLICY_P1)

# Case 2: KEV but NOT exposed -> the policy must NOT fire; the model decides
row = make_row("no")
row["score"] = score(row, kev, epss)
assert row["score"] == 49
assert assign_tier(row) == ("P3", "72 hours", POLICY_P1)

print("All tests passed")