"""Summarise the pipeline's SARIF files as a markdown report.

Usage: python3 sarif_summary.py file1.sarif file2.sarif ...
Prints findings per tool, per severity level, the top rules and the top CWEs,
so each build has a number you can trend (e.g. findings per build over a month).
"""
import collections
import json
import re
import sys


def load(paths):
    findings = []
    for path in paths:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for run in data.get("runs", []):
            driver = run["tool"]["driver"]
            tool = driver.get("name", "unknown")
            # Map each rule to the CWE IDs mentioned anywhere in its metadata
            rule_cwes = {}
            for rule in driver.get("rules", []):
                rule_cwes[rule["id"]] = sorted(set(re.findall(r"CWE-\d+", json.dumps(rule))))
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "unknown")
                findings.append({
                    "tool": tool,
                    "rule": rule_id,
                    "level": result.get("level", "warning"),
                    "cwes": rule_cwes.get(rule_id, []),
                })
    return findings


def table(title, counter, limit=None):
    print(f"\n### {title}\n")
    print("| Item | Count |")
    print("|---|---|")
    for item, count in counter.most_common(limit):
        print(f"| {item} | {count} |")


def main():
    findings = load(sys.argv[1:])
    print("## Security findings this build")
    print(f"\n**Total findings:** {len(findings)}")
    table("By tool", collections.Counter(f["tool"] for f in findings))
    table("By level (error = blocks the build)", collections.Counter(f["level"] for f in findings))
    table("Top 10 rules", collections.Counter(f'{f["tool"]}: {f["rule"]}' for f in findings), 10)
    table("Top weakness types (CWE)", collections.Counter(c for f in findings for c in f["cwes"]), 10)


if __name__ == "__main__":
    main()
