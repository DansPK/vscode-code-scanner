"""Download Semgrep rule packs and merge them into one file, one copy of each rule.

Packs overlap a lot (p/default, p/java, p/owasp-top-ten...). Loaded as separate files, the
same rule would run once per file and report every problem several times.

Usage: python fetch_semgrep_rules.py <out.yml>   (needs PyYAML; run at image build time)
"""

import sys
import urllib.request
from pathlib import Path

import yaml

PACKS = [
    # general
    "default", "secrets", "security-audit", "owasp-top-ten", "xss", "sql-injection", "command-injection",
    "jwt", "insecure-transport",
    # languages and frameworks
    "python", "django", "flask", "java", "kotlin", "scala", "csharp", "javascript", "typescript", "react",
    "nodejs", "golang", "php", "ruby", "c", "rust", "swift",
    # infrastructure as code
    "terraform", "dockerfile", "kubernetes",
]


# Our own rules (rules/*.yml next to this script's folder) are added first.
LOCAL_RULES = Path(__file__).resolve().parent.parent / "rules"


def main(out):
    rules, sources = {}, {}
    for path in sorted(LOCAL_RULES.glob("*.yml")):
        for rule in (yaml.safe_load(path.read_text()) or {}).get("rules", []):
            rules[rule["id"]] = rule
    for pack in PACKS:
        with urllib.request.urlopen(f"https://semgrep.dev/c/p/{pack}", timeout=120) as r:
            data = yaml.safe_load(r.read()) or {}
        for rule in data.get("rules", []):
            rules.setdefault(rule["id"], rule)
            sources.setdefault(pack, 0)
            sources[pack] += 1
    with open(out, "w") as f:
        yaml.safe_dump({"rules": list(rules.values())}, f, sort_keys=False)
    print(f"{len(rules)} unique rules from {len(PACKS)} packs and {LOCAL_RULES.name}/ -> {out}", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1])
