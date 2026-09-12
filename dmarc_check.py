#!/usr/bin/env python3
"""
dmarc_check.py — grade the email-spoofing defenses of a list of domains.

Reads a CSV with at least two columns: name, domain
Writes a CSV with the grade for each domain, plus a summary and,
for every unprotected domain, the exact DNS records that would fix it.

All lookups are public DNS queries — the same thing your browser does
to find a website. Nothing is sent to the organizations themselves.

Usage:
    pip install dnspython
    python3 dmarc_check.py domains.csv results.csv
"""

import csv
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
import dns.exception

RESOLVER = dns.resolver.Resolver()
RESOLVER.timeout = 5
RESOLVER.lifetime = 10
# Uses the system resolver by default. To force public resolvers so results
# don't depend on the machine running this, uncomment:
# RESOLVER.nameservers = ["1.1.1.1", "8.8.8.8"]

# DKIM selectors that cover the big email providers. DKIM can't be checked
# without knowing the selector, so this is best-effort: "found" is meaningful,
# "not found" is not.
COMMON_DKIM_SELECTORS = [
    "google", "selector1", "selector2", "k1", "default", "dkim", "mail",
    "s1", "s2", "everlytickey1", "mandrill", "smtp",
]


def txt_records(name):
    """Return the TXT strings at a DNS name, [] if none / NXDOMAIN,
    or None if the lookup itself failed (timeout / SERVFAIL)."""
    for tcp in (False, True):  # retry over TCP: big TXT answers get truncated over UDP
        try:
            ans = RESOLVER.resolve(name, "TXT", tcp=tcp)
            return [b"".join(r.strings).decode("utf-8", "ignore") for r in ans]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return []
        except dns.exception.DNSException:
            continue
    return None


def has_mx(domain):
    try:
        RESOLVER.resolve(domain, "MX")
        return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return False
    except dns.exception.DNSException:
        return None


def parse_dmarc(record):
    """Turn 'v=DMARC1; p=reject; rua=...' into a dict."""
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def check_domain(name, domain):
    domain = domain.strip().lower().rstrip(".")
    row = {
        "name": name,
        "domain": domain,
        "mx": None,
        "spf": "",
        "spf_mode": "",
        "dmarc": "",
        "dmarc_policy": "",
        "dmarc_pct": "",
        "dmarc_reporting": "",
        "dkim_found": "",
        "grade": "",
        "note": "",
    }

    # --- MX: does this domain even receive mail? ---
    row["mx"] = has_mx(domain)

    # --- SPF ---
    txts = txt_records(domain)
    if txts is None:
        txts = []
        row["spf_mode"] = "LOOKUP_FAILED"
        row["note"] = "SPF lookup timed out (rerun to confirm)"
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    if len(spf) > 1:
        row["spf"] = spf[0]
        row["spf_mode"] = "MULTIPLE (invalid)"
    elif spf:
        row["spf"] = spf[0]
        m = re.search(r"([-~?+])all\b", spf[0])
        row["spf_mode"] = {
            "-": "hardfail (-all)",
            "~": "softfail (~all)",
            "?": "neutral (?all)",
            "+": "pass-all (+all) — allows anyone",
        }.get(m.group(1), "no all mechanism") if m else "no all mechanism"
    elif row["spf_mode"] != "LOOKUP_FAILED":
        row["spf_mode"] = "NONE"

    # --- DMARC ---
    dtxts = txt_records(f"_dmarc.{domain}")
    if dtxts is None:
        row["grade"] = "LOOKUP_FAILED"
        row["note"] = "DNS timeout / SERVFAIL on _dmarc"
        return row
    dmarc = [t for t in dtxts if t.lower().startswith("v=dmarc1")]
    if dmarc:
        row["dmarc"] = dmarc[0]
        tags = parse_dmarc(dmarc[0])
        row["dmarc_policy"] = tags.get("p", "").lower() or "(missing p=)"
        row["dmarc_pct"] = tags.get("pct", "100")
        row["dmarc_reporting"] = "yes" if tags.get("rua") else "no"
    else:
        row["dmarc_policy"] = "NONE"

    # --- DKIM (best-effort) ---
    found = []
    for sel in COMMON_DKIM_SELECTORS:
        r = txt_records(f"{sel}._domainkey.{domain}")
        if r and any("v=dkim1" in t.lower() or "k=rsa" in t.lower() or "p=" in t.lower() for t in r):
            found.append(sel)
    row["dkim_found"] = ",".join(found) if found else "none of common selectors"

    # --- Grade ---
    p = row["dmarc_policy"]
    pct = row["dmarc_pct"]
    try:
        pct_i = int(pct)
    except (TypeError, ValueError):
        pct_i = 100

    if p == "NONE":
        row["grade"] = "NO_DMARC"
    elif p == "none":
        row["grade"] = "MONITOR_ONLY"
    elif p in ("quarantine", "reject") and pct_i < 100:
        row["grade"] = "PARTIAL"
        row["note"] = f"policy {p} applied to only {pct_i}% of mail"
    elif p == "quarantine":
        row["grade"] = "ENFORCED_QUARANTINE"
    elif p == "reject":
        row["grade"] = "ENFORCED_REJECT"
    else:
        row["grade"] = "MALFORMED"
        row["note"] = f"unrecognized policy: {p}"

    if row["spf_mode"] == "NONE" and row["grade"] not in ("ENFORCED_REJECT", "ENFORCED_QUARANTINE"):
        row["note"] = (row["note"] + "; " if row["note"] else "") + "no SPF record either"

    return row


def fix_records(domain):
    """The exact DNS records an unprotected domain should add, in order."""
    return f"""
=== {domain} ===
Step 1 (today, safe, breaks nothing) — turn on monitoring:
  Host:  _dmarc.{domain}
  Type:  TXT
  Value: v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain}; fo=1

Step 2 (after 2-4 weeks of reading reports, once all legitimate senders pass):
  Value: v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-reports@{domain}; fo=1

Step 3 (final, recommended by CISA for government domains):
  Value: v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@{domain}; fo=1

If there is no SPF record, add one listing your real mail servers, for example
for Google Workspace:
  Host:  {domain}
  Type:  TXT
  Value: v=spf1 include:_spf.google.com -all
(replace the include with your actual provider — Microsoft 365 is include:spf.protection.outlook.com)
"""


def main(in_path, out_path):
    with open(in_path, newline="") as f:
        rows = [r for r in csv.DictReader(f) if r.get("domain", "").strip()]

    results = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = {ex.submit(check_domain, r.get("name", ""), r["domain"]): r for r in rows}
        for i, fut in enumerate(as_completed(futs), 1):
            res = fut.result()
            results.append(res)
            print(f"[{i}/{len(rows)}] {res['domain']:<40} {res['grade']}", file=sys.stderr)

    results.sort(key=lambda r: (r["name"] or r["domain"]).lower())

    fields = ["name", "domain", "mx", "grade", "dmarc_policy", "dmarc_pct",
              "dmarc_reporting", "spf_mode", "dkim_found", "note", "spf", "dmarc"]
    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(results)

    # --- Summary ---
    total = len(results)
    counts = {}
    for r in results:
        counts[r["grade"]] = counts.get(r["grade"], 0) + 1
    unprotected = counts.get("NO_DMARC", 0) + counts.get("MONITOR_ONLY", 0) + counts.get("PARTIAL", 0) + counts.get("MALFORMED", 0)
    checked = total - counts.get("LOOKUP_FAILED", 0)

    print("\n================ SUMMARY ================")
    print(f"Domains checked: {checked} (of {total}; {counts.get('LOOKUP_FAILED', 0)} lookup failures)")
    for g in ["NO_DMARC", "MONITOR_ONLY", "PARTIAL", "MALFORMED", "ENFORCED_QUARANTINE", "ENFORCED_REJECT"]:
        if counts.get(g):
            print(f"  {g:<22} {counts[g]:>4}   ({100*counts[g]/checked:.0f}%)")
    print(f"\nNOT ENFORCED (spoofable): {unprotected} of {checked} = {100*unprotected/checked:.0f}%")
    print("  ('NO_DMARC' + 'MONITOR_ONLY' + 'PARTIAL' + 'MALFORMED')")
    print(f"\nResults written to {out_path}")

    # --- Fix records for every unprotected domain ---
    fix_path = out_path.rsplit(".", 1)[0] + "_fixes.txt"
    with open(fix_path, "w") as f:
        f.write("DNS records to fix each unprotected domain.\n"
                "Start at Step 1 (p=none). Never jump straight to p=reject on a domain\n"
                "that has never had DMARC — legitimate mail from unlisted senders will bounce.\n")
        for r in results:
            if r["grade"] in ("NO_DMARC", "MONITOR_ONLY", "PARTIAL", "MALFORMED"):
                f.write(fix_records(r["domain"]))
    print(f"Fix records written to {fix_path}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
