# NC Email Spoofing Audit

**68% of North Carolina's public school districts and municipalities cannot reject forged email today.**

This repo checks whether an organization's email domain has DMARC enforcement turned on, which is the free, standard control that stops someone from sending mail that appears to come from that domain. Every NC public school district (115) and every NC municipality with a web domain (495) was checked in September 2026. Nothing was sent to or accessed on any organization's systems; every check is a public DNS lookup, the same thing a browser does to find a website.

## Findings (September 2026)

| | Checked | Not enforced | % |
|---|---|---|---|
| School districts | 115 | 40 | 35% |
| Municipalities | 494 | 376 | 76% |
| **Total** | **609** | **416** | **68%** |

Breakdown of the 416:
- **285** have no DMARC record at all
- **120** have DMARC set to `p=none` (monitoring only; reports forged mail, blocks nothing)
- **10** enforce on only part of their mail (`pct` below 100)
- **1** has a typo in a live record (`p=Quarntine`), which mail servers ignore entirely

Districts are roughly twice as protected as towns. About a third of organizations use a different domain for email than for their website, and the unused domain is usually the unprotected one; 61 such email domains were checked separately (`mail_domains_results.csv`), and 44 of those were also unenforced.

## Why it matters

A forged email from a superintendent or town manager asking a clerk to update a vendor's bank details is business email compromise, the most expensive category of cybercrime the FBI reports each year. Local governments and school districts are frequent targets. DMARC at `p=reject` stops that email from ever reaching the inbox. It costs nothing and takes an IT person about twenty minutes.

## What's here

- `dmarc_check.py` — grades every domain in a CSV (SPF, DMARC policy, DKIM best-effort) and writes the exact DNS records each unprotected domain needs
- `compare_rescan.py` — diffs two scans to count how many domains were fixed between them
- `districts_results.csv`, `municipalities_results.csv` — full per-domain results
- `districts_results_fixes.txt`, `municipalities_results_fixes.txt` — the fix records, per domain, in the safe order (`p=none` → `quarantine` → `reject`)
- `mail_domains_results.csv` — results for the 61 email domains that differ from the website domain
- `example_domains.csv` — input format

## Run it yourself

```
pip install dnspython
python3 dmarc_check.py domains.csv results.csv
```

`domains.csv` needs columns `name,domain`. Grades: `NO_DMARC`, `MONITOR_ONLY`, `PARTIAL`, `MALFORMED`, `ENFORCED_QUARANTINE`, `ENFORCED_REJECT`, `LOOKUP_FAILED` (rerun those).

## What happens next

Every affected organization is being sent its specific finding and the exact fix. All 609 domains will be re-scanned 30 days later; the number that moved to enforcement is the outcome of this project and is verifiable by anyone with a DNS lookup.

## Limitations

- DKIM can't be checked without knowing the selector; "not found" for DKIM means nothing.
- A domain that sends no mail still needs DMARC at `p=reject`; otherwise it can be forged.
- Grades reflect the moment of the scan. Re-run before citing.

## Author

Siddharth Santhosh, high school senior, Cary, NC. Independent project, September 2026.
