# CallGuard data report

Built from `data/processed/cves.jsonl`, collected on 2026-10-17T13:17:49+00:00 (UTC).

| Source | As of |
|---|---|
| NVD | newest change 2026-10-16T20:17 (7,574 CVEs scanned) |
| CISA KEV | catalog 2026.10.16 |
| FIRST EPSS | scores dated 2026-10-16 |

## Summary

|  | CVEs |
|---|---|
| In scope | 886 |
| Published since 2024 | 160 (18%) |
| Critical / High severity | 56 / 327 |
| Listed in CISA KEV (known exploited) | 11, of which 4 linked to ransomware |
| With version data | 879 (99%) |
| Matched to a product by description only | 7 |
| Cloud products only (answered with the cloud message) | 3 |

## By product

| Product | CVEs | Since 2024 | Critical | High | In KEV | Version data |
|---|---|---|---|---|---|---|
| Cisco Unified Communications Manager | 262 | 13 | 4 | 94 | 2 | 100% |
| Cisco Unified CM IM and Presence | 68 | 8 | 3 | 28 | 1 | 100% |
| Cisco Unity Connection | 72 | 14 | 4 | 18 | 1 | 100% |
| Cisco Unified Contact Center Express | 62 | 22 | 7 | 17 | 0 | 100% |
| Cisco Unified / Packaged Contact Center Enterprise | 26 | 11 | 3 | 3 | 0 | 100% |
| Cisco Finesse | 27 | 6 | 3 | 7 | 0 | 100% |
| Cisco Unified Customer Voice Portal | 17 | 0 | 0 | 11 | 0 | 100% |
| Cisco Unified Intelligence Center | 28 | 9 | 1 | 8 | 0 | 100% |
| Avaya Aura Communication Manager | 18 | 0 | 0 | 10 | 0 | 100% |
| Avaya IP Office | 8 | 2 | 3 | 4 | 0 | 100% |
| Avaya Experience Portal and Orchestration Designer | 6 | 1 | 0 | 1 | 0 | 100% |
| Avaya Aura platform (Session Manager, System Manager, Utility Services, AVP, Messaging) | 8 | 1 | 0 | 4 | 0 | 100% |
| Avaya IX Workforce Engagement | 3 | 0 | 0 | 0 | 0 | 100% |
| Mitel MiCollab | 50 | 19 | 13 | 11 | 3 | 98% |
| Mitel MiVoice Connect (ShoreTel) | 32 | 0 | 10 | 6 | 2 | 100% |
| Mitel MiVoice Business | 5 | 3 | 2 | 1 | 1 | 80% |
| Mitel MiContact Center | 13 | 8 | 2 | 7 | 0 | 85% |
| Mitel MiVoice Office 400 | 3 | 2 | 0 | 2 | 0 | 100% |
| Mitel MiVoice MX-ONE | 2 | 2 | 1 | 1 | 0 | 100% |
| Mitel SIP phones (6800 and 6900 series) | 15 | 11 | 1 | 7 | 1 | 87% |
| Asterisk (open source and Certified Asterisk) | 183 | 15 | 4 | 69 | 0 | 100% |
| FreePBX (including its modules) | 74 | 42 | 9 | 40 | 3 | 100% |
| Genesys Engage / PureConnect (on-prem) | 7 | 0 | 0 | 3 | 0 | 100% |
| Verint Workforce Optimization / Impact 360 / Engagement | 11 | 2 | 0 | 3 | 0 | 100% |
| Five9 (cloud) | 3 | 1 | 1 | 1 | 0 | 100% |

## Known exploited (CISA KEV)

| CVE | Product | In KEV since | Ransomware | EPSS |
|---|---|---|---|---|
| CVE-2026-20230 | Cisco Unified Communications Manager | 2026-06-25 | Unknown | 88% |
| CVE-2019-19006 | FreePBX (including its modules) | 2026-02-03 | Unknown | 56% |
| CVE-2025-64328 | FreePBX (including its modules) | 2026-02-03 | Unknown | 85% |
| CVE-2026-20045 | Cisco Unified Communications Manager, Cisco Unified CM IM and Presence, Cisco Unity Connection | 2026-01-21 | Unknown | 5% |
| CVE-2025-57819 | FreePBX (including its modules) | 2025-08-29 | Unknown | 86% |
| CVE-2024-41710 | Mitel SIP phones (6800 and 6900 series) | 2025-02-12 | Unknown | 42% |
| CVE-2024-41713 | Mitel MiCollab | 2025-01-07 | Known | 97% |
| CVE-2024-55550 | Mitel MiCollab | 2025-01-07 | Known | 38% |
| CVE-2022-40765 | Mitel MiVoice Connect (ShoreTel) | 2023-02-21 | Known | 11% |
| CVE-2022-29499 | Mitel MiVoice Connect (ShoreTel) | 2022-06-27 | Known | 55% |
| CVE-2022-26143 | Mitel MiCollab, Mitel MiVoice Business | 2022-03-25 | Unknown | 87% |

## Watch list: highest exploit forecasts that are not in KEV

EPSS predicts; KEV confirms. Old flaws with public attack code keep high forecasts for years, so recent ones are listed separately.

**Published since 2024**

| CVE | Year | Product | Severity | EPSS |
|---|---|---|---|---|
| CVE-2024-35286 | 2024 | Mitel MiCollab | 9.8 CRITICAL | 65.7% |
| CVE-2025-47188 | 2025 | Mitel SIP phones (6800 and 6900 series) | 6.5 MEDIUM | 53.3% |
| CVE-2025-61678 | 2025 | FreePBX (including its modules) | 8.6 HIGH | 43.7% |
| CVE-2025-61675 | 2025 | FreePBX (including its modules) | 8.6 HIGH | 38.5% |
| CVE-2024-20404 | 2024 | Cisco Unified Contact Center Express, Cisco Unified / Packaged Contact Center Enterprise, Cisco Finesse | 5.3 MEDIUM | 22.6% |

**All years**

| CVE | Year | Product | Severity | EPSS |
|---|---|---|---|---|
| CVE-2006-5444 | 2006 | Asterisk (open source and Certified Asterisk) | 7.5 HIGH | 86.5% |
| CVE-2017-17090 | 2017 | Asterisk (open source and Certified Asterisk) | 7.5 HIGH | 82.2% |
| CVE-2017-17850 | 2017 | Asterisk (open source and Certified Asterisk) | 7.5 HIGH | 75.4% |
| CVE-2012-4869 | 2012 | FreePBX (including its modules) | 7.5 HIGH | 70.3% |
| CVE-2018-7284 | 2018 | Asterisk (open source and Certified Asterisk) | 7.5 HIGH | 66.2% |

## Severity

| Severity | CVEs |
|---|---|
| Critical | 56 |
| High | 327 |
| Medium | 488 |
| Low | 15 |
| No score yet | 0 |

366 older CVEs only have a CVSS v2 score. That older system has no Critical level, so even a 10.0 is labelled High.

## Where version data comes from

| Source | CVEs |
|---|---|
| NVD's analysis only | 617 (70%) |
| NVD's analysis and the vendor's list | 230 (26%) |
| the vendor's list only | 32 (4%) |
| only in the description text | 7 (1%) |

## Data quality notes

- NVD's work status: Modified 741, Analyzed 109, Deferred 29, Awaiting Analysis 5, Undergoing Analysis 2.
- 0 CVEs have no severity score yet.
- 7 CVEs had no product data at all and were matched from their description: CVE-2004-0944 (Mitel MiVoice Business), CVE-2005-2242 (Cisco Unified Communications Manager), CVE-2025-27827 (Mitel MiContact Center), CVE-2025-27828 (Mitel MiContact Center), CVE-2025-47187 (Mitel SIP phones (6800 and 6900 series)), CVE-2025-47188 (Mitel SIP phones (6800 and 6900 series)), CVE-2025-52913 (Mitel MiCollab).
