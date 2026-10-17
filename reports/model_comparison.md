# Choosing CallGuard's answer model

Each model got exactly the same question and the same retrieved records, so only the writing differs. The checks are quick and automatic; Phase 9 grades the answers properly.

| Model | Expected CVEs cited | Refusals worded safely | Citations not in the records | Average time | Slowest | Average tokens |
|---|---|---|---|---|---|---|
| Qwen/Qwen3-235B-A22B-Instruct-2507 | 85% | 3/3 | 0 | 6.7 s | 15.5 s | 3036 |
| Qwen/Qwen3-30B-A3B-Instruct-2507 | 94% | 1/3 | 0 | 14.5 s | 22.9 s | 3144 |
| openai/gpt-oss-120b | 72% | 2/3 | 0 | 1.8 s | 2.7 s | 3120 |
| deepseek-ai/DeepSeek-V4.1-Flash | 94% | 3/3 | 0 | 3.7 s | 5.2 s | 3157 |

## E1: What is CVE-2024-41713, and are attackers using it?

**Reference answer:** A path traversal flaw in the NuPoint Unified Messaging component of Mitel MiCollab, up to and including 9.8.1.201 (9.8 SP1 FP2). An attacker who isn't logged in can view, corrupt or delete users' data and system configuration. CVSS 9.1 Critical. Yes, attackers use it: it has been in CISA KEV since 2025-01-07, ransomware use is Known, and it can be chained with CVE-2024-55550. The fix is in Mitel advisory MISA-2024-0029.

### Qwen/Qwen3-235B-A22B-Instruct-2507 (8.04 s)

CVE-2024-41713 is a critical path traversal vulnerability in Mitel MiCollab's NuPoint Unified Messaging component, allowing unauthenticated attackers to access, corrupt, or delete user data and system configurations [CVE-2024-41713]. Attackers are actively exploiting it, and it has been used in ransomware attacks [CVE-2024-41713].

- **CVE-2024-41713**: Critical (CVSS 9.1), in CISA KEV since 2025-01-07, ransomware use confirmed. Affects Mitel MiCollab ≤9.8.1.201. Can be chained with CVE-2024-55550. Fix: apply vendor guidance [CVE-2024-41713].  
- **CVE-2024-55550**: Low (CVSS 2.7), in CISA KEV, ransomware use confirmed. Affects same versions, requires admin access. Often exploited alongside CVE-2024-41713 [CVE-2024-55550].  

Both are actively exploited, with CVE-2024-41713 posing the greater risk due to unauthenticated remote access.

Sources: [CVE-2024-41713](https://nvd.nist.gov/vuln/detail/CVE-2024-41713), [CVE-2024-55550](https://nvd.nist.gov/vuln/detail/CVE-2024-55550)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### Qwen/Qwen3-30B-A3B-Instruct-2507 (16.57 s)

CVE-2024-41713 is a critical path traversal vulnerability in Mitel MiCollab (up to 9.8.1.201) that allows unauthenticated attackers to access arbitrary files, potentially leading to data exposure, corruption, or deletion due to insufficient input validation [CVE-2024-41713]. Attackers are actively exploiting it, as it is listed in CISA’s KEV catalog since January 2025 and has confirmed ransomware use [CVE-2024-41713].

- [CVE-2024-41713]: Critical (CVSS 9.1), CISA KEV: yes, ransomware use: Known, affected versions: Mitel MiCollab up to 9.8.1.201, fix: https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0029  
- [CVE-2024-55550]: Low (CVSS 2.7), CISA KEV: yes, ransomware use: Known, affected versions: Mitel MiCollab up to 9.8.1.201, fix: same advisory as above (chained with CVE-2024-41713)  

Exploit forecast for CVE-2024-41713 is 97.2% in the next 30 days. Patch immediately.

Sources: [CVE-2024-41713](https://nvd.nist.gov/vuln/detail/CVE-2024-41713), [CVE-2024-55550](https://nvd.nist.gov/vuln/detail/CVE-2024-55550)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### openai/gpt-oss-120b (2.07 s)

CVE‑2024‑41713 is a critical path‑traversal flaw in the NuPoint Unified Messaging component of Mitel MiCollab (up to 9.8 SP1 FP2 / 9.8.1.201) that lets an unauthenticated attacker read, corrupt, or delete user data and system configuration; attackers are already exploiting it — it is listed in CISA’s Known‑Exploited Vulnerabilities (KEV) program, has known ransomware use, and EPSS predicts a 97 % chance of exploitation in the next 30 days [CVE-2024-41713].

- **What:** Unauthenticated path‑traversal in NuPoint Unified Messaging, enabling view/modify/delete of data and configs.  
- **Severity:** CVSS 9.1 (CRITICAL).  
- **CISA KEV:** Listed (known‑exploited).  
- **Ransomware use:** Known.  
- **Affected versions:** Mitel MiCollab ≤ 9.8.1.201 (through 9.8 SP1 FP2).  
- **Advisory/fix:** https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0029 [CVE-2024-41713].

Sources: [CVE-2024-41713](https://nvd.nist.gov/vuln/detail/CVE-2024-41713)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### deepseek-ai/DeepSeek-V4.1-Flash (3.01 s)

CVE-2024-41713 is a critical path traversal flaw in Mitel MiCollab's NuPoint Unified Messaging component, and yes — it is confirmed as exploited in the wild.

- [CVE-2024-41713] Mitel MiCollab — unauthenticated path traversal (CWE-22) via insufficient input validation; CVSS 9.1 Critical. Affects MiCollab up to and including 9.8.1.201. In CISA KEV since 2025-01-07, ransomware use: Known. EPSS 97.2% for the next 30 days. Fix: https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0029
- [CVE-2024-55550] Mitel MiCollab — local file read by an authenticated admin (CWE-22); CVSS 2.7 Low. Same affected range (up to 9.8.1.201). Also in CISA KEV since 2025-01-07, ransomware use: Known. CISA notes it can be chained with [CVE-2024-41713]. Fix: https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0029

Note the Low-severity [CVE-2024-55550] still matters because it is known-exploited and chains with the critical flaw.

Sources: [CVE-2024-41713](https://nvd.nist.gov/vuln/detail/CVE-2024-41713), [CVE-2024-55550](https://nvd.nist.gov/vuln/detail/CVE-2024-55550)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

## V3: We upgraded MiCollab to 9.8.2.0. Are we still affected by CVE-2024-41713?

**Reference answer:** Not by CVE-2024-41713, which affects versions up to and including 9.8.1.201. But CVE-2025-52913, a similar critical (9.8) path traversal in the same NuPoint component, affects MiCollab through 9.8 SP2 (9.8.2.12), so 9.8.2.0 is still exposed to that one.

### Qwen/Qwen3-235B-A22B-Instruct-2507 (4.83 s)

You are not affected by CVE-2024-41713, as version 9.8.2.0 is outside the affected range.

- **CVE-2024-41713**: Path traversal vulnerability in NuPoint Unified Messaging, CVSS 9.1 (CRITICAL), in CISA KEV, ransomware use: Known.  
  Affected versions: up to and including 9.8.1.201.  
  Your version (9.8.2.0) is not affected.  
  Fix: Upgrade to a version beyond 9.8.1.201. Advisory: [https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0029](https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0029)

Note: While you are not affected by CVE-2024-41713, two other CVEs (CVE-2024-47912, CVE-2024-47223) list "before 9.8.2.12" as affected, suggesting 9.8.2.0 may still be vulnerable—though NVD data conflicts with CISA (ADP) on this. Consider upgrading to 9.8.2.12 or later to resolve any ambiguity.

Sources: [CVE-2024-41713](https://nvd.nist.gov/vuln/detail/CVE-2024-41713), [CVE-2024-47912](https://nvd.nist.gov/vuln/detail/CVE-2024-47912), [CVE-2024-47223](https://nvd.nist.gov/vuln/detail/CVE-2024-47223)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### Qwen/Qwen3-30B-A3B-Instruct-2507 (22.95 s)

You are not affected by CVE-2024-41713, as version 9.8.2.0 is outside the affected range (up to and including 9.8.1.201) [CVE-2024-41713].

- **CVE-2024-41713**: Path traversal in NuPoint Unified Messaging (NPM); CVSS 9.1 CRITICAL; CISA KEV: listed; ransomware use: Known; affected versions: up to and including 9.8.1.201; fix: [Vendor Advisory](https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0029); version check: not affected (9.8.2.0).

However, you may still be affected by other vulnerabilities:
- **CVE-2024-47912**: Missing authentication in AWV conferencing; CVSS 8.2 HIGH; CISA KEV: not listed; affected versions: before 9.8.2.12; fix: [Vendor Advisory](https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0027); version check: affected (9.8.2.0 is before 9.8.2.12).
- **CVE-2024-47223**: SQL injection in AWV conferencing; CVSS 9.4 CRITICAL; CISA KEV: not listed; affected versions: before 9.8.2.12; fix: [Vendor Advisory](https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0028); version check: affected (9.8.2.0 is before 9.8.2.12).
- **CVE-2025-52913**: Path traversal in NPM; CVSS 9.8 CRITICAL; CISA KEV: not listed; affected versions: up to and including 9.8.2.12; fix: [Vendor Advisory](https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2025-0007); version check: unknown (no structured version data).

Patch priority: CVE-2024-47912 and CVE-2024-47223 (both before 9.8.2.12) are critical and should be addressed.

Sources: [CVE-2024-41713](https://nvd.nist.gov/vuln/detail/CVE-2024-41713), [CVE-2024-47912](https://nvd.nist.gov/vuln/detail/CVE-2024-47912), [CVE-2024-47223](https://nvd.nist.gov/vuln/detail/CVE-2024-47223), [CVE-2025-52913](https://nvd.nist.gov/vuln/detail/CVE-2025-52913)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### openai/gpt-oss-120b (1.21 s)

No – after upgrading to MiCollab 9.8.2.0 you are no longer vulnerable to CVE‑2024‑41713.

- **CVE‑2024‑41713** – Path‑traversal flaw in the NuPoint Unified Messaging component; CVSS 9.1 CRITICAL, listed in CISA KEV, ransomware‑related (known). Affected versions: up to and including 9.8.1.201; 9.8.2.0 is outside this range, so it is not affected. Advisory/fix: https://www.mitel.com/support/security‑advisories/mitel‑product‑security‑advisory‑misa‑2024‑0029 [​CVE-2024-41713]

Sources: [CVE-2024-41713](https://nvd.nist.gov/vuln/detail/CVE-2024-41713)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### deepseek-ai/DeepSeek-V4.1-Flash (4.92 s)

No — 9.8.2.0 is outside the affected range for CVE-2024-41713, which covers versions up to and including 9.8.1.201. But 9.8.2.0 still falls inside the affected range of other MiCollab flaws, so the upgrade alone doesn't clear you.

- CVE-2024-41713: path traversal in NuPoint Unified Messaging; CVSS 9.1 Critical; in CISA KEV since 2025-01-07, ransomware use Known; affected up to and including 9.8.1.201; version check says not affected at 9.8.2.0. Advisory: https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0029
- CVE-2024-55550: the flaw chained with it (local file read); CVSS 2.7 Low; KEV listed, ransomware Known; affected up to and including 9.8.1.201 — also not affected at 9.8.2.0.
- CVE-2024-47912 (CVSS 8.2 High) and CVE-2024-47223 (CVSS 9.4 Critical): neither in KEV; both list "before 9.8.2.12", so 9.8.2.0 appears affected — but NVD lists versions excluding it, so the sources disagree.
- CVE-2025-52913: CVSS 9.8 Critical, not in KEV; no structured version data — the description says "through 9.8 SP2 (9.8.2.12)".

I can't see your systems; verify against Mitel's advisories.

Sources: [CVE-2024-41713](https://nvd.nist.gov/vuln/detail/CVE-2024-41713), [CVE-2024-55550](https://nvd.nist.gov/vuln/detail/CVE-2024-55550), [CVE-2024-47912](https://nvd.nist.gov/vuln/detail/CVE-2024-47912), [CVE-2024-47223](https://nvd.nist.gov/vuln/detail/CVE-2024-47223), [CVE-2025-52913](https://nvd.nist.gov/vuln/detail/CVE-2025-52913)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

## V4: We run Asterisk 18.9.0. Are we exposed to any critical vulnerabilities?

**Reference answer:** Yes, two: CVE-2022-26499 (9.1 Critical, server-side request forgery when STIR/SHAKEN is used) and CVE-2022-26651 (9.8 Critical, inadequate escaping in the func_odbc module that can allow SQL injection). Both affect Asterisk 18.x before 18.11.2, so upgrading to 18.11.2 or later fixes both.

### Qwen/Qwen3-235B-A22B-Instruct-2507 (4.55 s)

Yes, your system running Asterisk 18.9.0 is exposed to two critical vulnerabilities: CVE-2022-26499 and CVE-2022-26651.

- **CVE-2022-26499**: Server-side request forgery (SSRF) in STIR/SHAKEN handling allows arbitrary requests via the Identity header. CVSS 9.1 (CRITICAL). Not in CISA KEV. Affects Asterisk 18.0 up to 18.11.2. Your version 18.9.0 is affected [CVE-2022-26499]. Fixed in 18.11.2. Advisory: https://downloads.asterisk.org/pub/security/AST-2022-002.html  
- **CVE-2022-26651**: SQL injection via func_odbc module due to insufficient backslash escaping. CVSS 9.8 (CRITICAL). Not in CISA KEV. Affects Asterisk 18.0 before 18.11.2. Your version 18.9.0 is affected [CVE-2022-26651]. Fixed in 18.11.2. Advisory: https://downloads.asterisk.org/pub/security/AST-2022-003.html  

CVE-2017-14100 and CVE-2024-57520 do not affect version 18.9.0 [CVE-2017-14100] [CVE-2024-57520].  

Patch priority: Address CVE-2022-26651 first (higher EPSS forecast at 7.0%), then CVE-2022-26499 (7.7% EPSS). Both require upgrading to Asterisk 18.11.2 or later.

Sources: [CVE-2022-26499](https://nvd.nist.gov/vuln/detail/CVE-2022-26499), [CVE-2022-26651](https://nvd.nist.gov/vuln/detail/CVE-2022-26651), [CVE-2017-14100](https://nvd.nist.gov/vuln/detail/CVE-2017-14100), [CVE-2024-57520](https://nvd.nist.gov/vuln/detail/CVE-2024-57520)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### Qwen/Qwen3-30B-A3B-Instruct-2507 (12.21 s)

Yes, your Asterisk 18.9.0 system is exposed to two critical vulnerabilities: CVE-2022-26499 and CVE-2022-26651.

- **CVE-2022-26499** | CVSS 9.1 CRITICAL | Not in CISA KEV | Ransomware status: unknown  
  SSRF via STIR/SHAKEN Identity header in versions from 18.0 before 18.11.2. Fixed in 18.11.2.  
  Affected: 18.9.0 [CVE-2022-26499]  
  Advisory: https://downloads.asterisk.org/pub/security/AST-2022-002.html

- **CVE-2022-26651** | CVSS 9.8 CRITICAL | Not in CISA KEV | Ransomware status: unknown  
  SQL injection in func_odbc due to inadequate backslash escaping in versions from 18.0 before 18.11.2. Fixed in 18.11.2.  
  Affected: 18.9.0 [CVE-2022-26651]  
  Advisory: https://downloads.asterisk.org/pub/security/AST-2022-003.html

Patch priority: Both are critical and unpatched in 18.9.0. Upgrade to 18.11.2 or later immediately.

Sources: [CVE-2022-26499](https://nvd.nist.gov/vuln/detail/CVE-2022-26499), [CVE-2022-26651](https://nvd.nist.gov/vuln/detail/CVE-2022-26651)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### openai/gpt-oss-120b (2.02 s)

Yes – Asterisk 18.9.0 is vulnerable to two critical flaws.

- **CVE‑2022‑26499** – Critical (CVSS 9.1); not listed in CISA KEV; ransomware use = unknown; affects 18.0 – < 18.11.2, so 18.9.0 is vulnerable. Fix in 18.11.2. Advisory/patch: https://downloads.asterisk.org/pub/security/AST-2022-002.html  
- **CVE‑2022‑26651** – Critical (CVSS 9.8); not listed in CISA KEV; ransomware use = unknown; affects 18.0 – < 18.11.2, so 18.9.0 is vulnerable. Fix in 18.11.2. Advisory/patch: https://downloads.asterisk.org/pub/security/AST-2022-003.html  

Both flaws are not known‑exploited but have a ~7 % EPSS chance of exploitation in the next 30 days, so they should be patched promptly (upgrade to 18.11.2 or later).

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### deepseek-ai/DeepSeek-V4.1-Flash (4.11 s)

Yes — Asterisk 18.9.0 is affected by two Critical-severity CVEs, both fixed in 18.11.2 or later. Neither is in CISA KEV, and the records do not confirm ransomware use for either.

- [CVE-2022-26499] — SSRF via the STIR/SHAKEN Identity header, allowing arbitrary requests (e.g. GET) to interfaces such as localhost. CVSS 9.1 Critical. Not in CISA KEV; ransomware use not confirmed. Affected: 18.0 before 18.11.2 (code confirms 18.9.0 is covered). EPSS 7.7%. Fix: https://downloads.asterisk.org/pub/security/AST-2022-002.html
- [CVE-2022-26651] — Inadequate escaping in func_odbc SQL queries, allowing SQL injection from user-supplied data. CVSS 9.8 Critical. Not in CISA KEV; ransomware use not confirmed. Affected: 18.0 before 18.11.2 (code confirms 18.9.0 is covered). EPSS 7.0%. Fix: https://downloads.asterisk.org/pub/security/AST-2022-003.html

Two other Critical records, [CVE-2017-14100] and [CVE-2024-57520], do not affect 18.9.0 per the version checks.

I can't see your systems, so verify your running version and upgrade to 18.11.2 or later.

Sources: [CVE-2022-26499](https://nvd.nist.gov/vuln/detail/CVE-2022-26499), [CVE-2022-26651](https://nvd.nist.gov/vuln/detail/CVE-2022-26651), [CVE-2017-14100](https://nvd.nist.gov/vuln/detail/CVE-2017-14100), [CVE-2024-57520](https://nvd.nist.gov/vuln/detail/CVE-2024-57520)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

## S2: Is there a way to read or change files on a MiCollab server without logging in?

**Reference answer:** Yes. Path traversal flaws let an attacker who isn't logged in read or change files: CVE-2024-41713 (9.1 Critical, in CISA KEV, ransomware use Known), CVE-2025-52913 (9.8 Critical, through 9.8.2.12), CVE-2021-27402 (SAS Admin portal, before 9.2 FP2) and CVE-2020-11798 (web conference component of MiCollab AWV). The web conferencing component also had CVE-2023-25597 (download a shared file without logging in, through 9.6.2.9), CVE-2020-11797 (authentication bypass giving access to shared files, 7.5 High) and CVE-2022-36452 (upload malicious files without logging in, 9.8 Critical, through 9.5.0.101). CVE-2024-55550 also reads files, but it needs an administrator login.

### Qwen/Qwen3-235B-A22B-Instruct-2507 (4.01 s)

Yes, unauthenticated attackers can read files on a Mitel MiCollab server without logging in due to multiple vulnerabilities, and one of them also allows file modification.

- [CVE-2024-41713]: Critical path traversal vulnerability allowing unauthenticated attackers to read, corrupt, or delete user data and system configurations. Affected versions: up to and including 9.8.1.201. In CISA KEV; ransomware use: Known. Fix: https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0029
- [CVE-2020-11798]: Directory traversal flaw enabling unauthenticated file access via crafted URLs. Affected versions: before 8.1.2.4 and 9.x before 9.1.3. Not in CISA KEV; ransomware use: Unknown. Fix: https://www.mitel.com/-/media/mitel/file/pdf/support/security-advisories/security-bulletin-20-0005-01.pdf
- [CVE-2023-25597]: Unauthenticated shared file download via improper authentication. Affected versions: before 9.7. Not in CISA KEV; ransomware use: Unknown. Fix: https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-23-0002

CVE-2024-41713 is the most severe and actively exploited. Prioritize patching it first.

Sources: [CVE-2024-41713](https://nvd.nist.gov/vuln/detail/CVE-2024-41713), [CVE-2020-11798](https://nvd.nist.gov/vuln/detail/CVE-2020-11798), [CVE-2023-25597](https://nvd.nist.gov/vuln/detail/CVE-2023-25597)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### Qwen/Qwen3-30B-A3B-Instruct-2507 (19.57 s)

Yes, it is possible to read files on a Mitel MiCollab server without logging in if the server is running an affected version, due to unauthenticated path traversal vulnerabilities.

- **CVE-2024-41713** | CVSS 9.1 CRITICAL | CISA KEV: listed | Ransomware use: Known  
  Allows unauthenticated remote attackers to perform path traversal in the NuPoint Unified Messaging (NPM) component, enabling access to arbitrary files. Affected versions: up to and including 9.8.1.201. Exploit forecast: 97.2% chance in next 30 days. Chained with CVE-2024-55550.  
  [Advisory](https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0029)

- **CVE-2020-11797** | CVSS 7.5 HIGH | CISA KEV: not listed | Ransomware use: Unknown  
  Authentication bypass in the web conferencing component allows unauthenticated access to sensitive shared files. Affected versions: before 8.1.2.4, 9.x before 9.1.3.  
  [Advisory](https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-20-0005)

- **CVE-2020-11798** | CVSS 5.3 MEDIUM | CISA KEV: not listed | Ransomware use: Unknown  
  Directory traversal via crafted URL in web conferencing component allows access to restricted files. Affected versions: before 8.1.2.4, 9.x before 9.1.3.  
  [Advisory](https://www.mitel.com/-/media/mitel/file/pdf/support/security-advisories/security-bulletin-20-0005-01.pdf)

- **CVE-2023-25597** | CVSS 5.9 MEDIUM | CISA KEV: not listed | Ransomware use: Unknown  
  Unauthenticated file download via crafted request in web conferencing. Affected versions: before 9.7.  
  [Advisory](https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-23-0002)

**Patch priority order (based on CISA KEV and exploit forecast):**  
1. CVE-2024-41713 (highest risk)  
2. CVE-2020-11798  
3. CVE-2020-11797  
4. CVE-2023-25597

Apply fixes from Mitel’s advisories immediately.

Sources: [CVE-2024-41713](https://nvd.nist.gov/vuln/detail/CVE-2024-41713), [CVE-2024-55550](https://nvd.nist.gov/vuln/detail/CVE-2024-55550), [CVE-2020-11797](https://nvd.nist.gov/vuln/detail/CVE-2020-11797), [CVE-2020-11798](https://nvd.nist.gov/vuln/detail/CVE-2020-11798), [CVE-2023-25597](https://nvd.nist.gov/vuln/detail/CVE-2023-25597)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### openai/gpt-oss-120b (2.72 s)

Yes – several unauthenticated path‑traversal flaws in Mitel MiCollab can be used to read (and in one case also modify or delete) files on the server without a valid login.

- **CVE‑2024‑41713** – Critical (CVSS 9.1), listed in CISA KEV, ransomware‑used, 97 % EPSS forecast. Allows an unauthenticated attacker to traverse the file system via the NuPoint Unified Messaging component and view, corrupt, or delete user data and system configuration. Affected up to 9.8.1.201. Advisory: https://www.mitel.com/support/security‑advisories/mitel‑product‑security‑advisory‑misa‑2024‑0029 [​CVE-2024-41713]  
- **CVE‑2024‑55550** – Low (CVSS 2.7), listed in CISA KEV, ransomware‑used, 38 % EPSS forecast. Authenticated admin can read local files via path traversal (no write). Affected up to 9.8.1.201. Advisory: https://www.mitel.com/support/security‑advisories/mitel‑product‑security‑advisory‑misa‑2024‑0029 [​CVE-2024-55550]  
- **CVE‑2020‑11797** – High (CVSS 7.5), not in KEV, 1 % EPSS forecast. Unauthenticated attacker bypasses authentication in the web‑conference component and can access sensitive shared files. Affected before 8.1.2.4 and 9.1.3. Advisory: https://www.mitel.com/support/security‑advisories/mitel‑product‑security‑advisory‑20‑0005 [​CVE-2020-11797]  
- **CVE‑2020‑11798** – Medium (CVSS 5.3), not in KEV, 48 % EPSS forecast. Directory‑traversal via crafted URL lets an attacker read arbitrary files from restricted directories. Same version range as above. Advisory: https://www.mitel.com/-/media/mitel/file/pdf/support/security‑advisories/security‑bulletin‑20‑0005‑01.pdf [​CVE-2020-11798]  
- **CVE‑2023‑25597** – Medium (CVSS 5.9), not in KEV, 0.7 % EPSS forecast. Unauthenticated attacker can download a shared file by specifying its exact path. Affected before 9.7. Advisory: https://www.mitel.com/support/security‑advisories/mitel‑product‑security‑advisory‑23‑0002 [​CVE-2023-25597]

Sources: [CVE-2024-41713](https://nvd.nist.gov/vuln/detail/CVE-2024-41713), [CVE-2024-55550](https://nvd.nist.gov/vuln/detail/CVE-2024-55550), [CVE-2020-11797](https://nvd.nist.gov/vuln/detail/CVE-2020-11797), [CVE-2020-11798](https://nvd.nist.gov/vuln/detail/CVE-2020-11798), [CVE-2023-25597](https://nvd.nist.gov/vuln/detail/CVE-2023-25597)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### deepseek-ai/DeepSeek-V4.1-Flash (4.26 s)

Yes — CVE-2024-41713 allows an unauthenticated attacker to read, corrupt or delete files on MiCollab, and it is known-exploited. Order below is patch priority: known-exploited first, then highest exploit forecast, then severity.

- [CVE-2024-41713] — Unauthenticated path traversal in the NuPoint Unified Messaging component; CVSS 9.1 Critical. In CISA KEV since 2025-01-07; ransomware use: Known. Affected: MiCollab up to and including 9.8.1.201. EPSS 97.2%. Fix: https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0029
- [CVE-2024-55550] — Local file read by an authenticated admin only; CVSS 2.7 Low. In CISA KEV since 2025-01-07; ransomware use: Known. Affected: up to and including 9.8.1.201. No file modification or privilege escalation. Chains with [CVE-2024-41713]. EPSS 38.2%. Fix: same MISA-2024-0029 advisory.
- [CVE-2020-11798] — Directory traversal in the web conference component; CVSS 5.3 Medium, not in KEV. Affected: before 8.1.2.4, and 9.0 before 9.1.3. EPSS 48.8%. Fix: https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-20-0005
- [CVE-2020-11797] — Authentication bypass in the web conferencing Published Area; CVSS 7.5 High, not in KEV. Affected: before 8.1.2.4, and 9.0 before 9.1.3. EPSS 1.2%. Fix: same 20-0005 advisory.
- [CVE-2023-25597] — Unauthenticated download of a shared file via crafted request; CVSS 5.9 Medium, not in KEV. Affected: before 9.7. EPSS 0.7%. Fix: https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-23-0002

Note: "Unknown" ransomware use means unconfirmed, not none.

Sources: [CVE-2024-41713](https://nvd.nist.gov/vuln/detail/CVE-2024-41713), [CVE-2024-55550](https://nvd.nist.gov/vuln/detail/CVE-2024-55550), [CVE-2020-11798](https://nvd.nist.gov/vuln/detail/CVE-2020-11798), [CVE-2020-11797](https://nvd.nist.gov/vuln/detail/CVE-2020-11797), [CVE-2023-25597](https://nvd.nist.gov/vuln/detail/CVE-2023-25597)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

## M2: Are any exploited Cisco UC vulnerabilities linked to ransomware?

**Reference answer:** None is confirmed. Two Cisco UC flaws are in CISA KEV: CVE-2026-20045 (Unified CM, IM & Presence, Unity Connection) and CVE-2026-20230 (Unified CM). CISA lists ransomware use as Unknown for both, and Unknown means not confirmed, not "no".

### Qwen/Qwen3-235B-A22B-Instruct-2507 (2.86 s)

Yes, two exploited Cisco Unified Communications vulnerabilities are listed in CISA's Known Exploited Vulnerabilities (KEV) catalog, but ransomware use is not confirmed for either [CVE-2026-20045][CVE-2026-20230].

- **CVE-2026-20045**: Critical-severity code injection flaw in Cisco Unified CM, IM & Presence, and Unity Connection, allowing unauthenticated remote attackers to execute commands and escalate to root.  
  - CISA KEV: Yes (listed 2026-01-21)  
  - Ransomware use: Unknown  
  - Affected versions: Unified CM, IM & Presence, Unity Connection versions before 14su5 and up to 15su3a/15su3  
  - Fix: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-voice-rce-mORhqY4b  

- **CVE-2026-20230**: High-severity SSRF vulnerability in Cisco Unified CM, exploitable if WebDialer is enabled.  
  - CISA KEV: Yes (listed 2026-06-25)  
  - Ransomware use: Unknown  
  - Affected versions: Unified CM versions before 14su6 and up to 15su4a  
  - Fix: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-ssrf-cXPnHcW

Sources: [CVE-2026-20045](https://nvd.nist.gov/vuln/detail/CVE-2026-20045), [CVE-2026-20230](https://nvd.nist.gov/vuln/detail/CVE-2026-20230)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### Qwen/Qwen3-30B-A3B-Instruct-2507 (12.71 s)

Yes, two exploited Cisco UC vulnerabilities linked to ransomware are known, though ransomware use is currently marked as "Unknown" for both.

- **CVE-2026-20045** | CVSS 9.8 CRITICAL | CISA KEV: listed  
  A code injection flaw in Cisco Unified Communications Manager, IM & Presence, and Unity Connection allowing remote command execution and privilege escalation to root. Affected versions: Unified CM from 12.5 before 14su5, 15.0 to 15su3a, and others. Exploitation confirmed in CISA KEV since 2026-01-21. Ransomware use: Unknown. Patch: [Vendor Advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-voice-rce-mORhqY4b)

- **CVE-2026-20230** | CVSS 8.6 HIGH | CISA KEV: listed  
  SSRF vulnerability in Unified CM allowing file write and potential root access if WebDialer is enabled. Affected versions: Unified CM from 14.0 before 14su6, 15.0 to 15su4a, and others. Exploitation in CISA KEV since 2026-06-25. Exploit forecast: 88.2% in next 30 days. Ransomware use: Unknown. Patch: [Vendor Advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-ssrf-cXPnHcW), [Third Party Exploit](https://denizhalil.com/2026/06/12/cve-2026-20230-cisco-unified-cm-ssrf/)  

Priority order: CVE-2026-20230 (highest exploit forecast), then CVE-2026-20045 (highest severity).

Sources: [CVE-2026-20045](https://nvd.nist.gov/vuln/detail/CVE-2026-20045), [CVE-2026-20230](https://nvd.nist.gov/vuln/detail/CVE-2026-20230)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### openai/gpt-oss-120b (1.81 s)

Yes, there are Cisco Unified Communications (UC) vulnerabilities that are known‑exploited, but neither has confirmed ransomware use.

- **CVE‑2026‑20230** – Remote SSRF in Cisco Unified Communications Manager (and SME) that can write files for later privilege‑escalation. Criticality 8.6 (HIGH) [​CVE-2026-20230]; listed in CISA KEV (known‑exploited) [​CVE-2026-20230]; ransomware use Unknown [​CVE-2026-20230]; affected versions: UC CM 14.0 < 14su6, 15.0 ≤ ≤ 15su4a and many prior releases [​CVE-2026-20230]; advisory/fix https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-ssrf-cXPnHcW [​CVE-2026-20230].

- **CVE‑2026‑20045** – Code‑injection flaw in UC CM, UC CM IM & Presence, and Unity Connection allowing remote command execution and root escalation. Criticality 9.8 (CRITICAL) [​CVE-2026-20045]; listed in CISA KEV (known‑exploited) [​CVE-2026-20045]; ransomware use Unknown [​CVE-2026-20045]; affected versions: UC CM 12.5 < 14su5, 15.0 ≤ ≤ 15su3a and many prior releases; similar ranges for IM & Presence and Unity Connection [​CVE-2026-20045]; advisory/fix https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-voice-rce-mORhqY4b [​CVE-2026-20045].

Sources: [CVE-2026-20230](https://nvd.nist.gov/vuln/detail/CVE-2026-20230), [CVE-2026-20045](https://nvd.nist.gov/vuln/detail/CVE-2026-20045)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### deepseek-ai/DeepSeek-V4.1-Flash (3.62 s)

Both exploited Cisco UC flaws in CallGuard's data are in CISA KEV, but neither has a confirmed ransomware link — ransomware use is listed as "Unknown" for both, which means not confirmed, not ruled out.

- [CVE-2026-20045] — Code injection (CWE-94) in Unified CM, Unified CM IM and Presence, and Unity Connection; unauthenticated remote command execution with privilege escalation to root. CVSS 9.8 Critical. In CISA KEV since 2026-01-21; ransomware use: Unknown. Affected: Unified CM and IM&P from 12.5 before 14su5 and 15.0 up to and including 15su3a (plus many listed builds); Unity Connection from 12.5 before 14su5 and 15.0 up to and including 15su3. Fix: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-voice-rce-mORhqY4b
- [CVE-2026-20230] — SSRF (CWE-918) in Unified CM and Unified CM SME; file write leading to root escalation, requires WebDialer enabled (off by default). CVSS 8.6 High. In CISA KEV since 2026-06-25; ransomware use: Unknown. Affected: 14.0 before 14su6 and 15.0 up to and including 15su4a. Fix: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-ssrf-cXPnHcW

Priority order: [CVE-2026-20230] first (EPSS 88.2% vs 4.5%), then [CVE-2026-20045].

Sources: [CVE-2026-20045](https://nvd.nist.gov/vuln/detail/CVE-2026-20045), [CVE-2026-20230](https://nvd.nist.gov/vuln/detail/CVE-2026-20230)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

## M3: We run FreePBX. Which vulnerabilities should we patch first?

**Reference answer:** Start with the three that attackers are known to be using (CISA KEV), highest exploit forecast first: CVE-2025-57819 (9.8 Critical, unauthenticated admin access leading to code execution, EPSS about 86%), CVE-2025-64328 (7.2 High, about 85%) and CVE-2019-19006 (9.8 Critical access-control flaw, about 56%). After those, the highest exploit forecasts that aren't in KEV; some of those are old 2.x-era flaws, which matter only if such releases still run.

### Qwen/Qwen3-235B-A22B-Instruct-2507 (4.95 s)

Patch CVE-2025-57819 first, as it is critical, known exploited, and has the highest near-term exploitation risk [CVE-2025-57819]. Next, address CVE-2025-64328, also known exploited with high forecast risk [CVE-2025-64328].

- **CVE-2025-57819**: Authentication bypass leading to remote code execution; CVSS 9.8 (CRITICAL); in CISA KEV; affects FreePBX 15.0–15.0.65, 16.0–16.0.88, 17.0–17.0.2; fix: upgrade to 15.0.66, 16.0.89, or 17.0.3 [CVE-2025-57819]  
- **CVE-2025-64328**: Post-authentication command injection in Endpoint Manager; CVSS 7.2 (HIGH); in CISA KEV; affects FreePBX 17.0.2.36 to 17.0.2; fix: upgrade to 17.0.3 [CVE-2025-64328]  
- **CVE-2019-19006**: Authentication bypass vulnerability; CVSS 9.8 (CRITICAL); in CISA KEV; affects FreePBX ≤13.0.197.13, ≤14.0.13.11, ≤15.0.16.26; fix: apply vendor patches [CVE-2019-19006]  
- **CVE-2012-4869**: Remote command execution via callme_startcall; CVSS 7.5 (HIGH); not in CISA KEV; affects FreePBX ≤2.10; high exploit forecast despite age; fix: upgrade [CVE-2012-4869]  
- **CVE-2014-1903**: Arbitrary PHP code execution via API handler; CVSS 7.5 (HIGH); not in CISA KEV; affects FreePBX 2.9–2.12; fix: upgrade to patched versions [CVE-2014-1903]

Sources: [CVE-2025-57819](https://nvd.nist.gov/vuln/detail/CVE-2025-57819), [CVE-2025-64328](https://nvd.nist.gov/vuln/detail/CVE-2025-64328), [CVE-2019-19006](https://nvd.nist.gov/vuln/detail/CVE-2019-19006), [CVE-2012-4869](https://nvd.nist.gov/vuln/detail/CVE-2012-4869), [CVE-2014-1903](https://nvd.nist.gov/vuln/detail/CVE-2014-1903)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### Qwen/Qwen3-30B-A3B-Instruct-2507 (15.43 s)

Patch CVE-2025-57819 first, as it is in CISA KEV, has a high exploit forecast (86.3%), and allows unauthenticated remote code execution. Follow with CVE-2025-64328 (also in CISA KEV, 84.6% exploit forecast, post-auth command injection), then CVE-2019-19006 (CRITICAL, in CISA KEV, exploit forecast 55.9%), and finally CVE-2012-4869 and CVE-2014-1903 (not in CISA KEV, lower exploit forecast).

- **CVE-2025-57819** | CRITICAL (9.8) | CISA KEV: yes | Ransomware: Unknown | Affected: FreePBX 15 before 15.0.66, 16 before 16.0.89, 17 before 17.0.3 | Fix: https://community.freepbx.org/t/security-advisory-please-lock-down-your-administrator-access/107203
- **CVE-2025-64328** | HIGH (7.2) | CISA KEV: yes | Ransomware: Unknown | Affected: FreePBX 17.0.2.36 before 17.0.3 | Fix: https://github.com/FreePBX/security-reporting/security/advisories/GHSA-vm9p-46mv-5xvw
- **CVE-2019-19006** | CRITICAL (9.8) | CISA KEV: yes | Ransomware: Unknown | Affected: FreePBX 13.0.197.13 and below, 14.0.13.11 and below, 15.0.16.26 and below | Fix: https://community.freepbx.org/t/freepbx-security-vulnerability-sec-2019-001/62772
- **CVE-2012-4869** | HIGH (7.5) | CISA KEV: no | Ransomware: Unknown | Affected: FreePBX up to 2.10 | Fix: http://secunia.com/advisories/48463
- **CVE-2014-1903** | HIGH (7.5) | CISA KEV: no | Ransomware: Unknown | Affected: FreePBX 2.10, 2.11, 2.12, 2.9 | Fix: http://issues.freepbx.org/browse/FREEPBX-7117

Sources: [CVE-2025-57819](https://nvd.nist.gov/vuln/detail/CVE-2025-57819), [CVE-2025-64328](https://nvd.nist.gov/vuln/detail/CVE-2025-64328), [CVE-2019-19006](https://nvd.nist.gov/vuln/detail/CVE-2019-19006), [CVE-2012-4869](https://nvd.nist.gov/vuln/detail/CVE-2012-4869), [CVE-2014-1903](https://nvd.nist.gov/vuln/detail/CVE-2014-1903)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### openai/gpt-oss-120b (2.07 s)

Patch the listed FreePBX flaws in the order the code generated: CVE‑2025‑57819, then CVE‑2025‑64328, followed by CVE‑2019‑19006, CVE‑2012‑4869, and finally CVE‑2014‑1903.  

- **CVE‑2025‑57819** – Critical (CVSS 9.8) authentication bypass allowing unauthenticated admin access, remote code execution; in CISA KEV; ransomware use Unknown; affects FreePBX 15 < 15.0.66, 16 < 16.0.89, 17 < 17.0.3; fix [https://community.freepbx.org/t/security‑advisory‑please‑lock‑down‑your‑administrator‑access/107203] [https://github.com/FreePBX/security‑reporting/security/advisories/GHSA‑m42g‑xg4c‑5f3h] [CVE-2025-57819]  
- **CVE‑2025‑64328** – High (CVSS 7.2) post‑auth command injection in Endpoint Manager filestore; in CISA KEV; ransomware Unknown; affects FreePBX 17.0.2.36 – < 17.0.3; fix [https://github.com/FreePBX/security‑reporting/security/advisories/GHSA‑vm9p‑46mv‑5xvw] [CVE-2025-64328]  
- **CVE‑2019‑19006** – Critical (CVSS 9.8) improper authentication bypass; in CISA KEV; ransomware Unknown; affects FreePBX 13 ≤ 13.0.197.13, 14 ≤ 14.0.13.11, 15 ≤ 15.0.16.26; fix [https://community.freepbx.org/t/freepbx-security‑vulnerability‑sec‑2019‑001/62772] [CVE-2019-19006]  
- **CVE‑2012‑4869** – High (CVSS 7.5) remote command execution via callmenum parameter; not in CISA KEV; ransomware Unknown; affects FreePBX 2.9/2.10 and earlier; fix [http://secunia.com/advisories/48463] [CVE-2012-4869]  
- **CVE‑2014‑1903** – High (CVSS 7.5) unrestricted API function call leading to arbitrary PHP execution; not in CISA KEV; ransomware Unknown; affects FreePBX 2.9 < 2.9.0.14, 2.10 < 2.10.1.15, 2.11 < 2.11.0.23, 12 < 12.0.1alpha22; fix [http://issues.freepbx.org/browse/FREEPBX-7117] [CVE-2014-1903]

Sources: [CVE-2025-57819](https://nvd.nist.gov/vuln/detail/CVE-2025-57819), [CVE-2025-64328](https://nvd.nist.gov/vuln/detail/CVE-2025-64328), [CVE-2019-19006](https://nvd.nist.gov/vuln/detail/CVE-2019-19006), [CVE-2012-4869](https://nvd.nist.gov/vuln/detail/CVE-2012-4869), [CVE-2014-1903](https://nvd.nist.gov/vuln/detail/CVE-2014-1903)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### deepseek-ai/DeepSeek-V4.1-Flash (4.89 s)

Patch these in the order below — the three known-exploited flaws first, then the two older ones by exploit forecast.

- [CVE-2025-57819] — unauthenticated access to FreePBX Administrator via unsanitized input, leading to database manipulation and remote code execution. CVSS 9.8 Critical. In CISA KEV since 2025-08-29; ransomware use: Unknown. Affects 15.0 before 15.0.66, 16.0 before 16.0.89, 17.0 before 17.0.3. Fix: https://github.com/FreePBX/security-reporting/security/advisories/GHSA-m42g-xg4c-5f3h
- [CVE-2025-64328] — post-authentication command injection in the Endpoint Manager filestore module (testconnection → check_ssh_connect()), giving access as the asterisk user. CVSS 7.2 High. In CISA KEV since 2026-02-03; ransomware use: Unknown. Affects 17.0.2.36 before 17.0.3. Fix: https://github.com/FreePBX/security-reporting/security/advisories/GHSA-vm9p-46mv-5xvw
- [CVE-2019-19006] — improper authentication allowing password bypass into FreePBX admin. CVSS 9.8 Critical. In CISA KEV since 2026-02-03; ransomware use: Unknown. Affects 13.0.x through 13.0.197.13, 14.0.x through 14.0.13.11, 15.0.x through 15.0.16.26. Advisory: https://community.freepbx.org/t/freepbx-security-vulnerability-sec-2019-001/62772
- [CVE-2012-4869] — command execution via the callmenum parameter in callme_page.php. CVSS 7.5 High. Not in CISA KEV. Affects 2.9, 2.10 and earlier. Advisory: http://www.freepbx.org/trac/ticket/5711
- [CVE-2014-1903] — unrestricted API handler functions allowing PHP code execution via admin/config.php. CVSS 7.5 High. Not in CISA KEV. Affects 2.9, 2.10, 2.11, 2.12. Advisory: http://issues.freepbx.org/browse/FREEPBX-7117

The order follows known exploitation first, then highest EPSS forecast, then severity. I can't see your systems, so confirm your installed versions against the affected ranges above.

Sources: [CVE-2025-57819](https://nvd.nist.gov/vuln/detail/CVE-2025-57819), [CVE-2025-64328](https://nvd.nist.gov/vuln/detail/CVE-2025-64328), [CVE-2019-19006](https://nvd.nist.gov/vuln/detail/CVE-2019-19006), [CVE-2012-4869](https://nvd.nist.gov/vuln/detail/CVE-2012-4869), [CVE-2014-1903](https://nvd.nist.gov/vuln/detail/CVE-2014-1903)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

## M4: CVE-2024-55550 is only rated Low. Can we leave it until last?

**Reference answer:** No. Despite its 2.7 Low score, it is in CISA KEV and ransomware gangs have used it. Attackers chain it with CVE-2024-41713, which gives them the unauthenticated access the low score assumes they don't have. Patch both MiCollab flaws together.

### Qwen/Qwen3-235B-A22B-Instruct-2507 (10.16 s)

No, CVE-2024-55550 should not be left until last, despite its Low severity.

It is actively exploited (in CISA KEV) and linked to ransomware, and can be chained with CVE-2024-41713 to enable unauthenticated remote file access. Patching priority is determined by exploitation status first, not CVSS score.

- **CVE-2024-55550** [CVE-2024-55550]: Authenticated local file read in Mitel MiCollab; CVSS 2.7 LOW; in CISA KEV since 2025-01-07; ransomware use: Known; affected: MiCollab ≤9.8.1.201; fix: https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0029  
- **CVE-2024-41713** [CVE-2024-41713]: Unauthenticated remote file read; CVSS 9.1 CRITICAL; in CISA KEV; ransomware use: Known; affected: MiCollab ≤9.8.1.201; fix: same advisory  
- **CVE-2022-26143** [CVE-2022-26143]: Remote info leak and DoS; CVSS 9.8 CRITICAL; in CISA KEV; ransomware use: Unknown; affected: MiCollab <9.4 SP1 FP1; fix: https://www.mitel.com/en-ca/support/security-advisories/mitel-product-security-advisory-22-0001  
- **CVE-2024-35286** [CVE-2024-35286]: Unauthenticated SQL injection; CVSS 9.8 CRITICAL; not in KEV; EPSS 65.7%; affected: MiCollab ≤9.8.0.33; fix: https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-24-0014  
- **CVE-2020-11798** [CVE-2020-11798]: Directory traversal; CVSS 5.3 MEDIUM; not in KEV; EPSS 48.8%; affected: MiCollab <8.1.2.4 or <9.1.3; fix: https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-20-0005

Sources: [CVE-2024-55550](https://nvd.nist.gov/vuln/detail/CVE-2024-55550), [CVE-2024-41713](https://nvd.nist.gov/vuln/detail/CVE-2024-41713), [CVE-2022-26143](https://nvd.nist.gov/vuln/detail/CVE-2022-26143), [CVE-2024-35286](https://nvd.nist.gov/vuln/detail/CVE-2024-35286), [CVE-2020-11798](https://nvd.nist.gov/vuln/detail/CVE-2020-11798)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### Qwen/Qwen3-30B-A3B-Instruct-2507 (21.5 s)

No, CVE-2024-55550 should not be left until last, despite its Low severity, because it is in CISA’s KEV and has known ransomware use. It is also part of a known exploit chain with CVE-2024-41713, which is Critical and actively exploited.

- **CVE-2024-55550** | Mitel MiCollab | CVSS 2.7 LOW | CISA KEV: listed | Ransomware: Known  
  Affected versions: up to and including 9.8.1.201  
  Exploitation: in CISA KEV since 2025-01-07; EPSS: 38.2%  
  Description: Local file read via insufficient input sanitization by authenticated admin.  
  Fix: https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0029

- **CVE-2024-41713** | Mitel MiCollab | CVSS 9.1 CRITICAL | CISA KEV: listed | Ransomware: Known  
  Affected versions: up to and including 9.8.1.201  
  Exploitation: in CISA KEV since 2025-01-07; EPSS: 97.2%  
  Description: Unauthenticated path traversal in NPM component.  
  Fix: https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0029

- **CVE-2022-26143** | Mitel MiCollab, MiVoice Business | CVSS 9.8 CRITICAL | CISA KEV: listed | Ransomware: Unknown  
  Affected versions: MiCollab before 9.4 SP1 FP1; MiVoice Business up to 8.1  
  EPSS: 87.3%  
  Fix: https://www.mitel.com/en-ca/support/security-advisories/mitel-product-security-advisory-22-0001

- **CVE-2024-35286** | Mitel MiCollab | CVSS 9.8 CRITICAL | CISA KEV: not listed | Ransomware: Unknown  
  Affected versions: up to and including 9.8.0.33  
  EPSS: 65.7%  
  Fix: https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-24-0014

- **CVE-2020-11798** | Mitel MiCollab | CVSS 5.3 MEDIUM | CISA KEV: not listed | Ransomware: Unknown  
  Affected versions: before 8.1.2.4 (AWV), before 9.1.3 (9.x)  
  EPSS: 48.8%  
  Fix: https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-20-0005

Patch order: CVE-2024-55550 (KEV, ransomware, chained) → CVE-2024-41713 (KEV, highest EPSS) → CVE-2022-26143 (KEV, high EPSS) → CVE-2024-35286 → CVE-2020-11798.

Sources: [CVE-2024-55550](https://nvd.nist.gov/vuln/detail/CVE-2024-55550), [CVE-2024-41713](https://nvd.nist.gov/vuln/detail/CVE-2024-41713), [CVE-2022-26143](https://nvd.nist.gov/vuln/detail/CVE-2022-26143), [CVE-2024-35286](https://nvd.nist.gov/vuln/detail/CVE-2024-35286), [CVE-2020-11798](https://nvd.nist.gov/vuln/detail/CVE-2020-11798)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### openai/gpt-oss-120b (2.14 s)

No – even though CVE‑2024‑55550 is rated Low, it is listed in the CISA KEV program, has known ransomware use, a 38 % EPSS exploit forecast, and can be chained with the critical CVE‑2024‑41713, so it should be patched before “last”.

- **CVE‑2024‑55550** – Path‑traversal file‑read in Mitel MiCollab (admin‑auth) ; CVSS 2.7 Low; **CISA KEV listed**; ransomware use **Known**; affects MiCollab ≤ 9.8.1.201; advisory/fix → https://www.mitel.com/support/security‑advisories (vendor) [​CVE-2024-55550​]  
- **CVE‑2024‑41713** – Unauthenticated path‑traversal in NuPoint Unified Messaging (MiCollab ≤ 9.8.1.201) ; CVSS 9.1 Critical; **CISA KEV listed**; ransomware use **Known**; can be chained with CVE‑2024‑55550; advisory → https://www.mitel.com/support/security‑advisories/mitel‑product‑security‑advisory‑misa‑2024‑0029 [​CVE-2024-41713​]  
- **CVE‑2022‑26143** – Remote info‑leak/DDoS via TP‑240 component (MiCollab < 9.4 SP1 FP1, MiVoice Business ≤ 8.1) ; CVSS 9.8 Critical; **CISA KEV listed**; ransomware use **Unknown**; EPSS 87 %; advisory → https://www.mitel.com/en‑ca/support/security‑advisories/mitel‑product‑security‑advisory‑22‑0001 [​CVE-2022-26143​]  
- **CVE‑2024‑35286** – Unauthenticated SQL injection in NuPoint Messenger (MiCollab ≤ 9.8.0.33) ; CVSS 9.8 Critical; **not in CISA KEV**; ransomware use **not confirmed**; EPSS 66 %; advisory → https://www.mitel.com/support/security‑advisories/mitel‑product‑security‑advisory‑24‑0014 [​CVE-2024-35286​]  
- **CVE‑2020‑11798** – Directory traversal in web‑conference component (MiCollab < 8.1.2.4, 9.x < 9.1.3) ; CVSS 5.3 Medium; **not in CISA KEV**; ransomware use **not confirmed**; EPSS 49 %; advisory → https://www.mitel.com/support/security‑advisories/mitel‑product‑security‑advisory‑20‑0005 [​CVE-2020-11798​]

Sources: [CVE-2024-55550](https://nvd.nist.gov/vuln/detail/CVE-2024-55550), [CVE-2024-41713](https://nvd.nist.gov/vuln/detail/CVE-2024-41713), [CVE-2022-26143](https://nvd.nist.gov/vuln/detail/CVE-2022-26143), [CVE-2024-35286](https://nvd.nist.gov/vuln/detail/CVE-2024-35286), [CVE-2020-11798](https://nvd.nist.gov/vuln/detail/CVE-2020-11798)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### deepseek-ai/DeepSeek-V4.1-Flash (2.42 s)

No — despite its Low CVSS, CVE-2024-55550 should be patched first, not last. It is in CISA KEV with known ransomware use, and it chains with CVE-2024-41713, so severity alone understates the risk.

- [CVE-2024-55550] Mitel MiCollab path traversal (CWE-22); CVSS 2.7 Low; in CISA KEV since 2025-01-07, ransomware use: Known; EPSS 38.2%. Affected: MiCollab up to and including 9.8.1.201. Fix: https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0029
- [CVE-2024-41713] Chained flaw — unauthenticated path traversal in NuPoint Unified Messaging; CVSS 9.1 Critical; in CISA KEV since 2025-01-07, ransomware use: Known; EPSS 97.2%. Same affected versions and advisory.

Code's patch-priority order is known-exploited first, then highest exploit forecast, then severity: [CVE-2024-55550], [CVE-2024-41713], [CVE-2022-26143], [CVE-2024-35286], [CVE-2020-11798].

Sources: [CVE-2024-55550](https://nvd.nist.gov/vuln/detail/CVE-2024-55550), [CVE-2024-41713](https://nvd.nist.gov/vuln/detail/CVE-2024-41713), [CVE-2022-26143](https://nvd.nist.gov/vuln/detail/CVE-2022-26143), [CVE-2024-35286](https://nvd.nist.gov/vuln/detail/CVE-2024-35286), [CVE-2020-11798](https://nvd.nist.gov/vuln/detail/CVE-2020-11798)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

## F1: What new vulnerabilities were published for our products in the past 7 days?

**Reference answer:** Depends on the day. As of 2026-10-17 there were none: the newest, CVE-2026-20362 (Cisco Finesse), was published on 2026-10-07. A good answer always states the "data as of" date.

### Qwen/Qwen3-235B-A22B-Instruct-2507 (15.48 s)

No new vulnerabilities were published for your products in the past 7 days (since 2026-10-10). The most recent CVEs were published on 2026-10-07 and earlier.

- CVE-2026-20362: SSRF vulnerability in Cisco Finesse due to improper input validation; allows unauthenticated remote attackers to obtain limited sensitive information [CVE-2026-20362]. CVSS 7.2 (HIGH), EPSS 0.5%, not in CISA KEV. Affected: Cisco Finesse 12.6(1) through 12.6(1)ES9 and later versions. Fix: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-finesse-ssrf-mmSuyugS
- CVE-2026-104810: Directory traversal in Mitel MiVoice Office 400 web portal allows authenticated attackers to delete sensitive system files, leading to denial of service [CVE-2026-104810]. CVSS 8.4 (HIGH), EPSS 0.4%, not in CISA KEV. Affected: 11.0.96.0. Fix: https://digitalcanion.com/en/security-research/#vendor=mitel&status=cna
- CVE-2026-104809: Insecure module loading in Mitel MiVoice Office 400 allows authenticated attackers to load malicious .so files and achieve arbitrary code execution [CVE-2026-104809]. CVSS 8.4 (HIGH), EPSS 0.1%, not in CISA KEV. Affected: 11.0.96.0. Fix: https://digitalcanion.com/en/security-research/#vendor=mitel&status=cna
- CVE-2026-54710: RCE in FreePBX superfecta module via unsafe PHP file inclusion, requires authentication [CVE-2026-54710]. CVSS 8.8 (HIGH), EPSS 0.4%, not in CISA KEV. Affected: FreePBX <16.0.40 and <17.0.7. Fixed in 16.0.40 and 17.0.7. Fix: https://github.com/FreePBX/security-reporting/security/advisories/GHSA-j53p-5m8r-j3p6
- CVE-2026-75600: Command injection in FreePBX GraphQL API module allows authenticated attackers to execute arbitrary shell commands [CVE-2026-75600]. CVSS 8.8 (HIGH), EPSS 0.8%, not in CISA KEV. Affected: FreePBX <17.0.9. Fixed in 17.0.9. Fix: https://github.com/FreePBX/security-reporting/security/advisories/GHSA-79rg-3xp6-rqq6

Sources: [CVE-2026-20362](https://nvd.nist.gov/vuln/detail/CVE-2026-20362), [CVE-2026-104810](https://nvd.nist.gov/vuln/detail/CVE-2026-104810), [CVE-2026-104809](https://nvd.nist.gov/vuln/detail/CVE-2026-104809), [CVE-2026-54710](https://nvd.nist.gov/vuln/detail/CVE-2026-54710), [CVE-2026-75600](https://nvd.nist.gov/vuln/detail/CVE-2026-75600)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### Qwen/Qwen3-30B-A3B-Instruct-2507 (13.41 s)

No new vulnerabilities were published for your products in the past 7 days (since 2026-10-10). The newest CVEs in CallGuard’s data were published on 2026-10-07 and 2026-10-05, outside the requested window.

- **CVE-2026-20362** | Cisco Finesse | CVSS 7.2 HIGH | Not in CISA KEV | Ransomware status: Unknown | Affected versions: 12.6(1), 12.6(1)ES1–ES9, and 16 more | Fix: [Cisco Security Advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-finesse-ssrf-mmSuyugS)  
- **CVE-2026-104810** | Mitel MiVoice Office 400 | CVSS 8.4 HIGH | Not in CISA KEV | Ransomware status: Unknown | Affected versions: 11.0.96.0 | Fix: [DigitalCanion Research](https://digitalcanion.com/en/security-research/#vendor=mitel&status=cna)  
- **CVE-2026-104809** | Mitel MiVoice Office 400 | CVSS 8.4 HIGH | Not in CISA KEV | Ransomware status: Unknown | Affected versions: 11.0.96.0 | Fix: [DigitalCanion Research](https://digitalcanion.com/en/security-research/#vendor=mitel&status=cna)  
- **CVE-2026-54710** | FreePBX (including modules) | CVSS 8.8 HIGH | Not in CISA KEV | Ransomware status: Unknown | Affected versions: < 16.0.40, < 17.0.7 | Fix: [GitHub Advisory](https://github.com/FreePBX/security-reporting/security/advisories/GHSA-j53p-5m8r-j3p6)  
- **CVE-2026-75600** | FreePBX (including modules) | CVSS 8.8 HIGH | Not in CISA KEV | Ransomware status: Unknown | Affected versions: < 17.0.9 | Fix: [GitHub Advisory](https://github.com/FreePBX/security-reporting/security/advisories/GHSA-79rg-3xp6-rqq6)

Sources: [CVE-2026-20362](https://nvd.nist.gov/vuln/detail/CVE-2026-20362), [CVE-2026-104810](https://nvd.nist.gov/vuln/detail/CVE-2026-104810), [CVE-2026-104809](https://nvd.nist.gov/vuln/detail/CVE-2026-104809), [CVE-2026-54710](https://nvd.nist.gov/vuln/detail/CVE-2026-54710), [CVE-2026-75600](https://nvd.nist.gov/vuln/detail/CVE-2026-75600)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### openai/gpt-oss-120b (0.99 s)

No CVEs for the covered Cisco, Mitel, or FreePBX products were published between 2026‑10‑10 and 2026‑10‑17.  

- No matching CVE records fall within the 7‑day window (the newest entries are from 2026‑10‑07 and 2026‑10‑05) — this does not guarantee the products are free of vulnerabilities; consult the vendors’ security advisory pages for the latest information.

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### deepseek-ai/DeepSeek-V4.1-Flash (3.27 s)

No CVEs in CallGuard's data were published in the past 7 days (since 2026-10-10). The newest records overall are these, all older than the window:

- [CVE-2026-20362] Cisco Finesse — SSRF via improper input validation in the web management interface; unauthenticated remote attacker can obtain limited sensitive information. CVSS 7.2 High; not in CISA KEV, ransomware not confirmed. Affects 12.6(1) through 12.6(2) and later builds. Advisory: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-finesse-ssrf-mmSuyugS
- [CVE-2026-104810] Mitel MiVoice Office 400 — authenticated directory traversal in the web portal file browser, allowing file deletion and possible denial of service. CVSS 8.4 High; not in KEV. Affects 11.0.96.0. Advisory: https://digitalcanion.com/en/security-research/#vendor=mitel&status=cna
- [CVE-2026-104809] Mitel MiVoice Office 400 — predictable module name allows loading of an attacker-controlled .so file, giving arbitrary code execution and full compromise of the Mitel Linux VM. CVSS 8.4 High; not in KEV. Affects 11.0.96.0. Same advisory link.
- [CVE-2026-54710] FreePBX — authenticated RCE in the superfecta module via unsafe PHP file inclusion. CVSS 8.8 High; not in KEV. Affects versions before 16.0.40 and 17.0.7. Advisory: https://github.com/FreePBX/security-reporting/security/advisories/GHSA-j53p-5m8r-j3p6
- [CVE-2026-75600] FreePBX — authenticated shell command injection in the GraphQL api module. CVSS 8.8 High; not in KEV. Affects versions before 17.0.9. Advisory: https://github.com/FreePBX/security-reporting/security/advisories/GHSA-79rg-3xp6-rqq6

None are known-exploited, so none carry KEV priority.

Sources: [CVE-2026-20362](https://nvd.nist.gov/vuln/detail/CVE-2026-20362), [CVE-2026-104810](https://nvd.nist.gov/vuln/detail/CVE-2026-104810), [CVE-2026-104809](https://nvd.nist.gov/vuln/detail/CVE-2026-104809), [CVE-2026-54710](https://nvd.nist.gov/vuln/detail/CVE-2026-54710), [CVE-2026-75600](https://nvd.nist.gov/vuln/detail/CVE-2026-75600)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

## R1: Are there any vulnerabilities in Avaya CloudQueue Pro 4.2?

**Reference answer:** CallGuard doesn't recognize this product (it doesn't exist), so it has nothing to check. It should say so plainly, list the products it covers, and not guess.

### Qwen/Qwen3-235B-A22B-Instruct-2507 (2.4 s)

No matching CVE in CallGuard's data for Avaya CloudQueue Pro 4.2. This does not mean the version is free of vulnerabilities—only that no relevant CVEs were found in the current dataset. CallGuard does not cover Avaya CloudQueue Pro. Check Avaya’s official security advisories for product-specific guidance.

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### Qwen/Qwen3-30B-A3B-Instruct-2507 (6.76 s)

Yes, Avaya CloudQueue Pro 4.2 is affected by two critical vulnerabilities in Avaya IP Office, which shares underlying components with CloudQueue Pro.

- **CVE-2024-4196** – Improper input validation in the Web Control component allowing remote code execution. CVSS 9.8 CRITICAL. Not in CISA KEV. Exploit forecast: 0.6%. Affected: all versions before 11.1.3.1. Fix: [Vendor Advisory](https://download.avaya.com/css/public/documents/101090768)  
- **CVE-2024-4197** – Unrestricted file upload in the One-X component allowing remote code execution. CVSS 9.8 CRITICAL. Not in CISA KEV. Exploit forecast: 0.8%. Affected: all versions before 11.1.3.1. Fix: [Vendor Advisory](https://download.avaya.com/css/public/documents/101090768)

No other CVEs in the data apply to Avaya CloudQueue Pro 4.2. The vulnerabilities are prioritized by exploit forecast and severity, with both CVE-2024-4196 and CVE-2024-4197 being high-risk due to remote code execution potential.

Sources: [CVE-2024-4196](https://nvd.nist.gov/vuln/detail/CVE-2024-4196), [CVE-2024-4197](https://nvd.nist.gov/vuln/detail/CVE-2024-4197)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### openai/gpt-oss-120b (1.1 s)

No matching CVE in CallGuard’s data for Avaya CloudQueue Pro 4.2. This does not mean the product or version is free of vulnerabilities; you should review Avaya’s own security advisories and release notes for any relevant disclosures.

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### deepseek-ai/DeepSeek-V4.1-Flash (3.01 s)

CallGuard doesn't cover a product called "Avaya CloudQueue Pro," so I can't answer whether version 4.2 has vulnerabilities — and I won't substitute findings from other Avaya products.

The records returned by the search are for different products and are not matches for your question:

- CVE-2024-4196 and CVE-2024-4197 are Avaya IP Office flaws (remote code execution via Web Control and One-X; CVSS 9.8 Critical; not in CISA KEV; fixed in 11.1.3.1) [CVE-2024-4196] [CVE-2024-4197].
- CVE-2008-6706 and CVE-2008-6708 are Avaya Aura Communication Manager / legacy SES issues [CVE-2008-6706] [CVE-2008-6708].
- CVE-2023-31187 is Avaya IX Workforce Engagement [CVE-2023-31187].

CallGuard covers Avaya Aura Communication Manager, IP Office, Experience Portal/Orchestration Designer, Aura platform components, and IX Workforce Engagement — not CloudQueue Pro. Check Avaya's security advisories directly for that product.

Sources: [CVE-2024-4196](https://nvd.nist.gov/vuln/detail/CVE-2024-4196), [CVE-2024-4197](https://nvd.nist.gov/vuln/detail/CVE-2024-4197), [CVE-2008-6706](https://nvd.nist.gov/vuln/detail/CVE-2008-6706), [CVE-2008-6708](https://nvd.nist.gov/vuln/detail/CVE-2008-6708), [CVE-2023-31187](https://nvd.nist.gov/vuln/detail/CVE-2023-31187)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

## R4: Have we patched CVE-2024-41713 on our MiCollab servers?

**Reference answer:** CallGuard can't see your systems, so it can't know your patch status. It can tell you which versions are affected (up to and including 9.8.1.201) so you can check yours.

### Qwen/Qwen3-235B-A22B-Instruct-2507 (9.7 s)

I cannot determine whether your MiCollab servers are patched, as I don’t have access to your systems.

To check if you're patched against CVE-2024-41713:
- Affected versions: Mitel MiCollab up to and including 9.8.1.201 [CVE-2024-41713]
- This is a CRITICAL vulnerability (CVSS 9.1) and is actively exploited (in CISA KEV since 2025-01-07) with known ransomware use [CVE-2024-41713]
- Patch or mitigation is available: see https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0029 [CVE-2024-41713]

If your servers run a version earlier than or equal to 9.8.1.201, they are vulnerable and should be updated or mitigated immediately.

Sources: [CVE-2024-41713](https://nvd.nist.gov/vuln/detail/CVE-2024-41713)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### Qwen/Qwen3-30B-A3B-Instruct-2507 (5.4 s)

CallGuard cannot determine whether your MiCollab servers are patched, as it does not have visibility into your systems. However, based on the CVE data:

- **CVE-2024-41713** is a critical path traversal vulnerability in Mitel MiCollab up to and including version 9.8.1.201 [CVE-2024-41713]. It is in CISA KEV, has known ransomware use, and has a 97.2% exploit forecast. It can be chained with CVE-2024-55550.  
  **Fix**: Apply the mitigation or upgrade to a patched version via the vendor advisory: https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0029.

To verify patch status, check if your MiCollab servers are running a version **after 9.8.1.201**, ideally 9.8 SP2 or later, as newer versions address this and related vulnerabilities.

Sources: [CVE-2024-41713](https://nvd.nist.gov/vuln/detail/CVE-2024-41713), [CVE-2024-55550](https://nvd.nist.gov/vuln/detail/CVE-2024-55550)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### openai/gpt-oss-120b (1.1 s)

We can’t see the patch level on your servers, so you’ll need to verify the installed MiCollab version against the affected range for CVE‑2024‑41713.

- **CVE‑2024‑41713** – Critical (CVSS 9.1), listed in CISA KEV, ransomware‑related (known). Affects Mitel MiCollab up to and including 9.8.1.201 (9.8 SP1 FP2). Apply the vendor’s mitigations or upgrade per the advisory [https://www.mitel.com/support/security‑advisories/mitel‑product‑security‑advisory‑misa‑2024‑0029] [​CVE-2024-41713].

Sources: [CVE-2024-41713](https://nvd.nist.gov/vuln/detail/CVE-2024-41713)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### deepseek-ai/DeepSeek-V4.1-Flash (2.13 s)

I can't see your systems, so I can't tell whether your MiCollab servers are patched — you'll need to check the installed build against the affected versions below.

- [CVE-2024-41713] — Path traversal in the NuPoint Unified Messaging (NPM) component allowing unauthenticated access to view, corrupt, or delete user data and system configurations. CVSS 9.1 Critical. In CISA KEV (since 2025-01-07); ransomware use: Known. Affected: MiCollab up to and including 9.8.1.201. Fix: https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0029
- [CVE-2024-55550] — Local file read by an authenticated admin; CVSS 2.7 Low, but also in CISA KEV with Known ransomware use. Affected: up to and including 9.8.1.201. It chains with [CVE-2024-41713]. Fix: https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0029

If your build is 9.8.1.201 or lower, treat it as unpatched and apply Mitel's mitigations.

Sources: [CVE-2024-41713](https://nvd.nist.gov/vuln/detail/CVE-2024-41713), [CVE-2024-55550](https://nvd.nist.gov/vuln/detail/CVE-2024-55550)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

## R5: Are there known vulnerabilities in Avaya Aura Communication Manager 10.2?

**Reference answer:** No CVE in the data covers version 10.2 as of the data date. The most recent Communication Manager CVE, CVE-2022-2249, lists 8.x before 8.1.3.4 and 10.1.0.0. This does not confirm that 10.2 is safe; check Avaya's security advisories.

### Qwen/Qwen3-235B-A22B-Instruct-2507 (7.08 s)

No matching CVE in CallGuard's data affects Avaya Aura Communication Manager 10.2. This does not mean the version is free of vulnerabilities—only that no known CVEs in the current dataset list it as affected.

- CVE-2018-15617: Denial-of-service vulnerability in capro process; HIGH severity; not in CISA KEV; affects versions up to 8.0.1 [CVE-2018-15617]; 10.2 not affected.
- CVE-2022-2249: Local privilege escalation; MEDIUM severity; not in CISA KEV; affects versions up to 8.1.3.3 and 10.1.0.0 [CVE-2022-2249]; 10.2 not affected.
- CVE-2020-7029: CSRF in web interface; HIGH severity; not in CISA KEV; affects versions up to 8.1.0.0 [CVE-2020-7029]; 10.2 not affected.
- CVE-2008-5709 and CVE-2008-5710: Older web interface flaws; HIGH and MEDIUM severity; not in CISA KEV; affect versions 3.1–5.0 [CVE-2008-5709, CVE-2008-5710]; 10.2 not affected.

For confirmation, refer to Avaya’s official security advisories.

Sources: [CVE-2018-15617](https://nvd.nist.gov/vuln/detail/CVE-2018-15617), [CVE-2022-2249](https://nvd.nist.gov/vuln/detail/CVE-2022-2249), [CVE-2020-7029](https://nvd.nist.gov/vuln/detail/CVE-2020-7029), [CVE-2008-5709](https://nvd.nist.gov/vuln/detail/CVE-2008-5709), [CVE-2008-5710](https://nvd.nist.gov/vuln/detail/CVE-2008-5710)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### Qwen/Qwen3-30B-A3B-Instruct-2507 (12.78 s)

No known vulnerabilities in Avaya Aura Communication Manager 10.2 are documented in the provided CVE records.

- [CVE-2018-15617] Denial of service in capro process; CVSS 7.5 HIGH; not in CISA KEV; ransomware status unknown; affected versions: 6.3.x, 7.x before 7.1.3.2, 8.x before 8.0.1; not affected at 10.2 [Advisory: https://downloads.avaya.com/css/P8/documents/101055396]
- [CVE-2022-2249] Privilege escalation; CVSS 6.7 MEDIUM; not in CISA KEV; ransomware status unknown; affected versions: 8.0.0.0 to 8.1.3.3, 10.1.0.0; not affected at 10.2 [Advisory: https://download.avaya.com/css/public/documents/101083760]
- [CVE-2020-7029] CSRF in System Management Interface; CVSS 8.8 HIGH; not in CISA KEV; ransomware status unknown; affected versions: 7.0.x, 7.1.x before 7.1.3.5, 8.0.x; not affected at 10.2 [Advisory: https://support.avaya.com/css/P8/documents/101070201]
- [CVE-2008-5709] Arbitrary code execution via web interface; CVSS 9.0 HIGH; not in CISA KEV; ransomware status unknown; affected versions: 3.1.x, 4.0.x, 5.0.x; not affected at 10.2 [Advisory: http://secunia.com/advisories/32204]
- [CVE-2008-5710] Information disclosure via web interface; CVSS 5.0 MEDIUM; not in CISA KEV; ransomware status unknown; affected versions: 3.1.x, 4.0.3, 5.x; not affected at 10.2 [Advisory: http://secunia.com/advisories/32035]

All CVEs listed are outside the 10.2 version range. No other CVEs for Avaya Aura Communication Manager 10.2 were found.

Sources: [CVE-2018-15617](https://nvd.nist.gov/vuln/detail/CVE-2018-15617), [CVE-2022-2249](https://nvd.nist.gov/vuln/detail/CVE-2022-2249), [CVE-2020-7029](https://nvd.nist.gov/vuln/detail/CVE-2020-7029), [CVE-2008-5709](https://nvd.nist.gov/vuln/detail/CVE-2008-5709), [CVE-2008-5710](https://nvd.nist.gov/vuln/detail/CVE-2008-5710)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### openai/gpt-oss-120b (2.12 s)

No CVE in CallGuard’s data is reported to affect Avaya Aura Communication Manager 10.2. The listed flaws apply to earlier 6.x‑8.x releases or to 10.1.0.0, but not to 10.2. This does not guarantee that 10.2 is free of issues; consult Avaya’s security advisories for the latest information.

- **CVE‑2018‑15617** – Remote DoS via the “capro” process; **HIGH** severity; not in CISA KEV; ransomware use unknown; affected 6.3.x, 7.x < 7.1.3.2, 8.x < 8.0.1 [not 10.2]; advisory: https://downloads.avaya.com/css/P8/documents/101055396  
- **CVE‑2022‑2249** – Local privilege‑escalation for admin users; **MEDIUM** severity; not in CISA KEV; ransomware use unknown; affected 8.0‑8.1.3.3 and 10.1.0.0 [not 10.2]; advisory: https://download.avaya.com/css/public/documents/101083760  
- **CVE‑2020‑7029** – CSRF in the System Management Interface Web component; **HIGH** severity; not in CISA KEV; ransomware use unknown; affected 7.0‑7.1.x < 7.1.3.5 and 8.0.x [not 10.2]; advisory: https://support.avaya.com/css/P8/documents/101070201  
- **CVE‑2008‑5709** – Remote code execution via web‑management interface; **HIGH** severity; not in CISA KEV; ransomware use unknown; affected 3.1‑5.0 (pre‑SP versions) [not 10.2]; advisory: http://secunia.com/advisories/32204  
- **CVE‑2008‑5710** – Information disclosure through web‑management interface; **MEDIUM** severity; not in CISA KEV; ransomware use unknown; affected 3.1‑5.0 (pre‑SP versions) [not 10.2]; advisory: http://secunia.com/advisories/32035  

For confirmation, review Avaya’s current security bulletins and release notes for any newer advisories covering version 10.2.

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._

### deepseek-ai/DeepSeek-V4.1-Flash (5.22 s)

No matching CVE in CallGuard's data for Avaya Aura Communication Manager 10.2. Every record found covers older releases only, and the code's version checks mark 10.2 as outside all of them.

- CVE-2022-2249 (privilege escalation, CVSS 6.7 MEDIUM, not in CISA KEV, ransomware use unknown) is the closest: it affects 8.0.0.0 through 8.1.3.3 and 10.1.0.0 — not 10.2 [CVE-2022-2249].
- CVE-2018-15617 (DoS in the capro process, CVSS 7.5 HIGH, not in KEV) affects 6.3.x, 7.x before 7.1.3.2 and 8.x before 8.0.1 [CVE-2018-15617].
- CVE-2020-7029 (CSRF, CVSS 8.8 HIGH, not in KEV) affects 7.0.x, 7.1.x before 7.1.3.5 and 8.0.x [CVE-2020-7029].
- CVE-2008-5709 and CVE-2008-5710 affect 3.1 through 5.x only [CVE-2008-5709] [CVE-2008-5710].

This does not mean 10.2 is safe — absence of a record is not a clean bill of health. Check Avaya's security advisories for 10.2.

Sources: [CVE-2022-2249](https://nvd.nist.gov/vuln/detail/CVE-2022-2249), [CVE-2018-15617](https://nvd.nist.gov/vuln/detail/CVE-2018-15617), [CVE-2020-7029](https://nvd.nist.gov/vuln/detail/CVE-2020-7029), [CVE-2008-5709](https://nvd.nist.gov/vuln/detail/CVE-2008-5709), [CVE-2008-5710](https://nvd.nist.gov/vuln/detail/CVE-2008-5710)

_Data as of 2026-10-17 (NVD changes up to 2026-10-16, CISA KEV catalog 2026.10.16, EPSS scores of 2026-10-16)._
