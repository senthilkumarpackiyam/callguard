# CallGuard build log

What we decided, what we measured and what we learned, phase by phase. This becomes the Google Doc in Phase 11.

## Before Phase 0: checking the data sources (2026-10-14)

Before committing to the project, we queried the four live sources for the products in scope.

- **All sources are live and current.** The KEV catalog was updated on 2026-10-13, EPSS scores were dated 2026-10-14, and the newest in-scope NVD CVE was published on 2026-10-07.
- **Corpus size:** about 880 CVEs when scoped to specific contact-center and UC products. All CVEs mentioning Cisco would be about 7,000, mostly routers and firewalls, so we scope by product.
- **NVD's version gap:** only 53–56% of 2025–2026 CVEs have NVD version ranges (CPE), against 100% for 2023 and earlier. CVE.org records had version data for all 10 gaps we sampled, so CVE.org becomes a fourth source.
- **Cloud products have almost no CVEs:** Amazon Connect 0, Five9 3, NICE CXone 6, Genesys 8. We focus on on-prem and hybrid stacks, and cloud products get their own refusal.
- **Keyword search is noisy:** "Twilio" matched CVEs for Nagios XI and OpenClaw, and "asterisk" matched about 40 CVEs unrelated to the Asterisk PBX. We filter on vendor and product fields instead.
- **KEV is thin for this domain:** 12 in-scope entries (Mitel 6, FreePBX 3, Cisco CUCM 2, Twilio Authy 1). All 4 ransomware-linked entries are Mitel.
- **Records are short:** the median description is about 64 tokens (p90 about 136), so a fixed 256-token split wouldn't split anything.

## Phase 0: Setup (2026-10-17)

- **Python 3.12, managed by uv.** AI libraries often lag behind the newest Python, so we chose an established version. uv gives the project its own environment.
- **Project layout:** shared code in `src/callguard/`, runnable jobs in `scripts/`, exploration in `notebooks/`, test questions in `eval/`, data in `data/`.
- **Secrets:** keys live only in `.env`, which Git ignores. `.env.example` lists the key names without values.
- **Nebius:** the AI platform is now called Token Factory; its API address is `https://api.tokenfactory.nebius.com/v1/`.
- **Setup check:** `scripts/check_setup.py` passes all 8 checks. Nebius lists 28 models, and the LangSmith key is accepted.
- **NVD API key:** the request form's Cloudflare security check wouldn't load in the browser, so we're continuing without a key. It's optional: it raises the limit from 5 to 50 requests per 30 seconds, and the full pull needs only about 20 requests.

## Phase 1: Meet the data (2026-10-17)

The notebook `notebooks/01_meet_the_data.ipynb` follows CVE-2024-41713 (a Mitel MiCollab path traversal flaw) through all four sources.

- **Correction to the data check:** NVD records now include an `affected` field, which is the vendor's version list copied from CVE.org. With it, version coverage for 2025–26 CVEs rises from 54% (NVD's own CPE analysis) to 89%, and older CVEs stay at 100%. So we read versions from both fields, and a separate CVE.org download isn't needed.
- **Who provides what:** NVD is the main source: description, CVSS, CWE, CPE, the vendor's version list, KEV's "exploited" flag and tagged links. Only KEV has the ransomware and forensic-triage flags. Only EPSS has the 30-day exploitation forecast.
- **"Unknown" is not "no":** KEV's ransomware field is either "Known" or "Unknown", and "Unknown" means unconfirmed. It's the same principle as "no CVE found" not meaning "safe".
- **Version names aren't simple numbers:** Cisco lists versions like `12.6(1)ES1` and `15.0(1)SU2`, so checking a version needs code that understands each vendor's format.
- **Attribution:** NVD's terms ask apps to show "This product uses the NVD API but is not endorsed or certified by the NVD."
- **Facts for test questions:** CVE-2024-41713 scores CVSS 9.1 (Critical), CWE-22, and affects MiCollab up to 9.8.1.201. It has been in KEV since 2025-01-07 (federal due date 2025-01-28), ransomware use is Known, EPSS is 97% (99.9th percentile), and it can be chained with CVE-2024-55550. The fix is in Mitel advisory MISA-2024-0029.

### Product scope

- **Decision:** 24 products are in scope: 8 Cisco, 5 Avaya, 7 Mitel, plus Asterisk, FreePBX, Genesys on-prem and Verint. 5 cloud products are recognized and answered with the cloud message (Amazon Connect, NICE CXone, Five9, Genesys Cloud CX, Twilio Flex). 3 are deliberately left out: Cisco Unified IP IVR, Cisco Emergency Responder, and Avaya products from before 2010. The list lives in `config/products.toml`.
- **Size:** in the data pulled on 2026-10-14, the in-scope products have 740 CVEs: 125 published since 2024, and 11 in KEV.
- **One product, many names:** Asterisk appears under more than 15 names (Digium became Sangoma, and there are several editions), so each product lists every name it goes by.
- **Same name, different product:** "CXone" matched OMRON factory software, "Finesse" was also the name of old Cisco firewall software, and "presence" hides inside "TelePresence". So matching uses product fields, with exact names and exclusions, never words in the description.
- **For Phase 2:** 12 recent CVEs in the pull had no product data at all, so the list can't match them. Phase 2 will try a fallback that looks for the product names in the description.

### Setup lesson: iCloud and the virtual environment

- The project is in `~/Documents`, which iCloud syncs. iCloud marks files whose names start with a dot as hidden, and Python skips hidden `.pth` files, so our own code became invisible to Python.
- **Fix:** the virtual environment now lives outside iCloud, at `~/.venvs/callguard`, and `.venv` is a shortcut (symlink) to it. This also stops iCloud from uploading about 15,000 package files.

## Phase 2: Collect and clean (2026-10-17)

- **Pipeline:** `scripts/collect.py` runs four steps. **Collect:** ask NVD for every CVE that mentions each vendor (16 searches, 7,574 CVEs, about 3 minutes without an API key). **Filter:** keep our products using `config/products.toml`. **Enrich:** add KEV and EPSS. **Clean and save:** write `data/processed/cves.jsonl` (one record per line) and `manifest.json` (the "data as of" times). Raw downloads stay in `data/raw/`, which Git ignores.
- **Result:** 889 records: 886 for in-scope products and 3 for Five9 (cloud). That's more than the 740 estimated in Phase 1, because searching by vendor finds CVEs that searching by product phrase missed. For example, Unity Connection went from 22 to 72 CVEs, CVP from 2 to 17 and CUIC from 4 to 28.
- **The description fallback earns its place:** 7 CVEs had no product data at all. Most are recent Mitel flaws that MITRE filed and NVD put on hold ("Deferred"). One is CVE-2025-52913, a critical (9.8) MiCollab path traversal much like CVE-2024-41713.
- **Version data is messy:** vendors write versions as ranges ("before 17.0.9"), as lists of exact builds (Cisco lists 28 builds like `12.6(1)ES1`), or only in the description ("through 9.8 SP2 (9.8.2.12)"). Each record keeps the structured ranges plus a readable summary.
- **Severity:** CVSS 3.1 is preferred so that scores can be compared. 366 older CVEs only have CVSS v2, which has no "Critical" level.
- **Watch list:** the riskiest recent flaw that isn't in KEV is CVE-2024-35286 (Mitel MiCollab, 9.8 Critical, EPSS 66%).
- The full one-page report is in `reports/data_report.md`.

## Phase 3: Write the exam first (2026-10-17)

- **The exam:** `eval/questions.toml` holds 25 questions with reference answers. They were written before building the assistant, so the test isn't shaped by whatever the assistant happens to do well. The mix is 4 exact CVE number, 5 version-specific, 5 search by meaning, 4 multi-step, 2 freshness and 5 should-refuse. The user reviewed and approved all 25.
- **Every answer comes from the data:** `scripts/check_questions.py` confirms that each expected CVE exists in `data/processed/cves.jsonl` and is named in its question or answer. Run it again whenever the data or the questions change.
- **Questions designed to catch specific mistakes:**
  - V2 tests the edge of a range ("up to and including").
  - V3 tests saying "not affected" correctly while spotting a related flaw (CVE-2025-52913) whose versions appear only in its description.
  - S2 includes a detail ("without logging in") that rules one CVE out.
  - M2's correct answer is "none confirmed", because Unknown is not the same as no.
  - M4 asks about a Low (2.7) CVE that ransomware gangs use and chain with a critical one: severity is not the same as risk.
  - F1 and F2 depend on the day they're asked, so grading works out their answers from the data at grading time.
  - R1–R5 cover five kinds of "no": an unknown product, a cloud product, an out-of-scope product, private data, and no matching records.
- **Data fixes made along the way:** CISA's short summary is now kept in each exploited record, because that's where the chaining of CVE-2024-41713 and CVE-2024-55550 is recorded. `scripts/collect.py --offline` re-cleans the saved downloads in about a second.
