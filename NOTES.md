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
