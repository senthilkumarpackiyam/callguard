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

## Phase 4: Make the data searchable (2026-10-17)

- **Embedding model:** Qwen/Qwen3-Embedding-8B, the only embedding model on the Nebius account. It turns each text into 4,096 numbers. As the model recommends, questions get a one-line task description ("Instruct: … Query: …") and records don't.
- **What gets embedded (the chunk):** one CVE per chunk. Each chunk holds a header line (CVE, products, severity, KEV status), the description, the affected versions, the weakness, and the exploitation note with CISA's summary. Three things stay out: the EPSS score and last-updated date, because they change daily (they're kept as filter tags instead), and links, because URLs blur meaning. Embedding all 889 took 122 seconds and 191,610 tokens. Embeddings are cached in `data/index/`, so a rebuild only pays for text that changed.
- **The index:** Qdrant runs on the Mac (`data/index/qdrant`) with two searches side by side. Search by meaning uses cosine similarity between embeddings. Search by keywords uses BM25, where IDF weighting makes rare words count more. Each CVE also carries filter tags: products, vendors, scope, published date and year, severity, CVSS, KEV, ransomware, EPSS and CWE.
- **First searches (top 5):**
  - "MiCollab path traversal": search by meaning returned exactly the 5 MiCollab path traversal CVEs; search by keywords found 4 of them.
  - "CVE-2024-41713": search by keywords put it first. Search by meaning missed it completely and returned CVEs with similar-looking numbers (41711, 41714), because embeddings blur numbers.
  - Finesse SSRF described in plain words: search by meaning found 4 of the 5 expected CVEs; search by keywords found 2.
  - "Finesse 12.6(2)ES3": neither search handles versions well, which is why Phase 5 checks versions in code.
  - A Bluetooth attack on Mitel phones: both searches put CVE-2020-27639 first.
- **Lesson:** each kind of search succeeds where the other fails, which is why Phase 5 combines them (hybrid search).

## Phase 5: Make search smart (2026-10-17)

- **What smart search does, in order:**
  1. It opens any CVE named in the question directly, plus any CVE that record mentions (for example, a chained flaw).
  2. It reads the question for products, vendors, a version, severity, and words about exploitation, ransomware, priorities or recency (`callguard.understand`).
  3. It filters the search to those, and relaxes the filters step by step if nothing matches.
  4. It ranks "what first?" questions by rule (exploited, then exploit forecast, then severity) and "newest" questions by date.
  5. Otherwise it runs hybrid search, merging meaning and keyword results with RRF. When a question names a CVE, the search also uses that CVE's description ("more like this"), so look-alike flaws surface.
  6. If a version is named, the version checker marks each CVE as affected, not affected or unknown, and ranks affected first.
- **Version checker (`callguard.versions`):** compares versions in plain code. 24 automated tests (`uv run pytest`) cover the exam's version cases, plus traps found along the way:
  - CISA once wrote a version as `9.8-SP1-\/9.8.1.5\/`, which at first made 9.8.2.0 look affected.
  - NVD and CISA sometimes disagree (NVD says up to 9.8.1.201, CISA says before 9.8.2.12). The checker then answers "affected", the cautious choice, and states that the sources disagree.
- **Retrieval scores on the exam** (18 questions with known CVEs, top 5; the full table is in `reports/retrieval_eval.md`):

| Setup | Found all | Share of expected CVEs found | Time per question |
|---|---|---|---|
| Meaning only | 6/18 | 44% | 6 ms |
| Keywords only | 10/18 | 68% | 10 ms |
| Hybrid (RRF) | 11/18 | 74% | 20 ms |
| Smart search | 16/18 | 96% | 31 ms |
| Smart + MiniLM reranker | 16/18 | 96% | 1.0 s |
| Smart + BGE reranker | 16/18 | 96% | 8.6 s |

- **Decision: no reranker by default.** Both rerankers matched smart search without improving on it, and they added 1 to 8.6 seconds per question. Phase 9 re-tests this on full answers.
- **The biggest gain came from understanding the question**, not from better ranking. Exact lookups, filters, priority rules and the version checker took search from 74% to 96%.
- **Remaining misses:** S1 and S2 ask for every matching flaw (5 and 6 CVEs), which is more than fits in a top 5. Phase 6 may give list-type questions more room.
- **Exam correction:** for S2, search found two correct answers the exam had missed: CVE-2023-25597 (download a shared file without logging in) and CVE-2022-36452 (upload malicious files without logging in). Both are now in the exam.

## Phase 6: Answers with citations and safe refusals (2026-10-17)

- **How an answer is made (`callguard.answer`):**
  1. Retrieve the records, as in Phase 5.
  2. Code handles three refusals itself, with no AI call: a deliberately excluded product, a cloud product with no records, and no records at all. These answer in under a second.
  3. Otherwise the model gets three things: the question; the facts code has worked out (products, the version asked about, the patch order, or "nothing in the past 7 days"); and the CVE cards with their version-check results. The model writes the answer from those.
  4. Code then adds the sources (NVD links) and the "data as of" line, and checks that every CVE cited was among the records the model was given.
- **The agent's script (system prompt) has 11 rules:**
  - answer only from the records, and cite every claim as [CVE-…]
  - give a direct answer first, then one bullet per CVE
  - trust the version checks and the patch order worked out by code
  - "Unknown" ransomware use doesn't mean no, and severity isn't the same as risk
  - say "No matching CVE…", plus "this does not mean safe", when nothing matches
  - name any product CallGuard doesn't cover, and don't substitute other products
  - say it can't see the user's systems when asked about them
  - be brief
- **Choosing the model:** four Nebius models answered 11 exam questions from the same records (`reports/model_comparison.md`):

| Model | Expected CVEs cited | Refusals worded safely | Citations not in the records | Average time | Slowest |
|---|---|---|---|---|---|
| Qwen3-235B | 85% | 3/3 | 0 | 6.7 s | 15.5 s |
| Qwen3-30B | 94% | 1/3 | 0 | 14.5 s | 22.9 s |
| gpt-oss-120b | 72% | 2/3 | 0 | 1.8 s | 2.7 s |
| **DeepSeek-V4.1-Flash (chosen)** | 94% | 3/3 | 0 | 3.7 s | 5.2 s |

- **Why refusal tests matter:** asked about a product that doesn't exist ("Avaya CloudQueue Pro 4.2"), Qwen3-30B answered, in both runs: "Yes, Avaya CloudQueue Pro 4.2 is affected by two critical vulnerabilities in Avaya IP Office, which shares underlying components with CloudQueue Pro." That is a confident invention. DeepSeek answered: "CallGuard doesn't cover a product called 'Avaya CloudQueue Pro' … and I won't substitute findings from other Avaya products."
- **Reasoning models think before they write:** in one test, DeepSeek-V4.1-Flash spent 836 of 900 tokens on hidden reasoning, which cut a long answer off. The limit is now 4,000 tokens, and any answer that still gets cut off is flagged. Two other "thinking" models (GLM-5.3-Flash, Kimi-K3) were dropped early, after using about 300 tokens of reasoning for a one-sentence reply.
- **Exam corrections:** S2 gained CVE-2020-11797 (unauthenticated access to shared files), which the answers surfaced. M3's reference answer now describes the priority rule instead of naming two CVEs that the rule doesn't rank next.
- **Automatic checks have blind spots:** curly apostrophes ("don’t") and other wording ("no visibility into your environment") made good refusals look like failures until the checker was fixed. Phase 9 uses a stronger grader.

## Phase 7: The call flow with LangGraph (2026-10-17)

- **The flow (`callguard.graph`)** has seven steps and three decision points. The diagram is in `reports/flow_check.md`.
  - **Understand:** read the question. A product deliberately not covered goes straight to refuse.
  - **Retrieve:** find the records. The route is one of lookup (a CVE is named), priority ("patch first"), newest ("past 7 days"), search, or cloud.
  - **Check:** a quick model (Qwen3-235B) reads the records and says whether they're the right ones. If they aren't, it proposes a better search, which is used once (rephrase, then retrieve again).
  - **Write:** DeepSeek-V4.1-Flash writes the answer from the records. If the check still says they don't fit, the model is told to say what's missing rather than stretch the records to fit.
  - **Refuse** and **finish:** refusals decided by code, then the sources and the "data as of" line.
- **LangSmith tracing:** every run records each step's inputs and outputs, and every model call with its prompt, answer, tokens and time, in the `callguard` project. `scripts/ask.py` prints a link for replaying the question.
- **All 25 exam questions in three settings** (`reports/flow_check.md`):

| Flow | Expected CVEs found | Refusals worded safely | Citations not in the records | Average time | p95 |
|---|---|---|---|---|---|
| Check every search | 90% | 5/5 | 0 | 4.2 s | 8.2 s |
| **Check open questions only (default)** | 90% | 5/5 | 0 | 2.8 s | 4.0 s |
| No check | 90% | 5/5 | 0 | 2.8 s | 4.4 s |

- **Decision:** the check runs only for open-ended questions that name no product, vendor or CVE. Checking every search added time (p95 of 8.2 s) without finding more, and it raised a false alarm on M2, where "none is confirmed" is the right answer. When a product or vendor is named, filters already keep the search on topic.
- **Every question type flows end to end:** exact lookups, versions, search, priority, newest, and all five kinds of refusal. The only misses are the two "list everything" questions: S1 found 4 of 5, S2 found 4 of 7.
- **Fixes found by running the flow:**
  - A version like "4.2" was checked against every product when no product was named. It's now checked only when we know whose version it is.
  - The answer script now forbids links that aren't in the records.
  - The refusal-wording check moved into shared code (`callguard.evaluate`).

## Phase 8: Keep it fresh (2026-10-17)

- **How a sync works (`callguard.sync`, run by `scripts/sync.py`):**
  1. Ask NVD for every CVE changed since the last sync, in windows of at most 120 days (NVD's limit). Rejected CVEs are included, so they can be removed.
  2. Add, update or remove each one, using the same product matching as Phase 2.
  3. Refresh CISA KEV and FIRST EPSS for every record (both are small).
  4. Save the records, the manifest (the "data as of" time) and a line in `data/processed/sync_log.jsonl`. Each file is written to a temporary copy and then swapped in, so a program reading at that moment never sees half a file.
  5. Update the index in place (an "upsert"): only changed records are touched, and only changed text is re-embedded. Only one program can have the index open at a time, so if the chat app has it open, the sync queues the changes and the app applies them before its next answer.
- **Schedule:** macOS's launchd runs the sync every 2 hours (`scripts/schedule_sync.py on|off|status`; the log is `~/Library/Logs/callguard-sync.log`). NVD asks automated tools to sync no more often than every two hours. The first run waited for macOS's permission to read the Documents folder; after one "Allow", runs finish in seconds.
- **Results:**

| Sync | NVD CVEs changed | Ours: new / updated / removed | Time |
|---|---|---|---|
| First real sync (18 hours of changes) | 544 | 0 / 0 / 0 | 8 s |
| Simulated two weeks offline | 27,692 | 6 / 21 / 0 | 146 s |
| First two scheduled runs | 0 | 0 / 0 / 0 | 2–4 s |

- **The sync found CVEs the original pull had missed:** 6 Mitel MiVoice Office 400 flaws, published 2026-10-05, whose descriptions never name Mitel. Phase 2 searched descriptions for vendor names; the sync checks each changed CVE's product data. **Limitation:** a CVE that never changes again and doesn't name its vendor can still be missed. A full scan of NVD by product data would close that gap, and an NVD API key (10 times the rate limit) would make it practical.
- **"Data as of" now includes the time of day (UTC)**, and a long-running app picks up a new sync before its next answer.
- **A latency spike:** one answer took 45 s because Nebius responded slowly; the same question normally takes about 4 s. Phase 9's p95 figure will capture spikes like this honestly.

## Phase 9: Grade it like a QA team (2026-10-17)

- **How:** all 25 exam questions ran through the full call flow in five setups (`scripts/run_exam.py`). RAGAS 0.4.3 graded faithfulness, context precision and context recall (`scripts/score_ragas.py`), with Qwen3-235B as the judge, a different model from the writer. RAGAS needs older LangChain libraries than the app, so grading runs in its own throwaway environment: the app sits the exam, and a separate grader marks it. `scripts/report_eval.py` writes `reports/evaluation.md`; the failure analysis is in `reports/failure_analysis.md`.
- **Targets (final setup), all met:**
  - Faithfulness: 92% on the 20 answerable questions; 88% including the three refusals the model wrote.
  - Correct refusals: 5 of 5, with no false refusals.
  - p95: 4.6 s over 75 answers from three runs; p50 2.4 s.
- **Setups compared:**

| Setup | Faithfulness (answerable) | Context precision | Context recall | Expected CVEs found | p95 (one run) |
|---|---|---|---|---|---|
| **Final: cards, 8 records for search questions** | 92% | 92% | 95% | 95% | 4.6 s |
| Cards, 5 records | 91% | 90% | 89% | 90% | 7.3 s |
| Cards, 5 records + MiniLM reranker | 90% | 94% | 89% | 88% | 7.4 s |
| Cards without the header line | 93% | 92% | 89% | 88% | 6.0 s |
| Description-only chunks | 89% | 91% | 89% | 85% | 11.6 s |

- **Decision:** search questions now get 8 records instead of 5. This raised recall from 89% to 95% and expected CVEs found from 90% to 95%, mostly for "list everything" questions. The reranker stays off: it found fewer of the expected CVEs, and its small faithfulness gain is within the judge's noise.
- **Main findings** (details in `reports/failure_analysis.md`):
  - RAGAS faithfulness penalizes CallGuard's safety wording: refusals and "this doesn't mean safe" can't be found in any record. A second judge's audit of the 10 lowest-scoring answers found one minor unsupported phrase and no invented facts.
  - Context precision scored 0 for a perfect search (M1), because the judge rates each one-CVE record on its own against a four-CVE answer. Metric results need sanity checks.
  - LLM judges are noisy: re-grading the same answer moved its faithfulness by 3 points. One run's p95 also swings with Nebius's speed, so p95 is measured over three runs.
  - The citation check now accepts CVEs named inside the records shown (CISA's "chained with" notes).

## Phase 10: Give it a face (2026-10-17)

- **Change of plan:** a branded website instead of a Streamlit chat page. It is plain HTML, CSS and JavaScript (`web/`), served by a small FastAPI server (`callguard.web`). Start it with `uv run scripts/serve.py`, then open http://localhost:8000.
- **What's on the page:**
  - The CallGuard brand: a shield-and-headset logo, an icon for the browser tab and a hero image, in navy, teal and mint (`web/static/brand/`).
  - A "Data as of" badge, which turns amber when the data is more than 3 hours old.
  - The latest vulnerabilities, newest first, with filters (vendor, product, severity, exploited only, text). A click opens the details: affected versions, CISA KEV and ransomware status, EPSS and links.
  - The chat. Answers stream in word by word, with progress lines such as "Searching the records…". CVE IDs in an answer open the same details panel.
  - Downloads: the filtered list as CSV, Excel or PDF, and any answer as a PDF.
  - Email: CallGuard opens a draft in the user's own email app (a "mailto" link) for any number of recipients. The server never sends mail, so it needs no mail account or password. Email apps limit how long a draft can be, so long answers are shortened in the draft.
- **Safety:**
  - Text from the data and from the AI is cleaned (with DOMPurify) before it's shown, and only web and CVE links are allowed.
  - The NVD notice and the "no CVE found doesn't mean safe" note appear on the page and in every PDF.
- **One question at a time:** only one program can open the index, so the server answers questions in turn. Each answer runs in its own worker, which always releases the index, even if the visitor closes the page midway. The first version held the index while streaming, so one abandoned answer froze every later question.
- **Testing:**
  - 7 automated tests for the server, for 35 tests in all.
  - A browser test that drives Chrome like a user (`scripts/check_website.py`, with Playwright). It covers the list, details, chat, PDF download, email checks and the phone layout: 12 of 12 checks pass.
- **Bugs found by testing in a real browser:**
  - **Hidden answer buttons.** The screen redraws the answer as it streams in. A redraw still waiting for its turn could paint the half-written answer back over the finished one, hiding its sources, its "Data as of" line and its buttons. This happened only when the last words and the "done" signal arrived together, so it appeared now and then. A test now forces that timing on every run.
  - **Web codes in 46 records (44 Cisco, 2 Avaya).** NVD's text had "IM &amp; Presence" instead of "IM & Presence", plus non-breaking spaces. Cleaning now decodes only complete codes, so a web address like "?a=1&para=2" stays intact. The 46 records were cleaned and re-indexed, and search scored the same as before (18 of 18 found at least one expected CVE, 16 of 18 found them all).
  - **PDFs.** The logo's two words had a gap, the footer ran into the page number, and "ransomware" broke mid-word in a narrow column.
  - **Phone layout.** The filters were cut off, and the list scrolled inside a short box. On phones the filters now sit two per row, and the list flows with the page, 10 at a time.
