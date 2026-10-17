# CallGuard roadmap

A learning roadmap for building CallGuard one phase at a time. Each phase ends with a checkpoint before the next one starts.

## Progress

- [x] Phase 0: Set up your workshop
- [x] Phase 1: Meet the data
- [x] Phase 2: Collect and clean the data
- [x] Phase 3: Write the exam first
- [x] Phase 4: Make the data searchable
- [x] Phase 5: Make search smart
- [ ] Phase 6: Answers with citations and safe refusals
- [ ] Phase 7: Build the call flow with LangGraph
- [ ] Phase 8: Keep it fresh
- [ ] Phase 9: Grade it like a QA team
- [ ] Phase 10: Give it a face
- [ ] Phase 11: Ship it

## The big idea

Picture a new agent on your floor. They're quick and articulate, but they don't know your products. So you give them a knowledge base and a rule: look it up first, answer only from what you found, quote the article number, and if it isn't there, say so.

That's **RAG** (retrieval-augmented generation):

- **Retrieval:** find the right articles. Ours are CVE records.
- **Generation:** an AI language model (an **LLM**) writes the answer from those articles, with citations.
- **Refusal:** if nothing matches, say so plainly, and never imply "you're safe."

CallGuard is that agent, specialized in security flaws in contact-center and UC products.

## What you'll have at the end

A chat app. A Tier 2 engineer asks *"Is there an actively exploited vulnerability in Mitel MiCollab?"* and gets a short answer containing:

- the CVE numbers, with links
- the severity
- whether attackers are using it
- the fix
- "data as of 14 Oct 2026, 22:00"

If they ask about a cloud product or a made-up version, it says it has no matching records, and that this doesn't mean they're safe.

## How the pieces fit

```
 NVD       --+
 CVE.org   --+
 CISA KEV  --+---> 1. Collect & clean    (refreshes every 2 h)
 EPSS      --+            |
                          v
                   2. Search index       (Qdrant: keywords + meaning)
                          |
 Question  ------> 3. Call flow          (LangGraph)
                   route > search > rerank > check > answer or refuse
                          |
                          v
                   4. Chat UI      5. Scorecard (25 test questions)
```

## Design decisions from the data check

See NOTES.md for the measurements behind these.

1. Pull specific products (~900 CVEs) instead of everything from each vendor.
2. Read version data from both NVD's own analysis and the vendor's list that NVD copies from CVE.org, and check "is my version affected?" in code. (Phase 1 showed that no separate CVE.org download is needed.)
3. Focus on on-prem and hybrid stacks. Cloud contact-center products get their own refusal message.
4. Filter by the vendor and product fields, not by words in the description.

## The phases

### Phase 0: Set up your workshop (~1–2 h)

- **Goal:** tools and accounts ready, project folder set up.
- **New ideas:**
  - *Terminal:* typing commands instead of clicking.
  - *Python environment:* a private toolbox for each project, so projects don't break each other.
  - *API key:* like an agent login. It identifies you and must stay secret.
  - *Git and GitHub:* version history for your code, plus an online backup.
- **You'll do:** install a few tools, create the folder structure, get your free NVD API key, set up Nebius and LangSmith, store your keys safely, and save the first version to GitHub.
- **Done when:** a check script shows a green tick for every tool, key and data source.

### Phase 1: Meet the data (~2–3 h)

- **Goal:** understand exactly what each source gives us.
- **New ideas:**
  - *API:* an IVR for computers. You ask in a fixed format and it answers with data.
  - *JSON:* data stored as labeled fields, like a CRM record.
  - *CVE:* a public ID for one security flaw.
  - *CVSS:* severity from 0 to 10, like ticket priority.
  - *CPE:* which products and versions are affected.
  - *KEV:* CISA's list of flaws that attackers are confirmed to be using.
  - *EPSS:* the chance a flaw will be exploited in the next 30 days, like a call-volume forecast.
  - Why NVD often lacks version data for recent CVEs, and where to find it instead.
- **You'll do:** make your first API calls in a notebook, follow one real CVE (Mitel MiCollab, CVE-2024-41713) through all four sources, and use your expertise to finalize the product list.
- **Done when:** you can explain that CVE field by field, and the product list is written down.

### Phase 2: Collect and clean the data (~4–6 h)

- **Goal:** one clean, trustworthy record per CVE.
- **New ideas:**
  - *Pipeline:* collect, clean, save, in that order.
  - *Paging:* fetching big results in batches.
  - *Rate limit:* the most calls an API allows per minute, like a concurrent-session cap.
  - Why messy data produces bad answers.
- **You'll do:** write scripts that pull your products from NVD (which already includes CVE.org's vendor data), add KEV and EPSS, tidy each record into readable text, and save it all to one file.
- **Done when:** you have ~900 clean records and a one-page data report: counts per product, how many have version data, and how many are being exploited.

### Phase 3: Write the exam first (~2–3 h)

- **Goal:** 25 test questions with their correct answers, written before we build the assistant.
- **New ideas:**
  - Why you set up the QA scorecard before launching a new queue.
  - The six question types: exact CVE ID, version-specific, search by meaning, multi-step, freshness, and should-refuse.
- **You'll do:** write the questions from your real-world experience. For each one, note the expected CVEs, or "should refuse".
- **Done when:** a test file with 25 questions and answers exists. Every later phase is measured against it.

### Phase 4: Make the data searchable (~3–4 h)

- **Goal:** a search index that finds CVEs both by exact words and by meaning.
- **New ideas:**
  - *Chunk:* the unit we store and fetch. Here, one CVE is one knowledge article.
  - *Embedding:* text turned into numbers so that similar meanings sit close together, like GPS coordinates for meaning.
  - *Vector database* (Qdrant): a library that can search by meaning.
  - *Keyword search* (BM25): exact matching, best for "CVE-2024-41713" or "8.1.3.2". We use both kinds of search.
- **You'll do:** turn each record into a chunk with a short label on top, create embeddings with Nebius, and load everything into Qdrant with filter tags (vendor, product, severity, exploited, date).
- **Done when:** a search for "MiCollab path traversal" puts the right CVE near the top.

### Phase 5: Make search smart (~4–6 h)

- **Goal:** the right 5 CVEs for every kind of question.
- **New ideas:**
  - *Hybrid search:* ask two experts, keyword search and meaning search, for their top lists, then merge the lists fairly. The merge method is called RRF.
  - *Filters:* like skills-based routing. Only Cisco, only critical, only exploited.
  - *Reranking:* a senior agent reads the 20 shortlisted articles and picks the best 5.
  - *Exact lookup:* questions with a CVE ID go straight to that record.
  - *Version checker:* plain code decides whether a version is affected, so we don't rely on the AI for that.
- **You'll do:** build the search function and the version checker, then score them on your Phase 3 questions, with and without reranking.
- **Done when:** you have numbers showing how often the right CVE lands in the top 5, before and after reranking.

### Phase 6: Answers with citations and safe refusals (~3–4 h)

- **Goal:** the first real answers. This is where it starts to feel like a product.
- **New ideas:**
  - *LLM:* the agent writing the reply from the articles.
  - *Prompt:* the agent's script.
  - *Hallucination:* confidently making things up. Citations and refusals guard against it.
  - Why "no CVE found" must never sound like "you're safe".
- **You'll do:**
  - Write the answer prompt.
  - Add CVE citations, NVD links and "data as of".
  - Work out patch priority in code: actively exploited first, then likely to be exploited, then severity.
  - Write the refusal wording.
- **Done when:** sample questions get correct, cited answers, and trick questions get safe refusals.

### Phase 7: Build the call flow with LangGraph (~4–6 h)

- **Goal:** the full assistant as a flow of steps with decision points.
- **New ideas:**
  - *LangGraph:* an IVR call-flow designer for AI steps, with steps, branches, and information passed along.
  - *Router:* the IVR menu that sends each question down the right path.
  - *Check step:* confirms the articles match the product and version asked about. If they don't, it rephrases the search once.
  - *LangSmith:* call recording plus screen capture. You can replay every step to see what went wrong.
- **You'll do:** connect route → search → rerank → check → answer or refuse, including the cloud-product refusal, and turn on LangSmith.
- **Done when:** every question type runs start to finish, and you can replay any question step by step in LangSmith.

### Phase 8: Keep it fresh (~2–3 h)

- **Goal:** data that's never more than a few hours old.
- **New ideas:**
  - *Upsert:* change only the records that changed, like editing today's schedule instead of rebuilding the whole year.
  - *Scheduling:* making a job run on its own every few hours.
- **You'll do:** build a sync job that fetches only what changed since the last run (NVD every 2 hours, KEV and EPSS daily), updates the index, and records the time.
- **Done when:** a sync run picks up newly changed CVEs, and answers show "data as of".

### Phase 9: Grade it like a QA team (~4–6 h)

- **Goal:** honest numbers on how good CallGuard is. This is probably what graders weigh most; the course brief will tell us for sure.
- **New ideas:**
  - *Faithfulness:* did the answer stick to the sources?
  - *Context precision and recall:* did search bring back the right articles, and all of them?
  - *Refusal accuracy:* did it decline exactly when it should?
  - *p50 and p95:* typical response time versus the slow tail. "p95 under 6 s" means 95 of 100 answers arrive within 6 seconds.
  - *RAGAS:* a tool that scores these automatically.
- **You'll do:** run all 25 questions, compare versions (with and without reranking, and different chunk designs), and write up what failed and why.
- **Done when:** you have a results table and a failure analysis, measured against the targets: at least 90% faithfulness, at least 95% correct refusals, and p95 under 6 seconds.

### Phase 10: Give it a face (~2–4 h)

- **Goal:** a chat app you can demo in a browser.
- **New ideas:**
  - *Front end and back end:* the agent desktop and the CRM server behind it.
  - *Streamlit:* a tool that builds a web page using only Python.
- **You'll do:** build a chat page with a sidebar for your stack and filters, a "data as of" badge, and clickable CVE links.
- **Done when:** you can demo every question type in the browser.

### Phase 11: Ship it (~4–6 h)

- **Goal:** all deliverables submitted.
- **You'll do:**
  - Tidy the GitHub repo and write its README.
  - Turn NOTES.md into the Google Doc: overview, data sources, prompts, chunking and reranking experiments, failure analysis.
  - Script and record the 5-minute video: one question of each type, a refusal, and a fresh CVE.
- **Done when:** the repo, Google Doc and video are submitted.

**Rough total: 35–55 hours.** These are loose estimates, and setup problems alone can add time.

## Where each deliverable comes from

| Deliverable | Built in |
|---|---|
| GitHub repo | Phases 0–10, tidied in 11 |
| Google Doc | NOTES.md from every phase, written up in 11 |
| Results and failure analysis | Phases 5 and 9 |
| Chat UI (bonus) | Phase 10 |
| 5-minute video | Phase 11 |
