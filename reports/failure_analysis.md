# Failure analysis

What went wrong in the evaluation (`reports/evaluation.md`), why, and what was done about it. Unless stated otherwise, figures are for the final setup: card chunks, 8 records for search questions, 25 exam questions.

## 1. "List everything" questions miss some CVEs (retrieval)

- **S2** ("Is there a way to read or change files on a MiCollab server without logging in?") found 5 of its 7 expected CVEs with 8 records, up from 4 of 7 with 5. Still missed: CVE-2025-52913 and CVE-2021-27402.
- **S1** (Finesse server-side request forgery) went from 4 of 5 to 5 of 5 with 8 records.
- **Cause:** these questions have more right answers than fit in a top 5. The CVEs still missed are either worded differently from the question ("access (view and modify) user data by injecting arbitrary directory paths" in the SAS Admin portal) or near-duplicates of a higher-ranked record (CVE-2025-52913 repeats CVE-2024-41713's NuPoint path traversal).
- **Done:** search questions now get 8 records, which raised context recall from 89% to 95% and expected CVEs found from 90% to 95%.
- **Next:** for explicit "list all" questions, list every record that passes the filters and let the writer summarize; or rephrase the question into the flaw type ("path traversal") before searching.

## 2. Faithfulness scores penalize safety wording (a metric limitation)

- **R1** (a product that doesn't exist) scored 0.00–0.07 faithfulness, and **R4** and **R5** scored 0.76–0.87. RAGAS splits an answer into claims and looks for each one in the records. Refusals and caveats ("CallGuard doesn't cover…", "this does not mean it's safe", "I can't see your systems") can't be found in any record, so they count as unsupported, even though CallGuard is designed to say them.
- **A second judge audited the 10 lowest-scoring answers**, with a different prompt that labels each unsupported statement as a fact or as guidance. It found one unsupported factual phrase ("ransomware status unknown" for a CVE that isn't in KEV, a slight overstatement), two guidance statements, and nothing else: no invented CVEs, versions, scores or fixes. Across all five setups, no answer cited a CVE that wasn't in its records.
- **Strict claim-splitting also marks reasonable inferences as unsupported**, for example "the score may be revised", inferred from NVD's "Awaiting Analysis" status (E2, 0.76–0.80).
- **So faithfulness is reported two ways:** 92% on the 20 answerable questions (target met), and 88% including the three refusals the model wrote.

## 3. A metric artifact: context precision of 0 for a perfect search (M1)

- **M1** ("Which Mitel vulnerabilities have been used in ransomware attacks?") retrieved exactly the 4 expected CVEs and answered correctly, yet scored 0.00 context precision in three separate gradings.
- The judge rates each record on its own against the reference answer. For every record it wrote: *"The context only provides detailed information about one Mitel vulnerability … However, the answer lists four."* With one CVE per chunk, no single record covers a four-CVE answer, so this judge marks each one "not useful".
- **Lesson:** a chunk design (one CVE per chunk) and a metric (usefulness judged per chunk) can interact. Check surprising scores against what actually happened; the plain count of expected CVEs found was 4 of 4.

## 4. Context recall drops when the reference states an absence

- **S3**'s reference answer says "the data has no SQL injection flaws in Verint or Avaya workforce tools". No record can support an absence, so recall was 0.50 even though both expected CVEs were found.
- **F1**'s first reference answer included an instruction ("A good answer states the data date"), which also can't be supported; it was removed.

## 5. Occasional slow answers (latency)

- Over 75 answers (three runs), p50 was 2.4 s and p95 was 4.6 s. One answer took 14.7 s, and one in Phase 8 took 45 s; both were slow Nebius responses. Long list answers also take longer to write.
- One 25-question run's p95 is close to its slowest answer, so it swung from 3.7 s to 7.4 s between runs. Three runs give a steadier number.
- **Next:** in the chat app, show the answer as it is written (streaming), so people see words within about a second even when the full answer is slow.

## 6. Experiments that didn't earn a place

| Experiment | Result | Decision |
|---|---|---|
| MiniLM reranker | Faithfulness and precision a few points higher, but expected CVEs found fell from 90% to 88%, and it adds time. The differences are within the judge's noise. | Off |
| Description-only chunks | Fewest expected CVEs found (85%) and the slowest run | The full card stays |
| Cards without the header line | Similar to full cards on this exam | Header kept: it lets keyword search match CVE numbers and product names (Phase 4's exact-ID result) |
| Checking every search (Phase 7) | No gain, and slower | Only open-ended questions are checked |

## 7. Checker fixes found during evaluation

- A CVE named inside a record (CISA's note that CVE-2024-55550 "can be chained with CVE-2024-41713") was counted as a made-up citation when the answer mentioned it. The citation check now accepts CVEs that are named in the records shown.
