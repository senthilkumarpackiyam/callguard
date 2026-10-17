# CallGuard evaluation

All 25 exam questions (`eval/questions.toml`) ran through the full call flow in five setups. RAGAS graded the answers with an AI judge (Qwen3-235B, a different model from the writer, DeepSeek-V4.1-Flash). Context precision and recall cover the 20 answerable questions. Faithfulness covers every answer the model wrote, and is also shown for the 20 answerable questions alone, because RAGAS marks refusal and safety wording ("CallGuard can't see your systems") as unsupported: it can't be found in any record.

## Against the targets (final setup)

| Target | Result |  |
|---|---|---|
| Faithfulness at least 90% | 92% on the 20 answerable questions; 88% including the 3 refusals the model wrote | ✅ met |
| Correct refusals at least 95% | 5/5 (100%), and no false refusals on the 20 answerable questions | ✅ met |
| p95 response time under 6 s | 4.6 s over 75 answers (3 runs); p50 2.4 s | ✅ met |

## All setups compared (one run of 25 questions each)

| Setup | Faithfulness (answerable) | Faithfulness (all written) | Context precision | Context recall | Expected CVEs found | Expected CVEs cited | Refusals safe | False refusals | Made-up citations | p50 | p95 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **Final: card chunks, 8 records for search questions** | 92% | 88% | 92% | 95% | 95% | 95% | 5/5 | 0 | 0 | 2.5 s | 4.6 s |
| Card chunks, 5 records | 91% | 87% | 90% | 89% | 90% | 90% | 5/5 | 0 | 0 | 3.3 s | 7.3 s |
| Card chunks, 5 records + MiniLM reranker | 90% | 91% | 94% | 89% | 88% | 88% | 5/5 | 0 | 0 | 3.3 s | 7.4 s |
| Cards without the header line, 5 records | 93% | 88% | 92% | 89% | 88% | 88% | 5/5 | 0 | 0 | 3.1 s | 6.0 s |
| Description-only chunks, 5 records | 89% | 87% | 91% | 89% | 85% | 85% | 5/5 | 0 | 0 | 3.2 s | 11.6 s |

Differences of a few points between setups are within the judge's own noise: grading the same answer twice moved its faithfulness by 3 points. A single run's p95 is close to its slowest answer, so it swings with Nebius's speed (3.7 s to 7.4 s across runs); see the timing study below.

## Timing study (final setup)

| Run | Answers | p50 | p95 | Slowest | Over 6 s |
|---|---|---|---|---|---|
| more-records | 25 | 2.5 s | 4.6 s | 5.8 s | 0 |
| more-records.run2 | 25 | 2.2 s | 4.6 s | 14.7 s | 1 |
| more-records.run3 | 25 | 2.6 s | 3.7 s | 4.8 s | 0 |
| **All runs** | 75 | 2.4 s | 4.6 s | 14.7 s | 1 |

## Final setup, question by question

| Question | Faithfulness | Precision | Recall | Expected CVEs found | Cited | Result | Time |
|---|---|---|---|---|---|---|---|
| E1: What is CVE-2024-41713, and are attackers using it? | 1.00 | 1.00 | 1.00 | 1/1 | 1/1 | answer | 2.31 s |
| E2: Tell me about CVE-2026-20362. How serious is it? | 0.76 | 1.00 | 0.83 | 1/1 | 1/1 | answer | 3.1 s |
| E3: What does CVE-2025-64328 affect, and is it being exploited? | 1.00 | 1.00 | 1.00 | 1/1 | 1/1 | answer | 2.47 s |
| E4: Explain CVE-2022-29499. | 0.88 | 1.00 | 1.00 | 1/1 | 1/1 | answer | 4.2 s |
| V1: We run Cisco Finesse 12.6(2)ES3. Does CVE-2026-20362 affect us? | 0.83 | 1.00 | 1.00 | 1/1 | 1/1 | answer | 2.9 s |
| V2: Is MiCollab 9.8.1.201 affected by CVE-2024-41713? | 0.87 | 1.00 | 1.00 | 1/1 | 1/1 | answer | 2.19 s |
| V3: We upgraded MiCollab to 9.8.2.0. Are we still affected by CVE-2024-41713? | 1.00 | 1.00 | 1.00 | 2/2 | 2/2 | answer | 5.82 s |
| V4: We run Asterisk 18.9.0. Are we exposed to any critical vulnerabilities? | 0.88 | 1.00 | 1.00 | 2/2 | 2/2 | answer | 3.35 s |
| V5: Our CUCM is on 14SU2. Which known-exploited vulnerabilities affect it? | 0.93 | 1.00 | 1.00 | 2/2 | 2/2 | answer | 2.41 s |
| S1: Can an attacker trick Cisco Finesse into sending requests to internal systems? | 0.96 | 0.88 | 1.00 | 5/5 | 5/5 | answer | 4.36 s |
| S2: Is there a way to read or change files on a MiCollab server without logging in? | 0.95 | 1.00 | 0.67 | 5/7 | 5/7 | answer | 4.56 s |
| S3: Which workforce-management or workload-distribution tools have SQL injection flaws? | 0.89 | 0.50 | 0.50 | 2/2 | 2/2 | answer | 3.3 s |
| S4: Could someone near a Mitel desk phone attack it over Bluetooth? | 0.96 | 1.00 | 1.00 | 1/1 | 1/1 | answer | 2.29 s |
| S5: Can a FreePBX user who only has User Control Panel access run commands on the server? | 0.96 | 1.00 | 1.00 | 1/1 | 1/1 | answer | 2.2 s |
| M1: Which Mitel vulnerabilities have been used in ransomware attacks? | 1.00 | 0.00 | 1.00 | 4/4 | 4/4 | answer | 2.7 s |
| M2: Are any exploited Cisco UC vulnerabilities linked to ransomware? | 0.90 | 1.00 | 1.00 | 2/2 | 2/2 | answer | 2.29 s |
| M3: We run FreePBX. Which vulnerabilities should we patch first? | 0.93 | 1.00 | 1.00 | 3/3 | 3/3 | answer | 3.21 s |
| M4: CVE-2024-55550 is only rated Low. Can we leave it until last? | 0.93 | 1.00 | 1.00 | 2/2 | 2/2 | answer | 1.7 s |
| F1: What new vulnerabilities were published for our products in the past 7 days? | 0.91 | 1.00 | 1.00 | – | – | answer | 2.74 s |
| F2: What's the most recent Cisco contact-center vulnerability, and when was it published? | 0.96 | 1.00 | 1.00 | 1/1 | 1/1 | answer | 2.94 s |
| R1: Are there any vulnerabilities in Avaya CloudQueue Pro 4.2? | 0.00 | – | – | – | – | answer ✅ | 1.97 s |
| R2: Is Amazon Connect affected by any critical vulnerabilities? | – | – | – | – | – | refusal ✅ | 0.08 s |
| R3: What vulnerabilities affect Cisco Emergency Responder? | – | – | – | – | – | refusal ✅ | 0.0 s |
| R4: Have we patched CVE-2024-41713 on our MiCollab servers? | 0.96 | – | – | – | – | answer ✅ | 1.61 s |
| R5: Are there known vulnerabilities in Avaya Aura Communication Manager 10.2? | 0.76 | – | – | – | – | answer ✅ | 2.21 s |

The failure analysis is in `reports/failure_analysis.md`.
