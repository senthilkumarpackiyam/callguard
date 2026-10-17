# Retrieval scores on the exam

18 exam questions that have known CVEs (exact number, version, meaning, multi-step). For each, did the expected CVEs appear in the top 5? Freshness and should-refuse questions are scored in Phase 9.

Search texts were embedded once up front (1 s in total, mostly Nebius calls), so the times below are search and reranking only.

| Setup | Found at least one | Found all | Share of expected CVEs found | Average time |
|---|---|---|---|---|
| Meaning only | 10/18 | 6/18 | 44% | 6 ms |
| Keywords only | 15/18 | 10/18 | 68% | 10 ms |
| Hybrid (RRF) | 16/18 | 11/18 | 74% | 20 ms |
| Smart, no reranker | 18/18 | 16/18 | 96% | 31 ms |
| Smart + MiniLM reranker | 18/18 | 16/18 | 96% | 1011 ms |
| Smart + BGE reranker | 18/18 | 16/18 | 96% | 8579 ms |

## By question type: share of expected CVEs found

| Setup | exact-id | version | meaning | multi-step |
|---|---|---|---|---|
| Meaning only | 25% | 60% | 59% | 25% |
| Keywords only | 100% | 50% | 71% | 56% |
| Hybrid (RRF) | 100% | 60% | 75% | 62% |
| Smart, no reranker | 100% | 100% | 86% | 100% |
| Smart + MiniLM reranker | 100% | 100% | 86% | 100% |
| Smart + BGE reranker | 100% | 100% | 85% | 100% |

## Question by question: expected CVEs found in the top 5

| Question | Expected | Meaning only | Keywords only | Hybrid (RRF) | Smart, no reranker | Smart + MiniLM reranker | Smart + BGE reranker |
|---|---|---|---|---|---|---|---|
| E1: What is CVE-2024-41713, and are attackers using it? | 1 | 0 | 1 | 1 | 1 | 1 | 1 |
| E2: Tell me about CVE-2026-20362. How serious is it? | 1 | 0 | 1 | 1 | 1 | 1 | 1 |
| E3: What does CVE-2025-64328 affect, and is it being exploited? | 1 | 0 | 1 | 1 | 1 | 1 | 1 |
| E4: Explain CVE-2022-29499. | 1 | 1 | 1 | 1 | 1 | 1 | 1 |
| V1: We run Cisco Finesse 12.6(2)ES3. Does CVE-2026-20362 affect us? | 1 | 1 | 1 | 1 | 1 | 1 | 1 |
| V2: Is MiCollab 9.8.1.201 affected by CVE-2024-41713? | 1 | 1 | 1 | 1 | 1 | 1 | 1 |
| V3: We upgraded MiCollab to 9.8.2.0. Are we still affected by CVE-2024-41713? | 2 | 1 | 1 | 1 | 2 | 2 | 2 |
| V4: We run Asterisk 18.9.0. Are we exposed to any critical vulnerabilities? | 2 | 0 | 0 | 0 | 2 | 2 | 2 |
| V5: Our CUCM is on 14SU2. Which known-exploited vulnerabilities affect it? | 2 | 1 | 0 | 1 | 2 | 2 | 2 |
| S1: Can an attacker trick Cisco Finesse into sending requests to internal systems? | 5 | 4 | 2 | 2 | 4 | 4 | 3 |
| S2: Is there a way to read or change files on a MiCollab server without logging in? | 6 | 1 | 1 | 2 | 3 | 3 | 4 |
| S3: Which workforce-management or workload-distribution tools have SQL injection flaws? | 2 | 0 | 2 | 2 | 2 | 2 | 2 |
| S4: Could someone near a Mitel desk phone attack it over Bluetooth? | 1 | 1 | 1 | 1 | 1 | 1 | 1 |
| S5: Can a FreePBX user who only has User Control Panel access run commands on the server? | 1 | 1 | 1 | 1 | 1 | 1 | 1 |
| M1: Which Mitel vulnerabilities have been used in ransomware attacks? | 4 | 0 | 3 | 2 | 4 | 4 | 4 |
| M2: Are any exploited Cisco UC vulnerabilities linked to ransomware? | 2 | 2 | 1 | 2 | 2 | 2 | 2 |
| M3: We run FreePBX. Which vulnerabilities should we patch first? | 3 | 0 | 0 | 0 | 3 | 3 | 3 |
| M4: CVE-2024-55550 is only rated Low. Can we leave it until last? | 2 | 0 | 2 | 2 | 2 | 2 | 2 |
