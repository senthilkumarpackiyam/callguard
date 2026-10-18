# CallGuard demo video: script and recording guide

A 5-minute video that shows each type of question, a refusal and a fresh CVE, then how it works and how well it scored. All the questions were tested on 17 October 2026. Each answered correctly in 0.1 to 3.2 seconds.

## Before you record (about 10 minutes)

1. **Start CallGuard.**
   - In the VSCode terminal, run `uv run scripts/serve.py`. Skip this if it's already running.
   - Open http://localhost:8000 in Chrome.
2. **Warm it up.** Ask any question once. After a restart, the first answer takes a few extra seconds while CallGuard loads its search index.
3. **Open three tabs, left to right:**
   1. CallGuard
   2. your GitHub repository's README, scrolled to "How it works"
   3. the Google Doc (optional)
4. **Tidy the screen.**
   - Close other apps.
   - Turn on Do Not Disturb (Control Center, then Focus).
   - Hide Chrome's bookmarks bar (Cmd+Shift+B).
   - If the text looks small, zoom the page to 110% (Cmd and +).
5. **Keep this script open** on a second screen or on paper, and copy each question from it when you need it.
6. **Practice once with a timer.** Aim for 4:45, so you have a little slack.

## How to record on a Mac

1. Press **Cmd+Shift+5**.
2. Choose **Record Entire Screen**.
3. Under **Options**, choose your Mac's microphone.
4. Click **Record**.
5. To stop, click the stop button in the menu bar at the top right.

The video is saved on your Desktop. To cut the start or the end, open it in QuickTime Player and use Edit, then Trim.

## The script

Replace [your name] with your name. The narration is a guide: say it in your own words.

**While an answer is appearing, keep talking about what's on the screen. Don't wait in silence.**

### 0:00–0:25 Introduction

**Show:** the top of the CallGuard home page.

**Say:** "Hi, I'm [your name]. I've spent about 20 years in contact centers. When a security headline breaks, every customer asks the same thing: are we exposed? Answering means digging through NVD, CISA's list of exploited flaws and vendor advisories, product by product and version by version. CallGuard answers in seconds, only from that data, and it cites its sources."

### 0:25–0:55 The website

**Show:**
1. Point at the "Data as of" badge.
2. Scroll to "Latest vulnerabilities".
3. Click the top card, the newest CVE. Let the details panel open, then close it.

**Say:** "Everything comes from three public sources: NVD, CISA's Known Exploited Vulnerabilities catalog, and FIRST's exploit forecasts. It refreshes every two hours, and the badge shows how fresh the data is. On the left are the newest CVEs for 24 contact-center products. Clicking one shows its severity, whether attackers are using it, the forecast, the affected versions and the fix."

### 0:55–1:20 Question by CVE number

**Paste:**
```
What is CVE-2024-41713, and are attackers using it?
```

**Say:** "First, a question by CVE number. In about two seconds it answers. Yes, attackers are using it, and ransomware groups too. Every claim cites its CVE, the sources link to NVD, and the last line says how fresh the data is."

### 1:20–1:50 Question by version

**Paste:**
```
We upgraded MiCollab to 9.8.2.0. Are we still affected by CVE-2024-41713?
```

**Say:** "Version questions are where people slip up, so CallGuard checks versions in code, not with the AI. The upgrade fixed this CVE, but other MiCollab flaws still cover 9.8.2.0. It even flags where NVD and CISA disagree, and says which version to patch to."

### 1:50–2:15 Question by description

**Paste:**
```
Could someone near a Mitel desk phone attack it over Bluetooth?
```

**Say:** "You don't need a CVE number. Describe the problem in plain words. It found the Bluetooth pairing flaw, and it explains why the other records it looked at don't match."

### 2:15–2:45 Multi-step: what to patch first

**Click** the suggestion "We run FreePBX. Which vulnerabilities should we patch first?" If the suggestions have scrolled away, paste it instead:
```
We run FreePBX. Which vulnerabilities should we patch first?
```

**Say:** "What do we patch first? CallGuard ranks by risk, not just severity. Flaws attackers are known to use come first, then the highest exploit forecast, then severity. It also reminds me that it can't see my systems, so I should check my own versions."

### 2:45–3:05 A fresh CVE

**Paste:**
```
What's the most recent Cisco contact-center vulnerability, and when was it published?
```

**Say:** "Freshness: here's the newest Cisco contact-center CVE and its publication date. It also points out that newest isn't the same as most urgent."

### 3:05–3:30 A refusal

**Paste:**
```
Are there any vulnerabilities in Avaya CloudQueue Pro 4.2?
```

**Say:** "Now a trick question: Avaya CloudQueue Pro doesn't exist. When I tested AI models, one confidently invented two critical vulnerabilities for it. CallGuard says it doesn't cover that product, refuses to borrow answers from other products, and reminds me that 'no CVE found' never means safe."

If you have time, also paste this for an instant answer about a cloud product:
```
Is Amazon Connect affected by any critical vulnerabilities?
```

### 3:30–3:55 Downloads and email

**Show:**
1. Under the last good answer, click **PDF**.
2. In the list, tick **Exploited only**, then click **Excel**.
3. Click **Email**, type two addresses separated by a comma, and click **Open in email app**.

**Say:** "Answers and lists download as PDF, Excel or CSV, or go to the whole team as an email draft."

### 3:55–4:35 How it works and how well it scored

**Show:** the GitHub tab. First the "How it works" diagram, then scroll up to "Results".

**Say:** "Under the hood, the data refreshes every two hours, and every CVE is indexed by meaning and by keywords. For each question, a LangGraph flow understands the question, finds the records, checks them, then writes a cited answer or refuses safely. I wrote a 25-question exam before building it. The results: faithfulness 92%, every refusal correct, no made-up citations, and 95% of answers in under 4.6 seconds."

### 4:35–5:00 Close

**Show:** back to the CallGuard home page.

**Say:** "My biggest lesson: let code decide what code can decide, like versions, patch order and refusals, and let the AI only write from the records. Thanks for watching."

## After recording

1. **Watch it once.** Check the sound and that it's under 5 minutes.
2. **Upload it** the way your course asks: for example, to YouTube as Unlisted, or to Google Drive shared as "Anyone with the link".
3. **Add the link:** paste it into the Google Doc's "Demo video" line, and send it to Claude to add to the README.
