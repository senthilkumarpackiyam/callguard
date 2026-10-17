"""Phase 10: use the website like a visitor would, in the installed Chrome, and check that everything works.

Covers the list, the details panel, the chat (one real question, so one AI answer), the answer PDF, the email
window and the phone layout. It also forces the timing that once hid a finished answer's buttons.

Start the website first (uv run scripts/serve.py), then run this in its own throwaway environment:

  uv run --no-project --with playwright python scripts/check_website.py [folder for screenshots]
"""

import json
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

URL = "http://127.0.0.1:8000/"
out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(tempfile.mkdtemp(prefix="callguard-check-"))
out.mkdir(parents=True, exist_ok=True)
checks, errors = [], []


def sse(name, payload):
    return f"event: {name}\ndata: {json.dumps(payload)}\n\n"


with sync_playwright() as p:
    browser = p.chromium.launch(channel="chrome", headless=True)
    page = browser.new_page(viewport={"width": 1366, "height": 900}, accept_downloads=True)
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(URL)
    page.wait_for_selector(".cve-item")
    checks.append(("list loaded", page.locator(".cve-item").count() > 0))

    # 1. The last words and "done" arriving together, before the next redraw (this once hid the answer's buttons)
    fake = (sse("status", {"text": "Searching the records…"}) + sse("token", {"text": "Half-written [CVE-2024-41713]"}) +
            sse("done", {"text": "Full answer [CVE-2024-41713].\n\nSources: CVE-2024-41713\n\n_Data as of test._",
                         "kind": "answer", "reason": "", "cited": ["CVE-2024-41713"], "route": "search", "seconds": 1.0}))
    page.route("**/api/ask", lambda route: route.fulfill(status=200, content_type="text/event-stream", body=fake))
    page.fill("#question", "timing test question")
    page.click("#send")
    page.wait_for_timeout(400)  # many screen redraws: a stale one would have run by now
    bubble = page.locator(".msg.bot .bubble").last
    checks.append(("finished answer survives a late redraw",
                   bubble.locator(".answer-tools").count() == 1 and "Data as of test" in bubble.inner_text()))
    page.unroute("**/api/ask")

    # 2. A real question through the chat box
    page.fill("#question", "Is there an actively exploited vulnerability in Mitel MiCollab?")
    page.click("#send")
    page.wait_for_function("document.querySelectorAll('.answer-tools').length >= 2", timeout=90_000)
    answer = page.locator(".msg.bot .bubble").last
    checks.append(("answer has CVE links", answer.locator(".cve-link").count() > 0))
    checks.append(("answer has data-as-of", "Data as of" in answer.inner_text()))
    page.locator("#ask").screenshot(path=str(out / "chat.png"))

    # 3. A CVE link inside the answer opens the details panel
    answer.locator(".cve-link").first.click()
    page.wait_for_selector(".drawer.open")
    checks.append(("CVE link opens details", "CVE-" in page.inner_text("#drawer-title")))
    page.keyboard.press("Escape")

    # 4. The answer as a PDF
    with page.expect_download() as download:
        answer.locator('[data-act="pdf"]').click()
    download.value.save_as(out / "answer.pdf")
    checks.append(("answer PDF downloads", (out / "answer.pdf").read_bytes()[:4] == b"%PDF"))

    # 5. Email window: a wrong address is caught; good addresses build one draft for everyone
    answer.locator('[data-act="email"]').click()
    page.wait_for_selector("#email-modal:not([hidden])")
    page.fill("#email-to", "alice@example.com, not-an-address")
    page.click("#email-open")
    checks.append(("bad address caught", page.is_visible("#email-error")))
    page.screenshot(path=str(out / "email.png"))
    mailto = page.evaluate("""() => mailtoLink(["alice@example.com", "bob@example.org"],
        document.getElementById("email-subject").value, document.getElementById("email-body").value)""")
    checks.append(("draft has both recipients", mailto.startswith("mailto:alice%40example.com,bob%40example.org?subject=")))
    checks.append(("draft stays short enough", len(mailto) < 8000))
    page.click("#email-cancel")

    # 6. Phone-sized screen: the list flows with the page, 10 at a time, and the filters aren't cut off
    phone = browser.new_page(viewport={"width": 390, "height": 844}, device_scale_factor=2)
    phone.on("pageerror", lambda e: errors.append(str(e)))
    phone.goto(URL)
    phone.wait_for_selector(".cve-item")
    checks.append(("phone shows 10 at a time", phone.locator(".cve-item").count() == 10))
    fits = phone.evaluate("""[...document.querySelectorAll('.filters select')].map(s => {
        const ctx = document.createElement('canvas').getContext('2d'), cs = getComputedStyle(s);
        ctx.font = `${cs.fontWeight} ${cs.fontSize} ${cs.fontFamily}`;
        const need = ctx.measureText(s.options[s.selectedIndex].text).width
                     + parseFloat(cs.paddingLeft) + parseFloat(cs.paddingRight) + 18;  // 18px for the arrow
        return need <= s.clientWidth; })""")
    checks.append(("phone filters not cut off", all(fits)))
    phone.screenshot(path=str(out / "phone.png"))
    browser.close()

checks.append(("no script errors", not errors))
for name, ok in checks:
    print(("PASS " if ok else "FAIL ") + name)
for e in errors:
    print("  script error:", e[:200])
print(f"Screenshots and PDF: {out}")
sys.exit(0 if all(ok for _, ok in checks) else 1)
