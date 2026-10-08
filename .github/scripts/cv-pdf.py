"""Gera os PDFs do currículo a partir de /cv/pdf/ e /cv/en/pdf/.

Uso: python3 cv-pdf.py <base_url> <pasta_saida> [chrome|chromium]
Ex.: python3 .github/scripts/cv-pdf.py http://127.0.0.1:4000 assets/cv chrome
"""
import sys
from playwright.sync_api import sync_playwright

base, out = sys.argv[1].rstrip("/"), sys.argv[2]
channel = sys.argv[3] if len(sys.argv) > 3 else None

JOBS = [
    ("/cv/pdf/", f"{out}/cv-mikio-nakamaru-pt.pdf", "Página", "de"),
    ("/cv/en/pdf/", f"{out}/cv-mikio-nakamaru-en.pdf", "Page", "of"),
]

FOOTER = """
<div style="width:100%;font-family:Helvetica,Arial,sans-serif;font-size:7px;color:#6b7886;
            padding:0 13mm;display:flex;justify-content:space-between;">
  <span>Mikio Nakamaru</span>
  <span>{page} <span class="pageNumber"></span> {of} <span class="totalPages"></span></span>
</div>"""

with sync_playwright() as p:
    browser = p.chromium.launch(channel=channel) if channel else p.chromium.launch()
    page = browser.new_page()
    for path, dst, word_page, word_of in JOBS:
        page.goto(base + path, wait_until="networkidle")
        page.evaluate("document.fonts.ready")
        page.emulate_media(media="print")
        page.pdf(
            path=dst,
            format="A4",
            print_background=True,
            prefer_css_page_size=True,
            display_header_footer=True,
            header_template="<span></span>",
            footer_template=FOOTER.format(page=word_page, of=word_of),
            tagged=True,
            outline=True,
        )
        print("ok", dst)
    browser.close()
