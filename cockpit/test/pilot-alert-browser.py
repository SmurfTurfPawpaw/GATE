"""Browser regression for the pilot alert's HTML hidden-state contract.

Run with Python Playwright and Chromium on PATH. A selected available case sets
hidden in the renderer (covered by site.test.mjs); the browser must remove the
alert from layout. This rejects CSS display rules overriding HTML hidden.
"""
import asyncio
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import threading
import unittest

from playwright.async_api import async_playwright, expect


class PilotAlertTest(unittest.IsolatedAsyncioTestCase):
    async def test_hidden_alert_is_not_visible(self):
        chromium = shutil.which("chromium")
        self.assertIsNotNone(chromium, "Chromium is required on PATH")
        root = Path(__file__).resolve().parent.parent
        server = ThreadingHTTPServer(
            ("127.0.0.1", 0), partial(SimpleHTTPRequestHandler, directory=str(root))
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(
                    executable_path=chromium, args=["--no-sandbox"]
                )
                try:
                    for width in (390, 1440):
                        page = await browser.new_page(viewport={"width": width, "height": 900})
                        await page.goto(f"http://127.0.0.1:{server.server_port}/")
                        alert = page.locator("#pilot-alert")
                        await expect(alert).to_be_visible()
                        await alert.evaluate("element => { element.hidden = true; }")
                        await expect(alert).to_be_hidden()
                        self.assertEqual(await alert.evaluate("element => element.getClientRects().length"), 0)
                        await alert.evaluate("element => { element.hidden = false; }")
                        await expect(alert).to_be_visible()
                        await page.close()
                finally:
                    await browser.close()
        finally:
            await asyncio.to_thread(server.shutdown)
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
