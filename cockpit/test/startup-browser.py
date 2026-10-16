"""Cold-start regression: run with Python Playwright and Chromium on PATH.

The local-companion contract promises usable private conversation independently
of the public preview. Initial state must reach the renderer before any poll.
"""
import asyncio
import json
import shutil
import subprocess
import unittest

from playwright.async_api import async_playwright, expect


class StartupTest(unittest.IsolatedAsyncioTestCase):
    async def test_private_controls_before_first_poll(self):
        chromium = shutil.which("chromium")
        if not chromium:
            self.fail("Chromium is required on PATH for this browser regression")
        server = subprocess.Popen(
            ["node", "--input-type=module", "-e", """
import { startCompanionServer } from './cockpit/companion/server.mjs';
import { ActivityStore } from './cockpit/companion/activity.mjs';
const server = await startCompanionServer({ adapter: {
  activityStore: new ActivityStore(), sendMessage() {}, answerQuestion() {},
  privateState: () => ({
    apiVersion: 'gate.local-companion-state/v1', sessionRevision: 1,
    stateRevision: 1, observedAt: new Date().toISOString(), connected: true,
    turn: 'idle', tokens: null, pendingQuestions: [],
    conversation: [{role: 'codex', text: 'Ready immediately', at: new Date().toISOString()}]
  })
}});
console.log(JSON.stringify(server.url));
process.on('SIGTERM', async () => { await server.close(); process.exit(); });
"""], stdout=subprocess.PIPE, text=True,
        )
        try:
            url = json.loads(await asyncio.to_thread(server.stdout.readline))
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(
                    executable_path=chromium, args=["--no-sandbox"]
                )
                try:
                    # Both ordinary cold loads and a delayed renderer dependency
                    # must consume the first state response, without five-second recovery.
                    for delayed in (False, True):
                        page = await browser.new_page()
                        errors, states = [], []
                        page.on("pageerror", lambda error: errors.append(str(error)))
                        page.on("response", lambda response: states.append(response.url)
                                if response.url.endswith("/api/private-state") else None)
                        if delayed:
                            async def delay_model(route):
                                await asyncio.sleep(1)
                                await route.continue_()
                            await page.route("**/assets/model.js", delay_model)
                        await page.goto(url, wait_until="domcontentloaded")
                        await expect(page.locator("#message-input")).to_be_enabled(timeout=1000)
                        self.assertIn("Ready immediately", await page.locator("#conversation").inner_text())
                        self.assertEqual(len(states), 1)
                        self.assertEqual(errors, [])
                        await page.locator("#message-input").fill("New private message")
                        self.assertTrue(await page.locator("#message-send").is_enabled())
                        await page.close()
                finally:
                    await browser.close()
        finally:
            server.terminate()
            await asyncio.to_thread(server.wait, 10)
            server.stdout.close()


if __name__ == "__main__":
    unittest.main()
