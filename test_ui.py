import asyncio
from playwright.async_api import async_playwright

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        # Open the file
        await page.goto("file:///app/index.html")
        await page.wait_for_load_state("networkidle")

        # Take a screenshot of the initial state
        await page.screenshot(path="initial_search.png", full_page=True)

        # Simulate typing a query that yields no results
        await page.fill("#globalSearch", "THIS_SHOULD_YIELD_NO_RESULTS_XYZ123")
        await page.wait_for_timeout(500) # wait for js filtering

        # Take a screenshot to verify empty state
        await page.screenshot(path="empty_search.png", full_page=True)

        # Simulate typing a query that yields results
        await page.fill("#globalSearch", "Nmap")
        await page.wait_for_timeout(500) # wait for js filtering

        # Take a screenshot to verify results state
        await page.screenshot(path="results_search.png", full_page=True)

        await browser.close()

asyncio.run(run())
