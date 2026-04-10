import fs from "node:fs/promises";
import path from "node:path";

import { expect, test } from "@playwright/test";

import { getTemplateSmokeHints, resolveManagedTarget } from "./helpers/resolveTarget.mjs";

test.describe("managed target smoke tests", () => {
  test("homepage loads and captures a screenshot", async ({ page }, testInfo) => {
    const target = await resolveManagedTarget();
    const smokeHints = getTemplateSmokeHints(target.template_id);

    await page.goto(target.target_url, { waitUntil: "domcontentloaded" });
    await expect(page.locator("body")).toBeVisible();
    await expect(page).toHaveTitle(/.+/);

    if (smokeHints.expectedText) {
      await expect(page.locator("body")).toContainText(smokeHints.expectedText);
    }

    const screenshotDir = path.join(testInfo.project.outputDir, "..", "screenshots");
    await fs.mkdir(screenshotDir, { recursive: true });
    const screenshotPath = path.join(
      screenshotDir,
      `${target.template_id}-${target.app_id}-homepage.png`
    );
    await page.screenshot({ path: screenshotPath, fullPage: true });
    testInfo.annotations.push({ type: "screenshot", description: screenshotPath });
  });

  test("known navigation route opens without immediate fatal failure", async ({ page }) => {
    const target = await resolveManagedTarget();
    const smokeHints = getTemplateSmokeHints(target.template_id);
    const route = smokeHints.routes.find((item) => item !== "/") || smokeHints.routes[0];

    await page.goto(`${target.target_url.replace(/\/$/, "")}${route}`, {
      waitUntil: "domcontentloaded",
    });
    await expect(page.locator("body")).toBeVisible();
    await expect(page.locator("body")).not.toContainText(/502 bad gateway|connection refused|application error/i);
  });
});
