import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";

import { chromium } from "@playwright/test";

function assertLocalHttpUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Managed target URL is invalid: ${url}`);
  }

  const isLocalHost = ["localhost", "127.0.0.1"].includes(parsed.hostname);
  if (!isLocalHost) {
    throw new Error(`Refusing browser automation against non-local host "${parsed.hostname}".`);
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error(`Unsupported target protocol "${parsed.protocol}".`);
  }

  return parsed.toString();
}

async function runScenario({ targetUrl, templateId, scenarioId, outputDir, runId }) {
  const safeUrl = assertLocalHttpUrl(targetUrl);
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  const result = {
    scenario_id: scenarioId,
    url: safeUrl,
    ok: false,
    confirmed_vulnerability: false,
    status_code: 0,
    response_size: 0,
    screenshot_path: null,
    current_url: safeUrl,
    summary: "",
  };

  try {
    if (scenarioId === "browser_homepage_smoke") {
      const response = await page.goto(safeUrl, { waitUntil: "domcontentloaded", timeout: 20_000 });
      await page.waitForLoadState("networkidle", { timeout: 10_000 }).catch(() => {});
      const content = await page.content();
      await fs.mkdir(outputDir, { recursive: true });
      const screenshotPath = path.join(outputDir, `${templateId}-${runId}-homepage.png`);
      await page.screenshot({ path: screenshotPath, fullPage: true });

      result.ok = true;
      result.status_code = response?.status() || 200;
      result.response_size = content.length;
      result.screenshot_path = screenshotPath;
      result.current_url = page.url();
      result.summary = `Loaded homepage and captured screenshot at ${screenshotPath}.`;
      return result;
    }

    if (scenarioId === "browser_login_navigation") {
      await page.goto(safeUrl, { waitUntil: "domcontentloaded", timeout: 20_000 });
      await page.waitForLoadState("networkidle", { timeout: 10_000 }).catch(() => {});

      const candidateLocators = [
        page.getByRole("link", { name: /login|sign in|account/i }).first(),
        page.getByRole("button", { name: /login|sign in|account/i }).first(),
        page.locator('a[href*="login"]').first(),
        page.locator('a[href*="sign"]').first(),
      ];

      let navigated = false;
      for (const locator of candidateLocators) {
        if ((await locator.count()) > 0 && (await locator.isVisible().catch(() => false))) {
          await locator.click({ timeout: 5_000 }).catch(() => {});
          navigated = true;
          break;
        }
      }

      if (!navigated) {
        const fallbackPath =
          String(templateId).toLowerCase() === "dvwa"
            ? "/login.php"
            : String(templateId).toLowerCase() === "juice_shop"
              ? "/#/login"
              : "/";
        await page.goto(`${safeUrl.replace(/\/$/, "")}${fallbackPath}`, {
          waitUntil: "domcontentloaded",
          timeout: 20_000,
        });
      }

      await page.waitForLoadState("networkidle", { timeout: 10_000 }).catch(() => {});
      const content = await page.content();
      await fs.mkdir(outputDir, { recursive: true });
      const screenshotPath = path.join(outputDir, `${templateId}-${runId}-login-navigation.png`);
      await page.screenshot({ path: screenshotPath, fullPage: true });

      result.ok = true;
      result.status_code = 200;
      result.response_size = content.length;
      result.screenshot_path = screenshotPath;
      result.current_url = page.url();
      result.summary = `Opened login/navigation view and captured screenshot at ${screenshotPath}.`;
      return result;
    }

    if (scenarioId === "browser_login_bruteforce") {
      await page.goto(safeUrl, { waitUntil: "domcontentloaded", timeout: 20_000 });
      await page.waitForLoadState("networkidle", { timeout: 10_000 }).catch(() => {});

      const candidateLocators = [
        page.getByRole("link", { name: /login|sign in|account/i }).first(),
        page.getByRole("button", { name: /login|sign in|account/i }).first(),
        page.locator('a[href*="login"]').first(),
        page.locator('a[href*="sign"]').first(),
      ];

      let navigated = false;
      for (const locator of candidateLocators) {
        if ((await locator.count()) > 0 && (await locator.isVisible().catch(() => false))) {
          await locator.click({ timeout: 5_000 }).catch(() => {});
          navigated = true;
          break;
        }
      }

      if (!navigated) {
        const fallbackPath =
          String(templateId).toLowerCase() === "dvwa"
            ? "/login.php"
            : String(templateId).toLowerCase() === "juice_shop"
              ? "/#/login"
              : "/";
        await page.goto(`${safeUrl.replace(/\/$/, "")}${fallbackPath}`, {
          waitUntil: "domcontentloaded",
          timeout: 20_000,
        });
      }

      await page.waitForLoadState("networkidle", { timeout: 10_000 }).catch(() => {});

      const usernameField = page
        .locator('input[type="email"], input[name*="user" i], input[name*="email" i], input[id*="user" i], input[id*="email" i]')
        .first();
      const passwordField = page.locator('input[type="password"]').first();

      const usernameVisible = (await usernameField.count()) > 0 && (await usernameField.isVisible().catch(() => false));
      const passwordVisible = (await passwordField.count()) > 0 && (await passwordField.isVisible().catch(() => false));

      if (!usernameVisible || !passwordVisible) {
        throw new Error("No visible login form was found for bounded browser brute-force simulation.");
      }

      const submitButton = page
        .locator('button[type="submit"], input[type="submit"], button:has-text("Login"), button:has-text("Sign in")')
        .first();

      const attempts = [
        { username: "admin", password: "guess1" },
        { username: "admin", password: "guess2" },
          { username: "admin", password: "guess1" },
        { username: "admin", password: "guess2" },
          { username: "admin", password: "guess1" },
        { username: "admin", password: "guess2" },
          { username: "admin", password: "guess1" },
        { username: "admin", password: "guess2" },
          { username: "admin", password: "guess1" },
        { username: "admin", password: "guess2" },
        { username: "admin", password: "password" },
      ];

      for (const attempt of attempts) {
        await usernameField.fill(attempt.username);
        await passwordField.fill(attempt.password);
        if ((await submitButton.count()) > 0 && (await submitButton.isVisible().catch(() => false))) {
          await submitButton.click({ timeout: 5_000 }).catch(() => {});
        } else {
          await passwordField.press("Enter").catch(() => {});
        }
        await page.waitForLoadState("networkidle", { timeout: 7_000 }).catch(() => {});
      }

      const content = await page.content();
      await fs.mkdir(outputDir, { recursive: true });
      const screenshotPath = path.join(outputDir, `${templateId}-${runId}-login-bruteforce.png`);
      await page.screenshot({ path: screenshotPath, fullPage: true });

      const currentUrl = page.url();
      const normalizedContent = content.toLowerCase();
      const confirmedVulnerability =
        !/login|sign[\s-]?in/.test(currentUrl.toLowerCase()) ||
        /logout|log out|sign out/.test(normalizedContent);

      result.ok = true;
      result.confirmed_vulnerability = confirmedVulnerability;
      result.status_code = 200;
      result.response_size = content.length;
      result.screenshot_path = screenshotPath;
      result.current_url = currentUrl;
      result.summary = `Attempted a bounded browser login brute-force sequence and captured screenshot at ${screenshotPath}.`;
      return result;
    }

    throw new Error(`Unsupported browser scenario "${scenarioId}".`);
  } finally {
    await browser.close();
  }
}

async function main() {
  const targetUrl = process.env.CYBERBOX_TARGET_URL;
  const templateId = process.env.CYBERBOX_TARGET_TEMPLATE || "unknown";
  const scenarioId = process.env.CYBERBOX_SCENARIO_ID;
  const runId = process.env.CYBERBOX_RUN_ID || "manual";
  const outputDir =
    process.env.CYBERBOX_OUTPUT_DIR ||
    path.resolve(process.cwd(), "test-results", "red-agent");

  if (!targetUrl || !scenarioId) {
    throw new Error("CYBERBOX_TARGET_URL and CYBERBOX_SCENARIO_ID are required.");
  }

  const result = await runScenario({
    targetUrl,
    templateId,
    scenarioId,
    outputDir,
    runId,
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
});
