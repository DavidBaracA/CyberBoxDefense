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

async function navigateToLoginSurface(page, safeUrl) {
  const candidateLocators = [
    page.getByRole("link", { name: /login|sign in|account/i }).first(),
    page.getByRole("button", { name: /login|sign in|account/i }).first(),
    page.locator('a[href*="login"]').first(),
    page.locator('a[href*="sign"]').first(),
  ];

  for (const locator of candidateLocators) {
    if ((await locator.count()) > 0 && (await locator.isVisible().catch(() => false))) {
      await locator.click({ timeout: 5_000 }).catch(() => {});
      await page.waitForLoadState("networkidle", { timeout: 10_000 }).catch(() => {});
      return true;
    }
  }

  await page.goto(safeUrl, { waitUntil: "domcontentloaded", timeout: 20_000 });
  await page.waitForLoadState("networkidle", { timeout: 10_000 }).catch(() => {});
  return false;
}

const BOUNDED_LOGIN_ATTEMPTS = [
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

async function runScenario({ targetUrl, targetPageUrl, templateId, scenarioId, outputDir, runId }) {
  const safeUrl = assertLocalHttpUrl(targetUrl);
  const safePageUrl = assertLocalHttpUrl(targetPageUrl || targetUrl);
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  const result = {
    scenario_id: scenarioId,
    url: safePageUrl,
    ok: false,
    confirmed_vulnerability: false,
    status_code: 0,
    response_size: 0,
    screenshot_path: null,
    current_url: safePageUrl,
    summary: "",
  };

  try {
    const response = await page.goto(safePageUrl, { waitUntil: "domcontentloaded", timeout: 20_000 });
    await page.waitForLoadState("networkidle", { timeout: 10_000 }).catch(() => {});

    if (scenarioId === "brute_force_login") {
      await navigateToLoginSurface(page, safePageUrl);
      const usernameField = page
        .locator('input[type="email"], input[name*="user" i], input[name*="email" i], input[id*="user" i], input[id*="email" i]')
        .first();
      const passwordField = page.locator('input[type="password"]').first();
      const loginVisible =
        (await usernameField.count()) > 0 &&
        (await passwordField.count()) > 0 &&
        (await passwordField.isVisible().catch(() => false));

      if (loginVisible) {
        const submitButton = page
          .locator('button[type="submit"], input[type="submit"], button:has-text("Login"), button:has-text("Sign in")')
          .first();

        for (const attempt of BOUNDED_LOGIN_ATTEMPTS) {
          await usernameField.fill(attempt.username);
          await passwordField.fill(attempt.password);
          if ((await submitButton.count()) > 0 && (await submitButton.isVisible().catch(() => false))) {
            await submitButton.click({ timeout: 5_000 }).catch(() => {});
          } else {
            await passwordField.press("Enter").catch(() => {});
          }
          await page.waitForLoadState("networkidle", { timeout: 7_000 }).catch(() => {});
        }
      }

      await fs.mkdir(outputDir, { recursive: true });
      const screenshotPath = path.join(outputDir, `${templateId}-${runId}-brute-force-login.png`);
      await page.screenshot({ path: screenshotPath, fullPage: true });

      const content = await page.content();
      const currentUrl = page.url();
      const normalizedContent = content.toLowerCase();
      const confirmedVulnerability =
        loginVisible &&
        (!/login|sign[\s-]?in/.test(currentUrl.toLowerCase()) ||
          /logout|log out|sign out/.test(normalizedContent));

      result.ok = true;
      result.confirmed_vulnerability = confirmedVulnerability;
      result.status_code = response?.status() || 200;
      result.response_size = content.length;
      result.screenshot_path = screenshotPath;
      result.current_url = currentUrl;
      result.summary = loginVisible
        ? `Attempted ${BOUNDED_LOGIN_ATTEMPTS.length} allowlisted login submissions and captured bounded evidence at ${screenshotPath}.`
        : `Captured evidence for login-surface analysis at ${screenshotPath}; no clear login form was visible.`;
      return result;
    }

    if (scenarioId === "sql_injection_probe" || scenarioId === "reflected_xss_probe") {
      const candidateInput = page
        .locator('input[type="search"], input[name*="search" i], input[name*="query" i], input[type="text"], textarea')
        .first();
      const candidateVisible =
        (await candidateInput.count()) > 0 && (await candidateInput.isVisible().catch(() => false));
      if (candidateVisible) {
        await candidateInput.fill("cyberbox-demo");
      }

      await fs.mkdir(outputDir, { recursive: true });
      const screenshotPath = path.join(outputDir, `${templateId}-${runId}-${scenarioId}.png`);
      await page.screenshot({ path: screenshotPath, fullPage: true });

      const content = await page.content();
      result.ok = true;
      result.status_code = response?.status() || 200;
      result.response_size = content.length;
      result.screenshot_path = screenshotPath;
      result.current_url = page.url();
      result.summary = candidateVisible
        ? `Located a query-like input and captured bounded evidence for ${scenarioId} at ${screenshotPath}.`
        : `Captured bounded reconnaissance evidence for ${scenarioId} at ${screenshotPath}.`;
      return result;
    }

    if (scenarioId === "file_upload_probe") {
      const fileInput = page.locator('input[type="file"]').first();
      const uploadVisible =
        (await fileInput.count()) > 0 && (await fileInput.isVisible().catch(() => false));

      await fs.mkdir(outputDir, { recursive: true });
      const screenshotPath = path.join(outputDir, `${templateId}-${runId}-file-upload-probe.png`);
      await page.screenshot({ path: screenshotPath, fullPage: true });

      const content = await page.content();
      result.ok = true;
      result.status_code = response?.status() || 200;
      result.response_size = content.length;
      result.screenshot_path = screenshotPath;
      result.current_url = page.url();
      result.summary = uploadVisible
        ? `Detected a file input and captured bounded upload-surface evidence at ${screenshotPath}.`
        : `Captured bounded reconnaissance evidence for upload-surface analysis at ${screenshotPath}.`;
      return result;
    }

    if (scenarioId === "open_redirect_probe") {
      const redirectLink = page.locator('a[href*="redirect"], a[href*="return"], a[href*="next="], a[href*="url="]').first();
      const redirectVisible =
        (await redirectLink.count()) > 0 && (await redirectLink.isVisible().catch(() => false));

      await fs.mkdir(outputDir, { recursive: true });
      const screenshotPath = path.join(outputDir, `${templateId}-${runId}-open-redirect-probe.png`);
      await page.screenshot({ path: screenshotPath, fullPage: true });

      const content = await page.content();
      result.ok = true;
      result.status_code = response?.status() || 200;
      result.response_size = content.length;
      result.screenshot_path = screenshotPath;
      result.current_url = page.url();
      result.summary = redirectVisible
        ? `Detected a redirect-like navigation signal and captured bounded evidence at ${screenshotPath}.`
        : `Captured bounded reconnaissance evidence for redirect-surface analysis at ${screenshotPath}.`;
      return result;
    }

    throw new Error(`Unsupported browser scenario "${scenarioId}".`);
  } finally {
    await browser.close();
  }
}

async function main() {
  const targetUrl = process.env.CYBERBOX_TARGET_URL;
  const targetPageUrl = process.env.CYBERBOX_TARGET_PAGE_URL || targetUrl;
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
    targetPageUrl,
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
