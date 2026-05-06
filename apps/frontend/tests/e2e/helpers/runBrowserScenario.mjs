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

function resolveLocalHttpUrl(url, baseUrl) {
  const safeBaseUrl = assertLocalHttpUrl(baseUrl);
  let parsed;
  try {
    parsed = new URL(url || safeBaseUrl, safeBaseUrl);
  } catch {
    throw new Error(`Managed target URL is invalid: ${url}`);
  }

  return assertLocalHttpUrl(parsed.toString());
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

const SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1"];
const SQLI_ROUTE_CANDIDATES = [
  { path: "/search", param: "q" },
  { path: "/search", param: "query" },
  { path: "/api/search", param: "q" },
  { path: "/api/search", param: "query" },
];
const XSS_PAYLOADS = [
  '"><iframe src="javascript:alert(\'cyberbox-xss\')">',
  '<img src=x data-cyberbox-xss="confirmed" onerror="window.__cyberboxXssConfirmed=1">',
  '<svg data-cyberbox-xss="confirmed" onload="window.__cyberboxXssConfirmed=1"></svg>',
  '<iframe src="javascript:alert(\'cyberbox-xss\')"></iframe>',
];
const XSS_ROUTE_CANDIDATES = [
  { path: "/search", param: "q" },
  { path: "/search", param: "query" },
  { path: "/api/search", param: "q" },
  { path: "/api/search", param: "query" },
];
const SQL_ERROR_PATTERNS = [
  /sql syntax/i,
  /mysql/i,
  /mariadb/i,
  /sqlite/i,
  /postgres/i,
  /odbc/i,
  /syntax error/i,
  /unclosed quotation/i,
  /quoted string not properly terminated/i,
  /simulated backend exception/i,
];
const SEARCH_REVEAL_SELECTORS = [
  'button[aria-label*="search" i]',
  'a[aria-label*="search" i]',
  '[role="button"][aria-label*="search" i]',
  'button:has-text("Search")',
  'a:has-text("Search")',
  'mat-icon:has-text("search")',
  '.mat-icon:has-text("search")',
];

function hasSqlErrorSignal(content) {
  return SQL_ERROR_PATTERNS.some((pattern) => pattern.test(content || ""));
}

function hasSqlEvidence(baseline, probe) {
  const baselineStatus = baseline?.status || 0;
  const probeStatus = probe?.status || 0;
  return (
    Boolean(probe?.sql_error) ||
    (baselineStatus > 0 && baselineStatus < 500 && probeStatus >= 500)
  );
}

async function captureResponseSnapshot(page, response) {
  const content = await page.content().catch(() => "");
  return {
    status: response?.status() || 0,
    url: page.url(),
    response_size: content.length,
    sql_error: hasSqlErrorSignal(content),
  };
}

function queryInputLocator(page) {
  return page
    .locator(
      'input[type="search"], input[name*="search" i], input[name*="query" i], input[placeholder*="search" i], input[aria-label*="search" i], input[name*="id" i], input[name*="user" i], input[type="text"], textarea'
    )
    .first();
}

async function submitCandidateInput(page, candidateInput, value) {
  await candidateInput.fill(value);
  const form = candidateInput.locator("xpath=ancestor::form[1]");
  const submitButton = form
    .locator('button[type="submit"], input[type="submit"], button')
    .first();
  if ((await submitButton.count()) > 0 && (await submitButton.isVisible().catch(() => false))) {
    await submitButton.click({ timeout: 5_000 }).catch(() => {});
  } else {
    await candidateInput.press("Enter").catch(() => {});
  }
  await page.waitForLoadState("networkidle", { timeout: 7_000 }).catch(() => {});
  return captureResponseSnapshot(page, null);
}

async function revealSearchInput(page, safePageUrl, preActionSelector) {
  const selectors = [preActionSelector, ...SEARCH_REVEAL_SELECTORS].filter(Boolean);

  for (const selector of selectors) {
    await page.goto(safePageUrl, { waitUntil: "domcontentloaded", timeout: 20_000 }).catch(() => {});
    await page.waitForLoadState("networkidle", { timeout: 7_000 }).catch(() => {});
    const revealControl = page.locator(selector).first();
    const controlVisible =
      (await revealControl.count().catch(() => 0)) > 0 &&
      (await revealControl.isVisible().catch(() => false));
    if (!controlVisible) {
      continue;
    }
    await revealControl.click({ timeout: 5_000 }).catch(() => {});
    await page.waitForTimeout(500);
    const revealedInput = queryInputLocator(page);
    const inputVisible =
      (await revealedInput.count().catch(() => 0)) > 0 &&
      (await revealedInput.isVisible().catch(() => false));
    if (inputVisible) {
      return { revealed: true, selector };
    }
  }

  return { revealed: false, selector: null };
}

async function probeVisibleSqlInput(page, safePageUrl, preActionSelector) {
  const reveal = await revealSearchInput(page, safePageUrl, preActionSelector);
  const candidateInput = queryInputLocator(page);
  const candidateVisible =
    (await candidateInput.count()) > 0 && (await candidateInput.isVisible().catch(() => false));
  if (!candidateVisible) {
    return { attempted: false, confirmed: false, evidence: null };
  }

  await submitCandidateInput(page, candidateInput, "cyberbox-demo");
  const baseline = await captureResponseSnapshot(page, null);
  for (const payload of SQLI_PAYLOADS) {
    await page.goto(safePageUrl, { waitUntil: "domcontentloaded", timeout: 20_000 }).catch(() => {});
    await page.waitForLoadState("networkidle", { timeout: 7_000 }).catch(() => {});
    if (reveal.revealed) {
      await revealSearchInput(page, safePageUrl, reveal.selector);
    }
    const freshInput = queryInputLocator(page);
    if ((await freshInput.count()) === 0) {
      continue;
    }
    const probe = await submitCandidateInput(page, freshInput, payload);
    if (hasSqlEvidence(baseline, probe)) {
      return {
        attempted: true,
        confirmed: true,
        evidence: `${reveal.revealed ? `Search input revealed by ${JSON.stringify(reveal.selector)}; ` : ""}visible input produced SQLi evidence with bounded payload ${JSON.stringify(payload)}.`,
      };
    }
  }
  return {
    attempted: true,
    confirmed: false,
    evidence: `${reveal.revealed ? `Search input revealed by ${JSON.stringify(reveal.selector)}; ` : ""}visible query-like input tested without SQLi evidence.`,
  };
}

async function probeHintedSqlTarget(page, safePageUrl, preActionSelector, targetSelector, targetParameter) {
  if (targetSelector) {
    await page.goto(safePageUrl, { waitUntil: "domcontentloaded", timeout: 20_000 }).catch(() => {});
    await page.waitForLoadState("networkidle", { timeout: 7_000 }).catch(() => {});
    if (preActionSelector) {
      await revealSearchInput(page, safePageUrl, preActionSelector);
    }
    const hintedInput = page.locator(targetSelector).first();
    const inputVisible =
      (await hintedInput.count().catch(() => 0)) > 0 &&
      (await hintedInput.isVisible().catch(() => false));
    if (inputVisible) {
      await submitCandidateInput(page, hintedInput, "cyberbox-demo");
      const baseline = await captureResponseSnapshot(page, null);
      for (const payload of SQLI_PAYLOADS) {
        await page.goto(safePageUrl, { waitUntil: "domcontentloaded", timeout: 20_000 }).catch(() => {});
        await page.waitForLoadState("networkidle", { timeout: 7_000 }).catch(() => {});
        if (preActionSelector) {
          await revealSearchInput(page, safePageUrl, preActionSelector);
        }
        const freshHintedInput = page.locator(targetSelector).first();
        if ((await freshHintedInput.count().catch(() => 0)) === 0) {
          continue;
        }
        const probe = await submitCandidateInput(page, freshHintedInput, payload);
        if (hasSqlEvidence(baseline, probe)) {
          return {
            attempted: true,
            confirmed: true,
            evidence: `LLM-suggested selector ${JSON.stringify(targetSelector)} produced SQLi evidence with bounded payload ${JSON.stringify(payload)}.`,
            status: probe.status,
          };
        }
      }
      return {
        attempted: true,
        confirmed: false,
        evidence: `LLM-suggested selector ${JSON.stringify(targetSelector)} tested without SQLi evidence.`,
        status: 0,
      };
    }
  }

  if (targetParameter) {
    const baselineUrl = new URL(safePageUrl);
    baselineUrl.searchParams.set(targetParameter, "cyberbox-demo");
    const baselineResponse = await page
      .goto(baselineUrl.toString(), { waitUntil: "domcontentloaded", timeout: 20_000 })
      .catch(() => null);
    await page.waitForLoadState("networkidle", { timeout: 7_000 }).catch(() => {});
    const baseline = await captureResponseSnapshot(page, baselineResponse);
    if (baseline.status && baseline.status !== 404) {
      for (const payload of SQLI_PAYLOADS) {
        const payloadUrl = new URL(safePageUrl);
        payloadUrl.searchParams.set(targetParameter, payload);
        const payloadResponse = await page
          .goto(payloadUrl.toString(), { waitUntil: "domcontentloaded", timeout: 20_000 })
          .catch(() => null);
        await page.waitForLoadState("networkidle", { timeout: 7_000 }).catch(() => {});
        const probe = await captureResponseSnapshot(page, payloadResponse);
        if (hasSqlEvidence(baseline, probe)) {
          return {
            attempted: true,
            confirmed: true,
            evidence: `LLM-suggested parameter ${JSON.stringify(targetParameter)} produced SQLi evidence with bounded payload ${JSON.stringify(payload)}.`,
            status: probe.status,
          };
        }
      }
      return {
        attempted: true,
        confirmed: false,
        evidence: `LLM-suggested parameter ${JSON.stringify(targetParameter)} tested without SQLi evidence.`,
        status: 0,
      };
    }
  }

  return {
    attempted: false,
    confirmed: false,
    evidence: "No usable LLM SQLi target hint was available.",
    status: 0,
  };
}

async function probeSqlRoutes(page, safeUrl) {
  const base = new URL(safeUrl);
  for (const route of SQLI_ROUTE_CANDIDATES) {
    const baselineUrl = new URL(route.path, base.origin);
    baselineUrl.searchParams.set(route.param, "cyberbox-demo");
    const baselineResponse = await page
      .goto(baselineUrl.toString(), { waitUntil: "domcontentloaded", timeout: 20_000 })
      .catch(() => null);
    await page.waitForLoadState("networkidle", { timeout: 7_000 }).catch(() => {});
    const baseline = await captureResponseSnapshot(page, baselineResponse);
    if (baseline.status === 0 || baseline.status === 404) {
      continue;
    }

    for (const payload of SQLI_PAYLOADS) {
      const payloadUrl = new URL(route.path, base.origin);
      payloadUrl.searchParams.set(route.param, payload);
      const payloadResponse = await page
        .goto(payloadUrl.toString(), { waitUntil: "domcontentloaded", timeout: 20_000 })
        .catch(() => null);
      await page.waitForLoadState("networkidle", { timeout: 7_000 }).catch(() => {});
      const probe = await captureResponseSnapshot(page, payloadResponse);
      if (hasSqlEvidence(baseline, probe)) {
        return {
          attempted: true,
          confirmed: true,
          evidence: `${route.path}?${route.param}= produced SQLi evidence with bounded payload ${JSON.stringify(payload)}.`,
          status: probe.status,
        };
      }
    }
  }
  return {
    attempted: true,
    confirmed: false,
    evidence: "Common query routes tested without SQLi evidence.",
    status: 0,
  };
}

async function captureXssSnapshot(page, response, dialogMessages) {
  const content = await page.content().catch(() => "");
  const executed = await page
    .evaluate(() => Boolean(window.__cyberboxXssConfirmed))
    .catch(() => false);
  const markerElementPresent = await page
    .locator('[data-cyberbox-xss="confirmed"]')
    .first()
    .count()
    .then((count) => count > 0)
    .catch(() => false);
  return {
    status: response?.status() || 0,
    url: page.url(),
    response_size: content.length,
    dialog_triggered: dialogMessages.some((message) => /cyberbox-xss/i.test(message)),
    execution_marker: executed || markerElementPresent,
  };
}

function hasXssEvidence(probe) {
  return Boolean(probe?.dialog_triggered || probe?.execution_marker);
}

async function probeVisibleXssInput(page, safePageUrl, preActionSelector, targetSelector, dialogMessages) {
  const reveal = await revealSearchInput(page, safePageUrl, preActionSelector);
  const candidateInput = targetSelector ? page.locator(targetSelector).first() : queryInputLocator(page);
  const candidateVisible =
    (await candidateInput.count().catch(() => 0)) > 0 &&
    (await candidateInput.isVisible().catch(() => false));
  if (!candidateVisible) {
    return { attempted: false, confirmed: false, evidence: null, status: 0 };
  }

  for (const payload of XSS_PAYLOADS) {
    await page.goto(safePageUrl, { waitUntil: "domcontentloaded", timeout: 20_000 }).catch(() => {});
    await page.waitForLoadState("networkidle", { timeout: 7_000 }).catch(() => {});
    if (reveal.revealed || preActionSelector) {
      await revealSearchInput(page, safePageUrl, reveal.selector || preActionSelector);
    }
    const freshInput = targetSelector ? page.locator(targetSelector).first() : queryInputLocator(page);
    if ((await freshInput.count().catch(() => 0)) === 0) {
      continue;
    }
    await submitCandidateInput(page, freshInput, payload);
    await page.waitForTimeout(750);
    const probe = await captureXssSnapshot(page, null, dialogMessages);
    if (hasXssEvidence(probe)) {
      return {
        attempted: true,
        confirmed: true,
        evidence: `${reveal.revealed ? `Search input revealed by ${JSON.stringify(reveal.selector)}; ` : ""}${targetSelector ? `LLM-suggested selector ${JSON.stringify(targetSelector)}` : "visible input"} produced bounded reflected-XSS evidence.`,
        status: probe.status,
      };
    }
  }

  return {
    attempted: true,
    confirmed: false,
    evidence: `${reveal.revealed ? `Search input revealed by ${JSON.stringify(reveal.selector)}; ` : ""}${targetSelector ? `LLM-suggested selector ${JSON.stringify(targetSelector)}` : "visible input"} tested without reflected-XSS evidence.`,
    status: 0,
  };
}

async function probeXssParameter(page, safePageUrl, targetParameter, dialogMessages) {
  if (!targetParameter) {
    return { attempted: false, confirmed: false, evidence: null, status: 0 };
  }

  for (const payload of XSS_PAYLOADS) {
    const payloadUrl = new URL(safePageUrl);
    payloadUrl.searchParams.set(targetParameter, payload);
    const payloadResponse = await page
      .goto(payloadUrl.toString(), { waitUntil: "domcontentloaded", timeout: 20_000 })
      .catch(() => null);
    await page.waitForLoadState("networkidle", { timeout: 7_000 }).catch(() => {});
    await page.waitForTimeout(750);
    const probe = await captureXssSnapshot(page, payloadResponse, dialogMessages);
    if (probe.status === 404) {
      continue;
    }
    if (hasXssEvidence(probe)) {
      return {
        attempted: true,
        confirmed: true,
        evidence: `LLM-suggested parameter ${JSON.stringify(targetParameter)} produced bounded reflected-XSS evidence.`,
        status: probe.status,
      };
    }
  }

  return {
    attempted: true,
    confirmed: false,
    evidence: `LLM-suggested parameter ${JSON.stringify(targetParameter)} tested without reflected-XSS evidence.`,
    status: 0,
  };
}

async function probeXssRoutes(page, safeUrl, dialogMessages) {
  const base = new URL(safeUrl);
  for (const route of XSS_ROUTE_CANDIDATES) {
    for (const payload of XSS_PAYLOADS) {
      const payloadUrl = new URL(route.path, base.origin);
      payloadUrl.searchParams.set(route.param, payload);
      const payloadResponse = await page
        .goto(payloadUrl.toString(), { waitUntil: "domcontentloaded", timeout: 20_000 })
        .catch(() => null);
      await page.waitForLoadState("networkidle", { timeout: 7_000 }).catch(() => {});
      await page.waitForTimeout(750);
      const probe = await captureXssSnapshot(page, payloadResponse, dialogMessages);
      if (probe.status === 404) {
        continue;
      }
      if (hasXssEvidence(probe)) {
        return {
          attempted: true,
          confirmed: true,
          evidence: `${route.path}?${route.param}= produced bounded reflected-XSS evidence.`,
          status: probe.status,
        };
      }
    }
  }

  return {
    attempted: true,
    confirmed: false,
    evidence: "Common query routes tested without reflected-XSS evidence.",
    status: 0,
  };
}

async function runScenario({
  targetUrl,
  targetPageUrl,
  preActionSelector,
  targetSelector,
  targetParameter,
  templateId,
  scenarioId,
  outputDir,
  runId,
}) {
  const safeUrl = assertLocalHttpUrl(targetUrl);
  const safePageUrl = resolveLocalHttpUrl(targetPageUrl || targetUrl, safeUrl);
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

    if (scenarioId === "sql_injection_probe") {
      const hintProbe = await probeHintedSqlTarget(page, safePageUrl, preActionSelector, targetSelector, targetParameter);
      const inputProbe = hintProbe.confirmed ? { attempted: false, confirmed: false, evidence: null } : await probeVisibleSqlInput(page, safePageUrl, preActionSelector);
      const routeProbe = hintProbe.confirmed || inputProbe.confirmed
        ? { attempted: false, confirmed: false, evidence: "Route probing skipped after visible input evidence.", status: 0 }
        : await probeSqlRoutes(page, safeUrl);
      const confirmedVulnerability = hintProbe.confirmed || inputProbe.confirmed || routeProbe.confirmed;
      if (!confirmedVulnerability) {
        await page.goto(safePageUrl, { waitUntil: "domcontentloaded", timeout: 20_000 }).catch(() => {});
        await page.waitForLoadState("networkidle", { timeout: 7_000 }).catch(() => {});
        await revealSearchInput(page, safePageUrl, preActionSelector);
      }

      await fs.mkdir(outputDir, { recursive: true });
      const screenshotPath = path.join(outputDir, `${templateId}-${runId}-${scenarioId}.png`);
      await page.screenshot({ path: screenshotPath, fullPage: true });

      const content = await page.content();
      result.ok = true;
      result.confirmed_vulnerability = confirmedVulnerability;
      result.status_code = hintProbe.status || routeProbe.status || response?.status() || 200;
      result.response_size = content.length;
      result.screenshot_path = screenshotPath;
      result.current_url = page.url();
      result.summary = confirmedVulnerability
        ? `Confirmed bounded SQL injection evidence: ${hintProbe.confirmed ? hintProbe.evidence : inputProbe.confirmed ? inputProbe.evidence : routeProbe.evidence} Screenshot saved to ${screenshotPath}.`
        : `Completed bounded SQL injection validation without confirmation. ${hintProbe.evidence || inputProbe.evidence || routeProbe.evidence} Screenshot saved to ${screenshotPath}.`;
      return result;
    }

    if (scenarioId === "reflected_xss_probe") {
      const dialogMessages = [];
      page.on("dialog", async (dialog) => {
        dialogMessages.push(dialog.message());
        await dialog.dismiss().catch(() => {});
      });
      const inputProbe = await probeVisibleXssInput(
        page,
        safePageUrl,
        preActionSelector,
        targetSelector,
        dialogMessages
      );
      const parameterProbe = inputProbe.confirmed
        ? { attempted: false, confirmed: false, evidence: "Parameter probing skipped after visible input evidence.", status: 0 }
        : await probeXssParameter(page, safePageUrl, targetParameter, dialogMessages);
      const routeProbe = inputProbe.confirmed || parameterProbe.confirmed
        ? { attempted: false, confirmed: false, evidence: "Route probing skipped after earlier XSS evidence.", status: 0 }
        : await probeXssRoutes(page, safeUrl, dialogMessages);
      const confirmedVulnerability = inputProbe.confirmed || parameterProbe.confirmed || routeProbe.confirmed;

      if (!confirmedVulnerability) {
        await page.goto(safePageUrl, { waitUntil: "domcontentloaded", timeout: 20_000 }).catch(() => {});
        await page.waitForLoadState("networkidle", { timeout: 7_000 }).catch(() => {});
        await revealSearchInput(page, safePageUrl, preActionSelector);
      }

      await fs.mkdir(outputDir, { recursive: true });
      const screenshotPath = path.join(outputDir, `${templateId}-${runId}-${scenarioId}.png`);
      await page.screenshot({ path: screenshotPath, fullPage: true });

      const content = await page.content();
      result.ok = true;
      result.confirmed_vulnerability = confirmedVulnerability;
      result.status_code = inputProbe.status || parameterProbe.status || routeProbe.status || response?.status() || 200;
      result.response_size = content.length;
      result.screenshot_path = screenshotPath;
      result.current_url = page.url();
      result.summary = confirmedVulnerability
        ? `Confirmed bounded reflected-XSS evidence: ${inputProbe.confirmed ? inputProbe.evidence : parameterProbe.confirmed ? parameterProbe.evidence : routeProbe.evidence} Screenshot saved to ${screenshotPath}.`
        : `Completed bounded reflected-XSS validation without confirmation. ${inputProbe.evidence || parameterProbe.evidence || routeProbe.evidence} Screenshot saved to ${screenshotPath}.`;
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
  const preActionSelector = process.env.CYBERBOX_PRE_ACTION_SELECTOR || "";
  const targetSelector = process.env.CYBERBOX_TARGET_SELECTOR || "";
  const targetParameter = process.env.CYBERBOX_TARGET_PARAMETER || "";
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
    preActionSelector,
    targetSelector,
    targetParameter,
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
