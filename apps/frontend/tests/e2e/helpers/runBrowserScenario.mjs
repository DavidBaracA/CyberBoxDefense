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

async function navigateToLoginSurface(page, safeUrl, preActionSelector = "") {
  if (preActionSelector) {
    const hintedControl = page.locator(preActionSelector).first();
    if ((await hintedControl.count().catch(() => 0)) > 0 && (await hintedControl.isVisible().catch(() => false))) {
      await hintedControl.click({ timeout: 5_000 }).catch(() => {});
      await page.waitForLoadState("networkidle", { timeout: 10_000 }).catch(() => {});
      return true;
    }
  }

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
  { username: "admin1", password: "password" },
  { username: "admin", password: "guess1" },
  { username: "admin", password: "guess2" },
  { username: "admin", password: "guess1" },
  { username: "admin", password: "guess2" },
  { username: "admin", password: "guess1" },
  { username: "admin", password: "guess2" },
  { username: "admin", password: "guess1" },
  { username: "admin", password: "guess2" },
  { username: "admin", password: "password" },
  { username: "user1@example.com", password: "Pasword1" },
  { username: "test@gmail.com", password: "password" },
  { username: "test@example.com", password: "Pasword12" },
  { username: "test2@example.com", password: "Password123" },
  { username: "test3@example.com", password: "Password123!" },
  { username: "admin10", password: "password" },
  { username: "user@example.com", password: "Password123!" },
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
const UPLOAD_REVEAL_SELECTORS = [
  'button[aria-label*="upload" i]',
  'button[aria-label*="avatar" i]',
  'button[aria-label*="attach" i]',
  'a[aria-label*="upload" i]',
  'a[aria-label*="avatar" i]',
  'a[aria-label*="attach" i]',
  'button:has-text("Upload")',
  'button:has-text("Avatar")',
  'button:has-text("Attach")',
  'a:has-text("Upload")',
  'a:has-text("Avatar")',
  'a:has-text("Attach")',
  'mat-icon:has-text("cloud_upload")',
  'mat-icon:has-text("upload")',
  '.mat-icon:has-text("cloud_upload")',
  '.mat-icon:has-text("upload")',
];
const REDIRECT_REVEAL_SELECTORS = [
  'a[href*="redirect"]',
  'a[href*="return"]',
  'a[href*="next="]',
  'a[href*="url="]',
  'a[href*="continue"]',
  'button[aria-label*="continue" i]',
  'button[aria-label*="redirect" i]',
  'button:has-text("Continue")',
  'a:has-text("Continue")',
];
const UPLOAD_CASES = [
  {
    caseId: "allowed_benign",
    filename: "probe_test.txt",
    contentType: "text/plain",
    content: "cyberbox benign upload probe\n",
    expectedAllowed: true,
  },
  {
    caseId: "dangerous_extension",
    filename: "probe_test.php",
    contentType: "text/plain",
    content: "PROBE_ONLY_DO_NOT_EXECUTE",
    expectedAllowed: false,
  },
  {
    caseId: "mime_mismatch",
    filename: "probe_test.jpg",
    contentType: "text/plain",
    content: "not really a jpeg\n",
    expectedAllowed: false,
  },
  {
    caseId: "double_extension",
    filename: "probe_test.jpg.php",
    contentType: "image/jpeg",
    content: "PROBE_ONLY_DO_NOT_EXECUTE",
    expectedAllowed: false,
  },
  {
    caseId: "filename_edge",
    filename: "probe test.txt",
    contentType: "text/plain",
    content: "filename sanitization probe\n",
    expectedAllowed: false,
  },
  {
    caseId: "path_like_filename",
    filename: "../probe_test.txt",
    contentType: "text/plain",
    content: "path-like filename probe\n",
    expectedAllowed: false,
  },
];
const REDIRECT_PATHS = ["/redirect", "/login", "/logout", "/next", "/return", "/callback", "/continue"];
const REDIRECT_PARAMETERS = [
  "next",
  "url",
  "target",
  "redirect",
  "redirect_uri",
  "return",
  "returnUrl",
  "return_to",
  "continue",
  "destination",
  "goto",
  "to",
];
const REDIRECT_PAYLOADS = [
  "https://example.com/",
  "//example.com/",
  "https://evil.example/",
  "/\\example.com",
  "https:%2f%2fexample.com%2f",
];
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const UPLOAD_REMEDIATION =
  "Allow-list extensions, verify file signatures rather than trusting Content-Type, rename files server-side, store uploads outside the web root, serve downloads with safe Content-Disposition, enforce size limits, and scan files where appropriate.";
const REDIRECT_REMEDIATION =
  "Use relative paths only, allow-list redirect destinations, map redirect IDs server-side, validate scheme and host, and show an interstitial warning for external destinations.";

function hasSqlErrorSignal(content) {
  return SQL_ERROR_PATTERNS.some((pattern) => pattern.test(content || ""));
}

function rawHttpMetadata(method, url, response, bodyText = "") {
  const headers = {};
  if (response?.headers?.forEach) {
    response.headers.forEach((value, key) => {
      headers[key] = value;
    });
  }
  return {
    method,
    url,
    status_code: response?.status || 0,
    headers,
    redirect_location: response?.headers?.get?.("location") || null,
    response_size: bodyText.length,
  };
}

function normalizeRedirectLocation(targetUrl, location) {
  if (!location) {
    return null;
  }
  let resolved;
  try {
    resolved = new URL(location.trim(), targetUrl);
  } catch {
    return null;
  }
  if (!["http:", "https:"].includes(resolved.protocol) || !resolved.hostname) {
    return null;
  }
  return resolved.toString();
}

function isExternalRedirect(targetUrl, location) {
  const resolved = normalizeRedirectLocation(targetUrl, location);
  if (!resolved) {
    return false;
  }
  return new URL(resolved).hostname.toLowerCase() !== new URL(targetUrl).hostname.toLowerCase();
}

function isSameOrigin(left, right) {
  try {
    return new URL(left).origin === new URL(right, left).origin;
  } catch {
    return false;
  }
}

function extractUploadedUrl(responseText, baseUrl, location) {
  if (location) {
    return new URL(location, baseUrl).toString();
  }
  const text = responseText || "";
  try {
    const parsed = JSON.parse(text);
    for (const key of ["url", "fileUrl", "file_url", "location", "path"]) {
      if (typeof parsed[key] === "string" && parsed[key]) {
        return new URL(parsed[key], baseUrl).toString();
      }
    }
  } catch {}
  const hrefMatch = text.match(/href=["']([^"']*(?:probe_test|probe%20test)[^"']*)["']/i);
  if (hrefMatch) {
    return new URL(hrefMatch[1], baseUrl).toString();
  }
  const plainMatch = text.match(/(?:https?:\/\/[^\s"']+|\/[^\s"']*)(?:probe_test|probe%20test)[^\s"']*/i);
  if (plainMatch) {
    return new URL(plainMatch[0], baseUrl).toString();
  }
  return null;
}

function uploadAccepted(status, bodyText) {
  if ([400, 403, 409, 413, 415, 422].includes(status)) {
    return false;
  }
  return !/invalid file|not allowed|unsupported|forbidden/i.test(bodyText || "");
}

function classifyUploadFinding(targetUrl, form, testCase, response, responseText, retrieval) {
  const accepted = uploadAccepted(response.status, responseText);
  const uploadedUrl = extractUploadedUrl(responseText, form.actionUrl, response.headers.get("location"));
  const publiclyRetrievable =
    retrieval && retrieval.status === 200 && /PROBE_ONLY_DO_NOT_EXECUTE/.test(retrieval.bodyText || "");
  const filename = testCase.filename.toLowerCase();
  const dangerousExtension = /\.(php|phtml|jsp|jspx|asp|aspx)$/.test(filename);
  const doubleExtension = /\.(jpg|png)\.(php|phtml|jsp|jspx|asp|aspx)$/.test(filename);
  const mimeMismatch = testCase.caseId === "mime_mismatch";
  const weakFilename = /[\\/]/.test(testCase.filename) || responseText.includes(testCase.filename);

  if (!accepted && !publiclyRetrievable) {
    return null;
  }
  if (testCase.expectedAllowed && !publiclyRetrievable) {
    return null;
  }

  let severity = "low";
  let confidence = 0.66;
  let description = "The upload endpoint accepted weak file-upload validation input.";
  if (dangerousExtension || doubleExtension) {
    severity = publiclyRetrievable ? "high" : "medium";
    confidence = publiclyRetrievable ? 0.9 : 0.78;
    description = "The upload endpoint accepted a script-like or double-extension filename.";
  } else if (mimeMismatch) {
    severity = "medium";
    confidence = 0.72;
    description = "The upload endpoint accepted a file whose extension and declared Content-Type did not match.";
  } else if (weakFilename) {
    severity = "low";
    confidence = 0.68;
    description = "The upload endpoint reflected or accepted a weak filename sanitization edge case.";
  } else {
    return null;
  }

  const rawHttp = [rawHttpMetadata("POST", form.actionUrl, response, responseText)];
  if (retrieval) {
    rawHttp.push(rawHttpMetadata("GET", retrieval.url, retrieval.response, retrieval.bodyText));
  }
  return {
    probe_name: "file_upload_probe",
    target_url: targetUrl,
    severity,
    confidence,
    category: "file_handling",
    cwe: "CWE-434",
    description,
    evidence: {
      tested_filename: testCase.filename,
      declared_content_type: testCase.contentType,
      http_status: response.status,
      redirect_location: response.headers.get("location"),
      returned_upload_url: uploadedUrl,
      validation_message: responseText.slice(0, 300),
      publicly_retrievable: Boolean(publiclyRetrievable),
    },
    remediation: UPLOAD_REMEDIATION,
    raw_http: rawHttp,
  };
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

async function isSafeLoginSubmit(locator) {
  if ((await locator.count().catch(() => 0)) === 0 || !(await locator.isVisible().catch(() => false))) {
    return false;
  }
  return locator
    .evaluate((node) => {
      const tag = node.tagName.toLowerCase();
      const role = (node.getAttribute("role") || "").toLowerCase();
      const type = (node.getAttribute("type") || "").toLowerCase();
      const text = [
        node.innerText,
        node.getAttribute("value"),
        node.getAttribute("aria-label"),
        node.getAttribute("title"),
      ]
        .filter(Boolean)
        .join(" ")
        .replace(/\s+/g, " ")
        .trim()
        .toLowerCase();
      if (/forgot|reset|recover|signup|sign up|register|create account/.test(text)) {
        return false;
      }
      const buttonLike =
        tag === "button" ||
        role === "button" ||
        (tag === "input" && ["submit", "button"].includes(type));
      const submitText = /^(log in|login|sign in|submit|continue)$/i.test(text);
      return buttonLike && (type === "submit" || submitText);
    })
    .catch(() => false);
}

async function firstVisibleLocator(locators, predicate = null) {
  for (const locator of locators) {
    if (
      (await locator.count().catch(() => 0)) > 0 &&
      (await locator.isVisible().catch(() => false)) &&
      (!predicate || (await predicate(locator)))
    ) {
      return locator;
    }
  }
  return null;
}

async function findLoginSubmitButton(page, passwordField, targetSelector = "") {
  const form = passwordField.locator("xpath=ancestor::form[1]");
  const formExists = (await form.count()) > 0;
  const formScope = formExists ? form : page;
  const hintedSubmit = targetSelector ? formScope.locator(targetSelector).first() : null;

  return firstVisibleLocator([
    hintedSubmit,
    formScope.locator('button[type="submit"]').first(),
    formScope.locator('input[type="submit"]').first(),
    formScope.locator('button:has-text("Login")').first(),
    formScope.locator('button:has-text("Log in")').first(),
    formScope.locator('button:has-text("Sign in")').first(),
    formScope.locator('button:has-text("Submit")').first(),
    formScope.locator('button:has-text("Continue")').first(),
    formScope.locator('[role="button"]:has-text("Login")').first(),
    formScope.locator('[role="button"]:has-text("Log in")').first(),
    formScope.locator('[role="button"]:has-text("Sign in")').first(),
    formScope.locator('[aria-label*="login" i]').first(),
    formScope.locator('[aria-label*="sign in" i]').first(),
    formScope.locator('input[type="button"][value*="login" i]').first(),
    formScope.locator('input[type="button"][value*="sign in" i]').first(),
    formScope.locator("button").first(),
  ].filter(Boolean), isSafeLoginSubmit);
}

async function describeLocator(locator) {
  if (!locator) {
    return null;
  }
  return {
    text: await locator.innerText({ timeout: 1_000 }).catch(() => ""),
    visible: await locator.isVisible().catch(() => false),
    enabled: await locator.isEnabled().catch(() => false),
  };
}

async function loginFormMetadata(usernameField, passwordField) {
  return passwordField
    .evaluate((passwordInput, usernameInput) => {
      const form = passwordInput.closest("form");
      const usernameValue = usernameInput && "value" in usernameInput ? usernameInput.value : "";
      const passwordValue = "value" in passwordInput ? passwordInput.value : "";
      return {
        form_action: form ? new URL(form.getAttribute("action") || window.location.href, window.location.href).toString() : null,
        form_method: form ? (form.getAttribute("method") || "GET").toUpperCase() : null,
        username_name: usernameInput?.getAttribute("name") || null,
        password_name: passwordInput.getAttribute("name") || null,
        username_value: usernameValue,
        password_length: passwordValue.length,
      };
    }, await usernameField.elementHandle().catch(() => null))
    .catch(() => null);
}

async function submitAncestorForm(page, passwordField, submitButton = null) {
  const form = passwordField.locator("xpath=ancestor::form[1]");
  if ((await form.count().catch(() => 0)) === 0) {
    return { submitted: false, error: "no_form" };
  }

  const submitterHandle = submitButton ? await submitButton.elementHandle().catch(() => null) : null;
  const error = await Promise.all([
    page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: 7_000 }).catch(() => null),
    form
      .evaluate((formNode, submitter) => {
        if (typeof formNode.requestSubmit === "function") {
          if (submitter) {
            formNode.requestSubmit(submitter);
            return;
          }
          formNode.requestSubmit();
          return;
        }
        formNode.submit();
      }, submitterHandle)
      .then(() => null)
      .catch((submitError) => submitError.message),
  ]).then(([, submitError]) => submitError);
  await submitterHandle?.dispose().catch(() => {});
  await page.waitForLoadState("networkidle", { timeout: 7_000 }).catch(() => {});
  return { submitted: !error, error };
}

async function submitLoginAttempt(page, usernameField, passwordField, targetSelector = "") {
  const submitButton = await findLoginSubmitButton(page, passwordField, targetSelector);
  const beforeUrl = page.url();
  const formMetadata = await loginFormMetadata(usernameField, passwordField);

  const formSubmission = await submitAncestorForm(page, passwordField, submitButton);
  if (formSubmission.submitted) {
    return {
      method: "form_request_submit",
      button_found: Boolean(submitButton),
      button: submitButton ? await describeLocator(submitButton) : null,
      form: formMetadata,
      before_url: beforeUrl,
      after_url: page.url(),
    };
  }

  if (submitButton) {
    const button = await describeLocator(submitButton);
    const clickError = await submitButton.click({ timeout: 5_000 }).then(() => null).catch((error) => error.message);
    await page.waitForLoadState("networkidle", { timeout: 7_000 }).catch(() => {});
    if (!clickError) {
      return {
        method: "click",
        button_found: true,
        button,
        form: formMetadata,
        form_submit_error: formSubmission.error,
        before_url: beforeUrl,
        after_url: page.url(),
      };
    }

    await passwordField.press("Enter").catch(() => {});
    await page.waitForLoadState("networkidle", { timeout: 7_000 }).catch(() => {});
    return {
      method: "click_failed_then_enter",
      button_found: true,
      button,
      click_error: clickError,
      form: formMetadata,
      form_submit_error: formSubmission.error,
      before_url: beforeUrl,
      after_url: page.url(),
    };
  }

  await passwordField.press("Enter").catch(() => {});
  await page.waitForLoadState("networkidle", { timeout: 7_000 }).catch(() => {});
  return {
    method: "enter",
    button_found: false,
    form: formMetadata,
    form_submit_error: formSubmission.error,
    before_url: beforeUrl,
    after_url: page.url(),
  };
}

async function loginFormStillVisible(usernameField, passwordField) {
  return (
    (await usernameField.count().catch(() => 0)) > 0 &&
    (await passwordField.count().catch(() => 0)) > 0 &&
    (await usernameField.isVisible().catch(() => false)) &&
    (await passwordField.isVisible().catch(() => false))
  );
}

async function pageLooksAuthenticated(page) {
  const currentUrl = page.url().toLowerCase();
  const content = (await page.content().catch(() => "")).toLowerCase();
  return (
    !/login|sign[\s-]?in/.test(currentUrl) ||
    /logout|log out|sign out/.test(content)
  );
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

function fileInputLocator(page, targetSelector) {
  return targetSelector ? page.locator(targetSelector).first() : page.locator('input[type="file"]').first();
}

async function revealFileInput(page, safePageUrl, preActionSelector, targetSelector) {
  const selectors = [preActionSelector, ...UPLOAD_REVEAL_SELECTORS].filter(Boolean);

  async function fileInputVisible() {
    const input = fileInputLocator(page, targetSelector);
    return (
      (await input.count().catch(() => 0)) > 0 &&
      ((await input.isVisible().catch(() => false)) || (await input.evaluate((node) => node.type === "file").catch(() => false)))
    );
  }

  await page.goto(safePageUrl, { waitUntil: "domcontentloaded", timeout: 20_000 }).catch(() => {});
  await page.waitForLoadState("networkidle", { timeout: 7_000 }).catch(() => {});
  if (await fileInputVisible()) {
    return { revealed: false, selector: null };
  }

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
    await page.waitForTimeout(700);
    if (await fileInputVisible()) {
      return { revealed: true, selector };
    }
  }

  return { revealed: false, selector: null };
}

async function discoverUploadForms(page, safePageUrl, preActionSelector, targetSelector) {
  const reveal = await revealFileInput(page, safePageUrl, preActionSelector, targetSelector);
  const forms = await page.evaluate((selector) => {
    const explicitInput = selector ? document.querySelector(selector) : null;
    const inputs = explicitInput ? [explicitInput] : Array.from(document.querySelectorAll('input[type="file"]'));
    return inputs.slice(0, 5).map((input) => {
      const form = input.closest("form");
      return {
        actionUrl: new URL(form?.getAttribute("action") || window.location.href, window.location.href).toString(),
        method: (form?.getAttribute("method") || "POST").toUpperCase(),
        fileField: input.getAttribute("name") || "file",
        locatorHint: input.id ? `#${input.id}` : input.getAttribute("name") ? `input[name="${String(input.getAttribute("name")).replace(/"/g, '\\"')}"]` : 'input[type="file"]',
      };
    });
  }, targetSelector || "");
  return {
    reveal,
    forms: forms.filter((form) => form.method === "POST" && isSameOrigin(safePageUrl, form.actionUrl)),
  };
}

async function cookieHeaderFor(page, url) {
  const cookies = await page.context().cookies(url).catch(() => []);
  return cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join("; ");
}

async function submitUploadCase(page, form, testCase) {
  const formData = new FormData();
  formData.append(
    form.fileField,
    new Blob([testCase.content], { type: testCase.contentType }),
    testCase.filename
  );
  const cookie = await cookieHeaderFor(page, form.actionUrl);
  const response = await fetch(form.actionUrl, {
    method: "POST",
    body: formData,
    redirect: "manual",
    headers: cookie ? { Cookie: cookie } : undefined,
  });
  const bodyText = await response.text().catch(() => "");
  return { response, bodyText };
}

async function retrieveUploadedUrl(page, safeUrl, uploadedUrl) {
  if (!uploadedUrl || !isSameOrigin(safeUrl, uploadedUrl)) {
    return null;
  }
  const cookie = await cookieHeaderFor(page, uploadedUrl);
  const response = await fetch(uploadedUrl, {
    method: "GET",
    redirect: "manual",
    headers: cookie ? { Cookie: cookie } : undefined,
  });
  const bodyText = await response.text().catch(() => "");
  return { url: uploadedUrl, response, bodyText };
}

async function probeUploadForms(page, safeUrl, safePageUrl, preActionSelector, targetSelector) {
  const { reveal, forms } = await discoverUploadForms(page, safePageUrl, preActionSelector, targetSelector);
  const evidence = [];
  const findings = [];

  if (forms.length === 0) {
    return {
      attempted: false,
      confirmed: false,
      status: 0,
      findings,
      evidence: `${reveal.revealed ? `Upload input reveal attempted via ${JSON.stringify(reveal.selector)}; ` : ""}no POST file-upload form was found.`,
    };
  }

  for (const form of forms.slice(0, 5)) {
    for (const testCase of UPLOAD_CASES) {
      const { response, bodyText } = await submitUploadCase(page, form, testCase);
      const uploadedUrl = extractUploadedUrl(bodyText, form.actionUrl, response.headers.get("location"));
      const retrieval = await retrieveUploadedUrl(page, safeUrl, uploadedUrl);
      const finding = classifyUploadFinding(safeUrl, form, testCase, response, bodyText, retrieval);
      evidence.push({
        form_action: form.actionUrl,
        file_field: form.fileField,
        tested_filename: testCase.filename,
        status_code: response.status,
        returned_upload_url: uploadedUrl,
      });
      if (finding) {
        findings.push(finding);
      }
    }
  }

  return {
    attempted: true,
    confirmed: findings.length > 0,
    status: findings[0]?.evidence?.http_status || 0,
    findings,
    evidence: `${reveal.revealed ? `Upload input revealed by ${JSON.stringify(reveal.selector)}; ` : ""}${findings.length} upload validation finding(s) from ${evidence.length} bounded harmless upload attempt(s).`,
  };
}

async function revealRedirectSurface(page, safePageUrl, preActionSelector) {
  const selectors = [preActionSelector, ...REDIRECT_REVEAL_SELECTORS].filter(Boolean);
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
    await page.waitForTimeout(700);
    return { revealed: true, selector };
  }
  return { revealed: false, selector: null };
}

function redirectCandidateUrls(safeUrl, safePageUrl, targetParameter, discoveredLinks) {
  const candidates = [];
  const parameters = targetParameter ? [targetParameter] : REDIRECT_PARAMETERS;
  const base = new URL(safeUrl);
  for (const href of [safePageUrl, ...discoveredLinks]) {
    const url = new URL(href, safePageUrl);
    if (url.origin !== base.origin) {
      continue;
    }
    const existingParams = Array.from(url.searchParams.keys());
    for (const parameter of existingParams.length ? existingParams : parameters) {
      candidates.push({ baseUrl: url.toString(), parameter });
    }
  }
  for (const pathName of REDIRECT_PATHS) {
    const url = new URL(pathName, base.origin);
    for (const parameter of parameters) {
      candidates.push({ baseUrl: url.toString(), parameter });
    }
  }
  return candidates.slice(0, 80);
}

function detectClientSideRedirect(targetUrl, bodyText) {
  const patterns = [
    /<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["'][^"']*url=([^"'>\s]+)/i,
    /(?:window\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']/i,
  ];
  for (const pattern of patterns) {
    const match = bodyText.match(pattern);
    if (match && isExternalRedirect(targetUrl, match[1])) {
      return normalizeRedirectLocation(targetUrl, match[1]);
    }
  }
  return null;
}

async function probeOpenRedirects(page, safeUrl, safePageUrl, preActionSelector, targetParameter) {
  const reveal = await revealRedirectSurface(page, safePageUrl, preActionSelector);
  const discoveredLinks = await page
    .locator("a[href]")
    .evaluateAll((nodes) => nodes.slice(0, 24).map((node) => node.getAttribute("href") || "").filter(Boolean))
    .catch(() => []);
  const candidates = redirectCandidateUrls(safeUrl, safePageUrl, targetParameter, discoveredLinks);
  const findings = [];
  let attempts = 0;
  let lastStatus = 0;

  for (const candidate of candidates) {
    for (const payload of REDIRECT_PAYLOADS) {
      const tested = new URL(candidate.baseUrl);
      tested.searchParams.set(candidate.parameter, payload);
      const testedUrl = tested.toString();
      const response = await fetch(testedUrl, { method: "GET", redirect: "manual" });
      const bodyText = await response.text().catch(() => "");
      const location = response.headers.get("location");
      attempts += 1;
      lastStatus = response.status;

      if (REDIRECT_STATUSES.has(response.status) && isExternalRedirect(safeUrl, location)) {
        const resolved = normalizeRedirectLocation(safeUrl, location);
        findings.push({
          probe_name: "open_redirect_probe",
          target_url: safeUrl,
          severity: "medium",
          confidence: 0.92,
          category: "navigation_flow",
          cwe: "CWE-601",
          description: "The target reflected an untrusted redirect destination into the Location header.",
          evidence: {
            tested_url: testedUrl,
            parameter: candidate.parameter,
            payload,
            http_status: response.status,
            location,
            resolved_external_host: new URL(resolved).hostname,
          },
          remediation: REDIRECT_REMEDIATION,
          raw_http: [rawHttpMetadata("GET", testedUrl, response, bodyText)],
        });
        continue;
      }

      const clientSideUrl = detectClientSideRedirect(safeUrl, bodyText);
      if (clientSideUrl) {
        findings.push({
          probe_name: "open_redirect_probe",
          target_url: safeUrl,
          severity: "low",
          confidence: 0.7,
          category: "navigation_flow",
          cwe: "CWE-601",
          description: "The response body contained a client-side redirect to an untrusted host.",
          evidence: {
            tested_url: testedUrl,
            parameter: candidate.parameter,
            payload,
            http_status: response.status,
            resolved_external_host: new URL(clientSideUrl).hostname,
          },
          remediation: REDIRECT_REMEDIATION,
          raw_http: [rawHttpMetadata("GET", testedUrl, response, bodyText)],
        });
      }
    }
  }

  return {
    attempted: attempts > 0,
    confirmed: findings.length > 0,
    status: findings[0]?.evidence?.http_status || lastStatus,
    findings,
    evidence: `${reveal.revealed ? `Redirect surface revealed by ${JSON.stringify(reveal.selector)}; ` : ""}${attempts} bounded redirect request(s) tested with redirects disabled.`,
  };
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
  storageStatePath,
}) {
  const safeUrl = assertLocalHttpUrl(targetUrl);
  const safePageUrl = resolveLocalHttpUrl(targetPageUrl || targetUrl, safeUrl);
  const browser = await chromium.launch({ headless: true });
  const storageStateExists = storageStatePath
    ? await fs.stat(storageStatePath).then(() => true).catch(() => false)
    : false;
  const context = await browser.newContext(
    storageStateExists ? { storageState: storageStatePath } : {}
  );
  const page = await context.newPage();
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
    findings: [],
  };

  try {
    const response = await page.goto(safePageUrl, { waitUntil: "domcontentloaded", timeout: 20_000 });
    await page.waitForLoadState("networkidle", { timeout: 10_000 }).catch(() => {});

    if (scenarioId === "brute_force_login") {
      await navigateToLoginSurface(page, safePageUrl, preActionSelector);
      const usernameField = page
        .locator('input[type="email"], input[name*="user" i], input[name*="email" i], input[id*="user" i], input[id*="email" i]')
        .first();
      const passwordField = page.locator('input[type="password"]').first();
      const loginVisible =
        (await usernameField.count()) > 0 &&
        (await passwordField.count()) > 0 &&
        (await passwordField.isVisible().catch(() => false));
      const submissionResults = [];

      if (loginVisible) {
        for (const attempt of BOUNDED_LOGIN_ATTEMPTS) {
          if (await pageLooksAuthenticated(page)) {
            submissionResults.push({
              method: "stopped_authenticated",
              button_found: false,
              before_url: page.url(),
              after_url: page.url(),
            });
            break;
          }
          if (!(await loginFormStillVisible(usernameField, passwordField))) {
            submissionResults.push({
              method: "stopped_form_unavailable",
              button_found: false,
              before_url: page.url(),
              after_url: page.url(),
            });
            break;
          }
          await usernameField.fill(attempt.username, { timeout: 5_000 });
          await passwordField.fill(attempt.password, { timeout: 5_000 });
          const submission = await submitLoginAttempt(page, usernameField, passwordField, targetSelector);
          submission.attempt_index = submissionResults.length + 1;
          submission.attempt_username = attempt.username;
          submission.attempt_password_length = attempt.password.length;
          submissionResults.push(submission);
          if (await pageLooksAuthenticated(page)) {
            break;
          }
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
      result.debug = {
        login_visible: loginVisible,
        target_selector: targetSelector || null,
        submission_results: submissionResults,
      };
      const submissionMethods = [...new Set(submissionResults.map((item) => item.method))];
      const buttonFoundCount = submissionResults.filter((item) => item.button_found).length;
      result.summary = loginVisible
        ? `Attempted ${submissionResults.filter((item) => item.method && !item.method.startsWith("stopped_")).length}/${BOUNDED_LOGIN_ATTEMPTS.length} allowlisted login submissions using ${submissionMethods.join(", ") || "no submit method"}; submit button found on ${buttonFoundCount}/${submissionResults.length} recorded step(s). Captured bounded evidence at ${screenshotPath}.`
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
      const uploadProbe = await probeUploadForms(page, safeUrl, safePageUrl, preActionSelector, targetSelector);
      if (!uploadProbe.confirmed) {
        await page.goto(safePageUrl, { waitUntil: "domcontentloaded", timeout: 20_000 }).catch(() => {});
        await page.waitForLoadState("networkidle", { timeout: 7_000 }).catch(() => {});
        await revealFileInput(page, safePageUrl, preActionSelector, targetSelector);
      }

      await fs.mkdir(outputDir, { recursive: true });
      const screenshotPath = path.join(outputDir, `${templateId}-${runId}-file-upload-probe.png`);
      await page.screenshot({ path: screenshotPath, fullPage: true });

      const content = await page.content();
      result.ok = true;
      result.confirmed_vulnerability = uploadProbe.confirmed;
      result.status_code = response?.status() || 200;
      result.response_size = content.length;
      result.screenshot_path = screenshotPath;
      result.current_url = page.url();
      result.findings = uploadProbe.findings;
      result.summary = uploadProbe.confirmed
        ? `Confirmed bounded file-upload validation evidence: ${uploadProbe.evidence} Screenshot saved to ${screenshotPath}.`
        : `Completed bounded file-upload validation without confirmation. ${uploadProbe.evidence} Screenshot saved to ${screenshotPath}.`;
      return result;
    }

    if (scenarioId === "open_redirect_probe") {
      const redirectProbe = await probeOpenRedirects(page, safeUrl, safePageUrl, preActionSelector, targetParameter);

      await fs.mkdir(outputDir, { recursive: true });
      const screenshotPath = path.join(outputDir, `${templateId}-${runId}-open-redirect-probe.png`);
      await page.screenshot({ path: screenshotPath, fullPage: true });

      const content = await page.content();
      result.ok = true;
      result.confirmed_vulnerability = redirectProbe.confirmed;
      result.status_code = redirectProbe.status || response?.status() || 200;
      result.response_size = content.length;
      result.screenshot_path = screenshotPath;
      result.current_url = page.url();
      result.findings = redirectProbe.findings;
      result.summary = redirectProbe.confirmed
        ? `Confirmed bounded open-redirect evidence: ${redirectProbe.evidence} Screenshot saved to ${screenshotPath}.`
        : `Completed bounded open-redirect validation without confirmation. ${redirectProbe.evidence} Screenshot saved to ${screenshotPath}.`;
      return result;
    }

    throw new Error(`Unsupported browser scenario "${scenarioId}".`);
  } finally {
    if (storageStatePath) {
      await fs.mkdir(path.dirname(storageStatePath), { recursive: true }).catch(() => {});
      await context.storageState({ path: storageStatePath }).catch(() => {});
    }
    await context.close().catch(() => {});
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
  const storageStatePath = process.env.CYBERBOX_BROWSER_STORAGE_STATE || "";

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
    storageStatePath,
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
});
