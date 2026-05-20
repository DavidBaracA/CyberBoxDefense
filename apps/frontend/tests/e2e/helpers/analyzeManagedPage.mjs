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
    throw new Error(`Refusing browser analysis against non-local host "${parsed.hostname}".`);
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error(`Unsupported target protocol "${parsed.protocol}".`);
  }

  return parsed.toString();
}

function clip(text, max = 220) {
  return String(text || "").replace(/\s+/g, " ").trim().slice(0, max);
}

async function extractCandidateElements(page) {
  return page.evaluate(() => {
    const rows = [];

    function collect(selector, limit, mapper) {
      const nodes = Array.from(document.querySelectorAll(selector)).slice(0, limit);
      for (const node of nodes) {
        rows.push(mapper(node));
      }
    }

    const signalList = (values) => values.filter(Boolean);
    const cleanText = (value) => String(value || "").replace(/\s+/g, " ").trim().slice(0, 200);
    const cssString = (value) => String(value || "").replace(/\\/g, "\\\\").replace(/"/g, '\\"');
    const locatorHint = (node) => {
      if (!node) {
        return "";
      }
      if (node.id) {
        return `#${node.id}`;
      }
      const ariaLabel = node.getAttribute("aria-label");
      if (ariaLabel) {
        return `${node.tagName.toLowerCase()}[aria-label="${cssString(ariaLabel)}"]`;
      }
      if (node.name) {
        return `${node.tagName.toLowerCase()}[name="${cssString(node.name)}"]`;
      }
      const role = node.getAttribute("role");
      if (role) {
        return `${node.tagName.toLowerCase()}[role="${cssString(role)}"]`;
      }
      return node.tagName.toLowerCase();
    };

    collect("input, textarea, select", 24, (node) => {
      const inputType = (node.getAttribute("type") || "").toLowerCase();
      const label =
        node.getAttribute("aria-label") ||
        node.getAttribute("placeholder") ||
        node.getAttribute("name") ||
        node.getAttribute("id") ||
        "";
      const text = cleanText(label);
      const lowerText = text.toLowerCase();
      const signals = signalList([
        inputType === "password" ? "password_field" : "",
        inputType === "file" ? "file_input" : "",
        /search|query/.test(lowerText) ? "search_field" : "",
        /user|email|login/.test(lowerText) ? "username_field" : "",
        node.tagName.toLowerCase() === "textarea" ? "textarea" : "",
        "form_input",
      ]);
      return {
        element_kind: inputType === "file" ? "file_input" : "input",
        text,
        locator_hint: locatorHint(node),
        input_type: inputType || node.tagName.toLowerCase(),
        confidence: signals.length >= 2 ? 0.85 : 0.55,
        signals,
      };
    });

    collect("button, input[type='submit'], a", 24, (node) => {
      const text = cleanText(node.innerText || node.value || node.getAttribute("aria-label") || "");
      const href = node.getAttribute("href") || "";
      const ariaLabel = cleanText(node.getAttribute("aria-label") || "");
      const combinedText = cleanText(`${text} ${ariaLabel}`);
      const lowerCombinedText = combinedText.toLowerCase();
      const isResetOrSignup = /forgot|reset|recover|signup|sign up|register|create account/.test(lowerCombinedText);
      const signals = signalList([
        /login|log in|sign in|account/.test(lowerCombinedText) ? "login_navigation" : "",
        !isResetOrSignup &&
        (node.matches("button[type='submit'], input[type='submit']") ||
          /^(login|log in|sign in|submit|continue)$/.test(lowerCombinedText))
          ? "login_submit"
          : "",
        /upload|attach/.test(lowerCombinedText) ? "upload_button" : "",
        /continue|redirect|return/.test(lowerCombinedText) ? "redirect_navigation" : "",
        /search|find/.test(lowerCombinedText) ? "search_reveal_or_submit" : "",
        href.includes("redirect") || href.includes("return") || href.includes("next=") ? "redirect_link" : "",
      ]);
      return {
        element_kind: node.tagName.toLowerCase() === "a" ? "link" : "button",
        text: combinedText,
        locator_hint: locatorHint(node),
        href: href || undefined,
        confidence: signals.length >= 1 ? 0.7 : 0.4,
        signals,
      };
    });

    return rows.filter((row) => row.text || row.href || row.signals.length > 0);
  });
}

function buildHeuristicAnalysis({ pageUrl, title, bodyText, candidateElements, linkHrefs, formActions }) {
  const lowerText = bodyText.toLowerCase();
  const lowerTitle = String(title || "").toLowerCase();
  const inputSignals = candidateElements.flatMap((item) => item.signals || []);
  const lowerLinks = linkHrefs.map((item) => item.toLowerCase());
  const lowerActions = formActions.map((item) => item.toLowerCase());

  const hasPassword = inputSignals.includes("password_field");
  const hasUserField = inputSignals.includes("username_field");
  const searchReveal = candidateElements.find((item) =>
    (item.signals || []).includes("search_reveal_or_submit")
  );
  const uploadReveal = candidateElements.find((item) =>
    (item.signals || []).includes("upload_button")
  );
  const redirectReveal = candidateElements.find((item) =>
    (item.signals || []).includes("redirect_navigation") || (item.signals || []).includes("redirect_link")
  );
  const loginReveal = candidateElements.find((item) =>
    (item.signals || []).includes("login_navigation") && item.element_kind === "link"
  );
  const loginSubmit = candidateElements.find((item) =>
    (item.signals || []).includes("login_submit") && item.element_kind === "button"
  );
  const fileInput = candidateElements.find((item) =>
    (item.signals || []).includes("file_input")
  );
  const hasSearch =
    inputSignals.includes("search_field") ||
    Boolean(searchReveal) ||
    /search|query|find/.test(lowerText);
  const hasFileUpload = inputSignals.includes("file_input") || /upload|attachment|avatar/.test(lowerText);
  const hasRedirect =
    lowerLinks.some((item) => /redirect|return|next=|url=|continue/.test(item)) ||
    lowerActions.some((item) => /redirect|return|next=|url=|continue/.test(item));

  let pageType = "generic_page";
  const surfaces = [];
  const recommendations = [];

  if (hasPassword || /login|sign in|authenticate/.test(lowerText) || /login|sign in/.test(lowerTitle)) {
    pageType = "login_page";
    surfaces.push("authentication");
    recommendations.push({
      scenario_id: "brute_force_login",
      confidence: hasPassword && hasUserField ? 0.95 : 0.72,
      rationale: "Detected login-oriented text plus password and/or account inputs.",
      source: "dom_heuristic",
      supporting_signals: ["login_page", ...(hasPassword ? ["password_field"] : []), ...(hasUserField ? ["username_field"] : [])],
      pre_action_selector: loginReveal?.locator_hint || undefined,
      target_selector: loginSubmit?.locator_hint || undefined,
    });
  }

  if (hasSearch) {
    if (pageType === "generic_page") {
      pageType = "search_page";
    }
    surfaces.push("query_input");
    recommendations.push({
      scenario_id: "sql_injection_probe",
      confidence: 0.78,
      rationale: "Detected search or query-oriented inputs that could support bounded SQLi targeting.",
      source: "dom_heuristic",
      supporting_signals: ["query_form", "search_field"],
      pre_action_selector: searchReveal?.locator_hint || undefined,
    });
    recommendations.push({
      scenario_id: "reflected_xss_probe",
      confidence: 0.74,
      rationale: "Detected text input surfaces likely to reflect user-supplied content or results.",
      source: "dom_heuristic",
      supporting_signals: ["form_page", "text_input", "search_field"],
      pre_action_selector: searchReveal?.locator_hint || undefined,
    });
  }

  if (hasFileUpload) {
    pageType = pageType === "generic_page" ? "upload_page" : pageType;
    surfaces.push("file_upload");
    recommendations.push({
      scenario_id: "file_upload_probe",
      confidence: 0.88,
      rationale: "Detected file input or upload-oriented wording on the current page.",
      source: "dom_heuristic",
      supporting_signals: ["upload_page", "file_input"],
      pre_action_selector: uploadReveal && !fileInput ? uploadReveal.locator_hint : undefined,
      target_selector: fileInput?.locator_hint || undefined,
    });
  }

  if (hasRedirect) {
    surfaces.push("redirect_navigation");
    recommendations.push({
      scenario_id: "open_redirect_probe",
      confidence: 0.69,
      rationale: "Detected redirect-like parameters or return-navigation indicators.",
      source: "dom_heuristic",
      supporting_signals: ["return_flow", "redirect_link"],
      pre_action_selector: redirectReveal?.locator_hint || undefined,
      target_parameter: "to",
    });
  }

  return {
    page_type: pageType,
    confidence: recommendations.length > 0 ? Math.max(...recommendations.map((item) => item.confidence)) : 0.35,
    recommended_scenarios: recommendations,
    candidate_interaction_surfaces: Array.from(new Set(surfaces)),
    heuristic_summary: {
      page_url: pageUrl,
      title,
      has_password_input: hasPassword,
      has_username_input: hasUserField,
      login_reveal_selector: loginReveal?.locator_hint || null,
      login_submit_selector: loginSubmit?.locator_hint || null,
      has_search_surface: hasSearch,
      search_reveal_selector: searchReveal?.locator_hint || null,
      upload_reveal_selector: uploadReveal?.locator_hint || null,
      upload_target_selector: fileInput?.locator_hint || null,
      redirect_reveal_selector: redirectReveal?.locator_hint || null,
      has_file_upload_surface: hasFileUpload,
      has_redirect_signal: hasRedirect,
      candidate_element_count: candidateElements.length,
    },
    summary:
      recommendations.length > 0
        ? `Detected ${recommendations.length} generic scenario candidates from DOM heuristics.`
        : "No strong generic scenario signals were detected; planner can still fall back to bounded defaults.",
  };
}

async function analyzePage({ targetUrl, templateId, outputDir, runId, storageStatePath, analysisLabel }) {
  const safeUrl = assertLocalHttpUrl(targetUrl);
  const browser = await chromium.launch({ headless: true });
  const storageStateExists = storageStatePath
    ? await fs.stat(storageStatePath).then(() => true).catch(() => false)
    : false;
  const context = await browser.newContext(
    storageStateExists ? { storageState: storageStatePath } : {}
  );
  const page = await context.newPage();

  try {
    const response = await page.goto(safeUrl, { waitUntil: "domcontentloaded", timeout: 20_000 });
    await page.waitForLoadState("networkidle", { timeout: 10_000 }).catch(() => {});

    const title = await page.title();
    const bodyText = clip(await page.locator("body").innerText().catch(() => ""), 2400);
    const candidateElements = await extractCandidateElements(page);
    const linkHrefs = await page.locator("a[href]").evaluateAll((nodes) =>
      nodes.slice(0, 24).map((node) => node.getAttribute("href") || "").filter(Boolean)
    );
    const formActions = await page.locator("form").evaluateAll((nodes) =>
      nodes.slice(0, 12).map((node) => node.getAttribute("action") || "").filter(Boolean)
    );

    await fs.mkdir(outputDir, { recursive: true });
    const safeAnalysisLabel = String(analysisLabel || "page-analysis").replace(/[^a-z0-9_-]+/gi, "-");
    const screenshotPath = path.join(outputDir, `${templateId}-${runId}-${safeAnalysisLabel}.png`);
    await page.screenshot({ path: screenshotPath, fullPage: false });

    const heuristic = buildHeuristicAnalysis({
      pageUrl: page.url(),
      title,
      bodyText,
      candidateElements,
      linkHrefs,
      formActions,
    });

    const domSummary = {
      title,
      body_text_excerpt: bodyText,
      link_hrefs: linkHrefs.slice(0, 24),
      form_actions: formActions.slice(0, 12),
      candidate_elements: candidateElements.slice(0, 24),
      input_count: candidateElements.filter((item) => item.element_kind === "input" || item.element_kind === "file_input").length,
      button_count: candidateElements.filter((item) => item.element_kind === "button").length,
      link_count: candidateElements.filter((item) => item.element_kind === "link").length,
    };

    return {
      ok: true,
      page_url: page.url(),
      page_title: title,
      template_id: templateId,
      status_code: response?.status() || 200,
      screenshot_path: screenshotPath,
      visible_text_excerpt: bodyText,
      candidate_elements: candidateElements,
      dom_summary: domSummary,
      ...heuristic,
    };
  } finally {
    await context.close().catch(() => {});
    await browser.close();
  }
}

async function main() {
  const targetUrl = process.env.CYBERBOX_TARGET_URL;
  const templateId = process.env.CYBERBOX_TARGET_TEMPLATE || "unknown";
  const runId = process.env.CYBERBOX_RUN_ID || "manual";
  const outputDir =
    process.env.CYBERBOX_OUTPUT_DIR ||
    path.resolve(process.cwd(), "test-results", "red-agent");
  const storageStatePath = process.env.CYBERBOX_BROWSER_STORAGE_STATE || "";
  const analysisLabel = process.env.CYBERBOX_ANALYSIS_LABEL || "page-analysis";

  if (!targetUrl) {
    throw new Error("CYBERBOX_TARGET_URL is required.");
  }

  const result = await analyzePage({
    targetUrl,
    templateId,
    outputDir,
    runId,
    storageStatePath,
    analysisLabel,
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
});
