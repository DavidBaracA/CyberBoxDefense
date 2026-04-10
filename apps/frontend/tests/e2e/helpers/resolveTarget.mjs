import process from "node:process";

const DEFAULT_BACKEND_URL = process.env.CYBERBOX_BACKEND_URL || "http://localhost:8000";

function assertLocalHttpUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Managed target URL is invalid: ${url}`);
  }

  const isLocalHost = ["localhost", "127.0.0.1"].includes(parsed.hostname);
  if (!isLocalHost) {
    throw new Error(
      `Refusing to run Playwright against non-local target host "${parsed.hostname}".`
    );
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error(`Unsupported target protocol "${parsed.protocol}".`);
  }

  return parsed.toString();
}

export async function fetchManagedTargets(backendUrl = DEFAULT_BACKEND_URL) {
  const response = await fetch(`${backendUrl}/apps`);
  if (!response.ok) {
    throw new Error(`Unable to fetch managed apps from ${backendUrl}/apps (${response.status}).`);
  }

  const payload = await response.json();
  return Array.isArray(payload) ? payload : [];
}

export async function resolveManagedTarget(backendUrl = DEFAULT_BACKEND_URL) {
  const apps = await fetchManagedTargets(backendUrl);
  const runningApps = apps.filter((app) => app?.status === "running");

  if (runningApps.length === 0) {
    throw new Error(
      "No running platform-managed vulnerable apps were found. Deploy and start one before running Playwright smoke tests."
    );
  }

  const requestedAppId = process.env.CYBERBOX_TARGET_APP_ID?.trim();
  if (requestedAppId) {
    const matched = runningApps.find((app) => app?.app_id === requestedAppId);
    if (!matched) {
      const known = runningApps.map((app) => `${app.app_id}:${app.name}`).join(", ");
      throw new Error(
        `Requested CYBERBOX_TARGET_APP_ID="${requestedAppId}" is not a running managed app. Running targets: ${known}`
      );
    }

    return {
      ...matched,
      target_url: assertLocalHttpUrl(matched.target_url),
    };
  }

  if (runningApps.length > 1) {
    const known = runningApps.map((app) => `${app.app_id}:${app.name}`).join(", ");
    throw new Error(
      `Multiple running managed apps found. Set CYBERBOX_TARGET_APP_ID to one of: ${known}`
    );
  }

  return {
    ...runningApps[0],
    target_url: assertLocalHttpUrl(runningApps[0].target_url),
  };
}

export function getTemplateSmokeHints(templateId) {
  const normalized = String(templateId || "").toLowerCase();
  if (normalized === "juice_shop") {
    return {
      expectedText: /juice shop|search|account/i,
      routes: ["/", "/#/login"],
    };
  }

  if (normalized === "dvwa") {
    return {
      expectedText: /dvwa|damn vulnerable web application|login/i,
      routes: ["/", "/login.php"],
    };
  }

  if (normalized === "crapi") {
    return {
      expectedText: /crapi|login|signup/i,
      routes: ["/"],
    };
  }

  return {
    expectedText: null,
    routes: ["/"],
  };
}

