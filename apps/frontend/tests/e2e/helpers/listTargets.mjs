import { fetchManagedTargets } from "./resolveTarget.mjs";

async function main() {
  const apps = await fetchManagedTargets();
  const runningApps = apps.filter((app) => app?.status === "running");

  if (runningApps.length === 0) {
    console.log("No running managed apps found.");
    return;
  }

  console.log("Running managed targets:");
  for (const app of runningApps) {
    console.log(`- ${app.app_id} | ${app.name} | ${app.template_id} | ${app.target_url}`);
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});

