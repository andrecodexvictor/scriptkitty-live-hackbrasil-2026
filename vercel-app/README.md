# ScriptKitty Live — Static Vercel Preview

Public Hack Brasil 2026 showcase and interactive ChainBreak scenario explorer for **ScriptKitty Live** and **PatchCat**.

- **Repository:** `https://github.com/andrecodexvictor/scriptkitty-live-hackbrasil-2026`
- **Mode:** `SIMULATED LAB DATA` (static client-side preview over synthetic `payments-lab` fixtures; zero live targets scanned; zero autonomous merge or deploy).
- **Live Loopback Stack:** Run `npm run demo:live` from the monorepo root to launch the live PatchCat UI (`http://127.0.0.1:5173`) and loopback MCP Streamable HTTP server (`http://127.0.0.1:3847/mcp`).

## Local development

Use Node.js 24 and run these commands from `vercel-app`.

```sh
npm ci --no-audit --no-fund
npm run build
npm run preview -- --host 127.0.0.1
```

## CI and Vercel deployment

The [Vercel workflow](../.github/workflows/vercel.yml) tests and builds the showcase on pull requests and pushes to `main`. Review [PROVENANCE.md](../PROVENANCE.md) and the [submission checklist](../docs/SUBMISSION_PACK.md#5-explicit-human-approval-checklist-mandatory-before-submission) with the team before publishing.

### Publish from Vercel

For a Vercel project connected to the repository root, leave **Root Directory** at its default (the repository root) and use Node.js `24.x`. The [root Vercel config](../vercel.json) installs and builds the showcase and publishes `vercel-app/dist`. Select the latest commit on `main` when deploying from the Vercel dashboard.

### Publish from GitHub Actions

1. Set the Vercel project's **Root Directory** to `vercel-app` and **Node.js Version** to `24.x`. The build configuration in that directory disables Vercel's automatic Git deployments.
2. In GitHub, create the `vercel-production` environment, restrict its deployment branch to `main`, and add `VERCEL_TOKEN`, `VERCEL_ORG_ID`, and `VERCEL_PROJECT_ID` as environment secrets. Use a Vercel token with access to the project.
3. Open **Actions → Vercel → Run workflow** and select `main`. Check the deployment URL in the **Publish prebuilt output** step and verify that the showcase loads over HTTPS.
