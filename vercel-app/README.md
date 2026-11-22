# ScriptKitty Live — Static Vercel Preview

Public Hack Brasil 2026 showcase and interactive ChainBreak scenario explorer for **ScriptKitty Live** and **PatchCat**.

- **Repository:** `https://github.com/andrecodexvictor/scriptkitty-live-hackbrasil-2026`
- **Mode:** `SIMULATED LAB DATA` (static client-side preview over synthetic `payments-lab` fixtures; zero live targets scanned; zero autonomous merge or deploy).
- **Live Loopback Stack:** Run `npm run demo:live` from the monorepo root to launch the live PatchCat UI (`http://127.0.0.1:5173`) and loopback MCP Streamable HTTP server (`http://127.0.0.1:3847/mcp`).

## Local Development

```powershell
npm install; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
npm run build; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
npm run preview
```
