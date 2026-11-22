# Hack Brasil 2026 — Official Submission Package (`docs/SUBMISSION_PACK.md`)

**Product:** **ScriptKitty Live**  
**Autonomous Security Agent:** **PatchCat**  
**Primary Capability:** **ChainBreak** (Deterministic Policy-Graph & Attack-Path Reachability)  
**Companion Capabilities:** Continuous Security Audit · Verified Remediation · Agent & MCP Security  
**Target Competition Repository:** `https://github.com/andrecodexvictor/scriptkitty-live-hackbrasil-2026` *(Created `2026-11-21T12:22:37Z`, `private: false`, `fork: false` — push gated on [`PROVENANCE.md`](../PROVENANCE.md) & Section 5 below)*  
**Public Live Preview URL:** `[Pending Public Deploy — HUMAN_APPROVAL_REQUIRED]`  
**Public Team Video URL:** `[Pending 4-Person Team Video Upload — HUMAN_APPROVAL_REQUIRED]`

> [!WARNING]
> **DO NOT SUBMIT THE PORTAL FORM UNTIL ALL ITEMS IN SECTION 5 ARE COMPLETED BY THE HUMAN TEAM.**  
> In compliance with Hack Brasil 2026 rules and our honest evidence discipline ([`CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md)):
> 1. The competition repository (`scriptkitty-live-hackbrasil-2026`) must receive a human-approved clean push disclosing pre-event (`2026-07-25`) vs. Hack Brasil 2026 provenance ([`../PROVENANCE.md`](../PROVENANCE.md)).
> 2. The public HTTPS preview (`PUBLIC_DEMO_URL`) must be deployed and verified by a human operator.
> 3. The official pitch video (`<= 180s`, **2m30s / 150s target**) must include **all 4 team members appearing on camera and speaking** alongside the live screen capture (`demo-video/scriptkitty-live-poc-demo-2m30s.mp4`).

---

## 1. Copy-Paste Portal Form Texts — Português (PT-BR)

### 1.1 Nome do Projeto & Tagline (PT-BR)
- **Nome do Produto:** **ScriptKitty Live (PatchCat)**
- **Tagline Curta (até 140 caracteres):**  
  `Segurança que enxerga o caminho inteiro do ataque: verificação determinística de grafos (ChainBreak), remediação verificada e defesa MCP.`

### 1.2 Problema & Solução (PT-BR)
> **O Problema:** Equipes de engenharia enfrentam dois pontos cegos críticos: (1) scanners de segurança baseados apenas em LLM geram excesso de falsos positivos sem prova determinística e sugerem correções que quebram fluxos legítimos; (2) a adoção acelerada de agentes autônomos e ferramentas Model Context Protocol (MCP) cria rotas de ataque multi-salto invisíveis — onde uma única permissão em uma ferramenta MCP conecta uma identidade externa a dados restritos de pagamento/PII e a um destino externo não autorizado.
>
> **A Solução — ScriptKitty Live & PatchCat:** O **ScriptKitty Live** coloca o agente defensivo **PatchCat** no centro de um pipeline determinístico e *fail-closed* em modo **`LAB`**:
> 1. **ChainBreak (Grafo Determinístico de Políticas e Caminhos de Ataque):** Modela identidades, agentes, ferramentas MCP, serviços, ativos de dados e destinos externos. Em vez de palpites probabilísticos, comprova matematicamente caminhos de risco (`PATH_VALIDATED`, nunca exagerando como exploração em produção `EXPLOIT_CONFIRMED`), citando a linha exata da política (`sourceRef`) e o hash SHA-256 (`inputSha256`).
> 2. **Remediação Verificada (Contrafactual e AppSec):** Sintetiza a alteração mínima de permissão (`REMOVE_EDGE`) que reduz caminhos proibidos de `1 -> 0` preservando `3/3` operações legítimas de negócio, além de reproduzir, corrigir e testar regressão em vulnerabilidades reais de código (`CWE-89` SQLi, `CWE-78` CMDi, `CWE-639` IDOR) em subprocesso Node offline com variáveis limpas (`ProcessSandbox`: `NO_PROXY=*`, `shell: false`, limite de `1 MiB` — não isolamento de SO/contêiner) e *rollback* automático.
> 3. **Auditoria Contínua & Release Gate Tripartite:** Sela cada evidência em árvores **Merkle RFC 8785** vinculadas ao commit SHA e exige **Separação Tripartite de Deveres** ($A_{\text{disc}} \ne A_{\text{veri}} \ne A_{\text{auth}}$), rejeitando qualquer tentativa de auto-certificação (`E_SOD_SELF_CERTIFICATION`).
> 4. **Segurança para Agentes & MCP:** Servidor MCP Streamable HTTP em loopback (`127.0.0.1:3847/mcp`) com autenticação Bearer (`401`), allowlist de `Origin` (`403`), isolamento multi-tenant (`FORBIDDEN`), **Runtime Guardian** (pinning SHA-256 contra *tool poisoning*, proteção contra *prompt injection* e delegação HMAC-SHA256) e sandbox **Kali Linux LAB** (`LAB_SYNTHETIC` sem shell bruto).

### 1.3 Diferenciais Técnicos & Transparência de Engenharia (PT-BR)
> - **Determinismo Antes de IA Consultiva:** Toda validação de grafo, hash e reprodução roda em código determinístico. A revisão consultiva de risco opera apenas sobre resumos sanitizados (`sanitizedStateDigest`), nunca define severidade `P0` sozinha e escala para aprovação humana (`PENDING_REVIEW`).
> - **100% Reproduzível Localmente em 1 Comando:** **640 testes automatizados distintos** (`499` testes unitários e de integração TS em 16 pacotes/apps + `121` verificações TS em 7 tiers = `620` TS nos `17` workspaces + `20` Python; incl. `8/8` em `apps/ui`) e lançador ao vivo (`npm run demo:live`) rodando UI + MCP Streamable HTTP em `127.0.0.1`.
> - **Governança e Limites Honestos (`LAB`):** Zero auto-merge (`mergeAllowed: false`), zero auto-deploy (`deployAllowed: false`), integrações externas sem chave explicitamente reportadas como `NOT_CONFIGURED`, e proveniência pré-evento vs. Hack Brasil 2026 integralmente auditada em `PROVENANCE.md`.

---

## 2. Copy-Paste Portal Form Texts — English (EN)

### 2.1 Project Name & Tagline (EN)
- **Product Name:** **ScriptKitty Live (PatchCat)**
- **Short Tagline (<= 140 chars):**  
  `Security that sees the whole attack path: deterministic policy-graph verification (ChainBreak), verified remediation, and MCP runtime defense.`

### 2.2 Problem & Solution (EN)
> **The Problem:** Modern engineering teams face two compounding security blind spots: (1) LLM-only security scanners flood developers with unverified alerts and speculative patches that break valid business workflows; (2) autonomous agents and Model Context Protocol (MCP) tools introduce multi-hop permission risks where a single rollout grant can bridge an external identity to restricted payment/PII data and an unauthorized external sink.
>
> **The Solution — ScriptKitty Live & PatchCat:** **ScriptKitty Live** pairs **PatchCat** (our autonomous defensive security operator) with a deterministic, fail-closed verification architecture operating in isolated **`LAB`** mode:
> 1. **ChainBreak (Deterministic Policy-Graph & Attack-Path Reachability):** Models identities, agents, MCP tools, APIs, services, data assets, and external sinks. ChainBreak proves multi-hop attack chains deterministically (`PATH_VALIDATED`, never overclaiming live production exploitation `EXPLOIT_CONFIRMED`), citing exact policy `sourceRef` lines and SHA-256 input digests (`inputSha256`).
> 2. **Verified Remediation (Counterfactual Graph & AppSec Code Fixes):** Synthesizes the minimal permission removal (`REMOVE_EDGE`) that drops forbidden attack paths from `1 -> 0` while preserving `3/3` legitimate business operations, alongside env-scrubbed offline Node subprocess sandbox (`ProcessSandbox`: `NO_PROXY=*`, `shell: false`, `1 MiB` output cap — rather than OS/container isolation) reproduction and AST patching for `CWE-89` (SQLi), `CWE-78` (CMDi), and `CWE-639` (IDOR) with automatic rollback on regression.
> 3. **Continuous Security Audit & Tri-Party Release Gate:** Seals every finding, diff, and gate decision in RFC 8785 SHA-256 binary Merkle trees bound to the Git commit SHA, enforcing mathematical Tri-Party Separation of Duties ($A_{\text{disc}} \ne A_{\text{veri}} \ne A_{\text{auth}}$) and rejecting agent self-certification (`E_SOD_SELF_CERTIFICATION`).
> 4. **Agent & MCP Security:** Exposes capabilities over loopback MCP Streamable HTTP (`127.0.0.1:3847/mcp`) with Bearer auth (`401`), strict `Origin` allowlisting (`403`), and server-derived tenant isolation (`FORBIDDEN`), protected by **Runtime Guardian** (`170/170` tests against tool poisoning, prompt injection, path traversal, and confused-deputy escalation) and an allowlisted **Kali Linux LAB Verification Sandbox** (`LAB_SYNTHETIC`, static `--` argv, zero raw shell).

### 2.3 Technical Differentiation & Engineering Honesty (EN)
> - **Deterministic Proof Before Advisory AI:** Graph reachability, SHA-256 receipts, and sandbox reproducers run deterministically first. Advisory risk review receives only secret-scrubbed digests (`sanitizedStateDigest`), never assigns `P0` alone, and escalates to mandatory human review (`PENDING_REVIEW`).
> - **One-Command Local Reproducibility:** **640 distinct automated tests** (`499` package/app TS unit+integration + `121` 7-tier TS verification = `620` TS across `17` workspaces + `20` Python; incl. `8/8` in `apps/ui`) and a one-command live loopback stack (`npm run demo:live`).
> - **Transparent Provenance & Non-Production Locks:** `mergeAllowed: false` and `deployAllowed: false` are permanently enforced; unconfigured external APIs report `NOT_CONFIGURED` honestly; and pre-event (`2026-07-25`) vs. Hack Brasil 2026 engineering is transparently documented in `PROVENANCE.md`.

---

## 3. 4-Person Team Pitch & Demo Video Script (`<= 180s` / Target `150s` = `2m30s`)

> [!IMPORTANT]
> **Hack Brasil Video Rule:** Every member of the 4-person team MUST appear on camera and speak during the video, and the total duration MUST be **`<= 180 seconds`** (our synchronized screen-recording master `demo-video/scriptkitty-live-poc-demo-2m30s.mp4` is exact **`150.0 seconds` / `2m30s`**).  
> Record each speaker in a clean picture-in-picture (PiP) webcam overlay or split-screen synchronized with the 6 acts of `demo-video/scriptkitty-live-poc-demo-2m30s.mp4` below.

### Speaker Roster (4 Team Members — All Appear on Camera & Speak)
- **Membro 1 (`0:00 – 0:35` · `35s`):** Visão do Produto, Problema e Conexão Ao Vivo no Console **ScriptKitty Live / PatchCat** (`payments-lab/baseline`).
- **Membro 2 (`0:35 – 1:15` · `40s`):** Motor **ChainBreak**, Detecção Multi-Salto no `unsafe-rollout` (`PATH_VALIDATED`) e Recibo Criptográfico SHA-256.
- **Membro 3 (`1:15 – 1:55` · `40s`):** Revisão Humana Consultiva (`PENDING_REVIEW`), Transporte MCP Streamable HTTP *Fail-Closed* (`401`/`403`/`FORBIDDEN`) e **Remediação Verificada** (`1 -> 0` caminhos, `3/3` fluxos preservados).
- **Membro 4 (`1:55 – 2:30` · `35s`):** Defesa em Profundidade (**AppSec Lab**, **Runtime Guardian** e **Sandbox Kali LAB**), Release Gate Tripartite ($A_{\text{disc}} \ne A_{\text{veri}} \ne A_{\text{auth}}$), Custódia Merkle RFC 8785 e Encerramento.

---

### Roteiro Cronometrado Palavra por Palavra (PT-BR — 150 Segundos / 2m30s)

#### Turno 1 — Membro 1 em Câmera (`0:00 – 0:35`)
- **Cena na Tela:** Card de abertura **ScriptKitty Live / PatchCat** (`#0C121A` dark graphite + `#79B7F3` ice-blue + `#64CDB1` emerald) -> Terminal `security.status` (`mode: LAB`, `mergeAllowed: false`, `deployAllowed: false`) -> Console Web conectado em `MODE: LIVE MCP HTTP` no cenário `payments-lab/baseline`.
- **Fala do Membro 1 (em câmera):**
  > *"Olá jurados do Hack Brasil! Eu sou [Nome do Membro 1] e este é o **ScriptKitty Live**, operado pelo nosso agente defensivo **PatchCat**.  
  > Scanners comuns baseados apenas em IA geram dezenas de alertas sem prova e não enxergam rotas de ataque que atravessam agentes autônomos e ferramentas MCP.  
  > O ScriptKitty Live resolve isso com engenharia determinística em modo `LAB` isolado — onde auto-merge e deploy permanecem travados por padrão.  
  > Aqui no console conectado ao vivo via MCP HTTP em loopback, o cenário `baseline` comprova **zero caminhos proibidos** e mantém todas as **três operações legítimas** funcionando."*

#### Turno 2 — Membro 2 em Câmera (`0:35 – 1:15`)
- **Cena na Tela:** Clique ao vivo na aba `unsafe-rollout` (`#tab-unsafe-rollout`) -> Grafo **ChainBreak** destaca a rota crítica em vermelho/coral (`#F08589`) -> Tabela de saltos e recibo criptográfico aberto (`#details-receipt-chainbreak`).
- **Fala do Membro 2 (em câmera):**
  > *"Eu sou [Nome do Membro 2] e vou mostrar o nosso motor principal: o **ChainBreak**.  
  > Quando simulamos um rollout candidato que adiciona uma única permissão de leitura na ferramenta MCP `report-exporter`, o PatchCat entra em alerta imediato.  
  > O ChainBreak comprova matematicamente o caminho completo de três saltos — do agente de suporte até o vazamento de dados restritos de pagamento para um destino externo — violando a política `NO_RESTRICTED_DATA_EXTERNAL_TRANSFER` com severidade `P1`.  
  > Reparem no rigor técnico: cada salto aponta para a linha exata da política (`sourceRef`) e para o hash SHA-256 do grafo, emitindo `PATH_VALIDATED` — sem jamais inventar uma exploração em produção."*

#### Turno 3 — Membro 3 em Câmera (`1:15 – 1:55`)
- **Cena na Tela:** Painel **Revisão Humana de Risco** (`PENDING_REVIEW`) -> Captura de terminal do servidor MCP Streamable HTTP (`HTTP 401`, `HTTP 403`, bloqueio cross-tenant `FORBIDDEN`, replay idempotente) -> Clique em **Preview Fix Diff** (`#btn-pr-suggest`) indo para `payments-lab/remediated` (`1 -> 0` caminhos, `3/3` operações).
- **Fala do Membro 3 (em câmera):**
  > *"Aqui é [Nome do Membro 3]. No ScriptKitty Live, a triagem por IA é estritamente consultiva sobre resumos sanitizados: ela nunca define severidade P0 sozinha e escala para aprovação humana obrigatória (`PENDING_REVIEW`).  
  > Todo esse motor roda sobre um servidor **MCP Streamable HTTP fail-closed** em loopback: chamadas sem token recebem `HTTP 401`, origens não autorizadas recebem `HTTP 403` e leituras entre tenants diferentes são bloqueadas na hora.  
  > E na **Remediação Verificada**, o PatchCat sintetiza o diff contrafactual mínimo — removendo apenas a aresta excessiva `e-rollout-exporter-read-pii`. O grafo comprova na hora: os caminhos proibidos caem de **1 para 0**, preservando **3 de 3** fluxos legítimos de negócio."*

#### Turno 4 — Membro 4 em Câmera (`1:55 – 2:30`)
- **Cena na Tela:** Grid triplo de terminal (AppSec Lab corrigindo SQLi/CMDi/IDOR + **Runtime Guardian** `170/170` + **Sandbox Kali LAB** bloqueando `evil.example`, `169.254.169.254` e flag injection) -> Toggle **Self-Certification** no Release Gate mostrando `REJECT` (`E_SOD_SELF_CERTIFICATION`) -> Restauração dos 3 papéis mostrando `PASS` + raiz Merkle RFC 8785 -> Card final com contagens reais de testes.
- **Fala do Membro 4 (em câmera):**
  > *"Eu sou [Nome do Membro 4]. Nossa defesa vai do código ao runtime: no laboratório AppSec, corrigimos SQL Injection, Command Injection e IDOR com rollback automático; o **Runtime Guardian** protege servidores MCP com 170 testes passando; e o **Sandbox Kali LAB** opera com argumentos estáticos sem shell, bloqueando domínios fora de escopo e metadados de nuvem.  
  > Por fim, no **Release Gate**, se um agente tenta aprovar o próprio trabalho, a **Separação Tripartite de Deveres** rejeita na hora. Com três papéis independentes, a entrega é selada em árvore **Merkle RFC 8785**, mantendo o humano no comando final.  
  > **ScriptKitty Live e PatchCat**: segurança determinística, verificável e pronta para o Hack Brasil 2026. Obrigado!"*

---

## 4. Technical Metadata of Local Base Video (`demo-video/`)

- **Video File:** `demo-video/scriptkitty-live-poc-demo-2m30s.mp4`
- **Subtitles File (PT-BR):** `demo-video/scriptkitty-live-poc-demo-2m30s.srt`
- **Extracted Verification Keyframes:** `demo-video/frames/01-0m10s-architecture-status.png` .. `06-2m20s-quality-gate-merkle-zenpr.png`
- **Target Specs Verified by `ffprobe`:** `150.0s` (`<= 180s`), `1920x1080`, `30 fps`, `H.264 (yuv420p)`, `AAC 48 kHz stereo`.

---

## 5. Explicit Human Approval Checklist (Mandatory Before Submission)

A human team lead MUST verify and check off every item below before pushing code, deploying a public URL, or submitting the Hack Brasil 2026 form:

- [ ] **1. Provenance & Clean Export Approval (`PROVENANCE.md`):**
  - Reviewed [`../PROVENANCE.md`](../PROVENANCE.md) confirming the honest split between the pre-event prototype (`2026-07-25`, commits `b1c9e2b`, `c976486`, `f1c334f` from `Script-kitty.git`) and the Hack Brasil 2026 engineering (`2026-11-06`–`2026-11-21`).
  - Staged and reviewed the clean export directory (`PROVENANCE.md` §4) so zero `.env` files, zero secrets, and zero unintended pre-event history artifacts are pushed without disclosure.
- [ ] **2. Push to Official Hack Brasil 2026 Repository (`HUMAN_APPROVAL_REQUIRED`):**
  - Pushed the human-approved commit to `https://github.com/andrecodexvictor/scriptkitty-live-hackbrasil-2026.git` (created `2026-11-21T12:22:37Z`, post Nov 4 21:00 BRT, public, non-fork).
  - Verified that `LICENSE` (MIT), `PROVENANCE.md`, `NOTICE.md`, `README.md`, and `docs/CLAIMS_MATRIX.md` are visible at the root/docs of the public GitHub repository.
- [ ] **3. Public HTTPS Web Preview Deployment (`HUMAN_APPROVAL_REQUIRED`):**
  - Deployed the static frontend preview (`vercel-app/dist` or `apps/ui/dist`) to a public HTTPS URL.
  - Set `PUBLIC_DEMO_URL=<https://...>` and confirmed it loads over HTTPS with zero console errors across desktop and mobile viewports ( note: the public static preview runs in deterministic `LAB` browser mode; the live MCP HTTP server always remains loopback-only on `127.0.0.1`).
- [ ] **4. 4-Person Team Camera Video Recording & Upload (`HUMAN_APPROVAL_REQUIRED`):**
  - Recorded all **4 team members appearing on camera and speaking** following the `150s` (`<= 180s`) script in Section 3 above.
  - Verified final video duration is **`<= 180 seconds`** via `ffprobe`.
  - Uploaded the video to a public link (YouTube Unlisted/Public, Vimeo, or Loom) and set `PUBLIC_VIDEO_URL=<https://...>`.
- [ ] **5. Final Quality Gates Run (`npm run gates`):**
  - Executed `npm run gates` after completing items 2–4 so [`../evidence/gate-report.json`](../evidence/gate-report.json) records the final `verifiedSha` and gate statuses `G00` through `G14`.
- [ ] **6. Hack Brasil Portal Form Submission:**
  - Pasted the PT-BR / EN texts from Sections 1–2, the GitHub URL (`https://github.com/andrecodexvictor/scriptkitty-live-hackbrasil-2026`), the live HTTPS demo URL, and the `<= 180s` 4-person team video URL into the Hack Brasil submission form.
