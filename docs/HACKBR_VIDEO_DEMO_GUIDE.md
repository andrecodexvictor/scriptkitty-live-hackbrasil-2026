# Guia de Gravação & Roteiro HackBR — Vídeo Demo ScriptKitty 2.0 (`PatchCat`)

**Idioma do Vídeo / Narração:** Português (PT-BR)  
**Duração Alvo:** **2 min 45 s** (janela ideal de 2 a 3 minutos para jurados HackBR)  
**Modo Demonstrado:** `LAB` (`productionTested=false`, `mergeAllowed=false`, `deployAllowed=false`)  
**Script Executado em Tela:** [`scripts/demo-wednesday.mjs`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/scripts/demo-wednesday.mjs)

---

## 1. Preparação Antes de Gravar (Setup de Tela & Ambiente)

1. **Verifique o build limpo antes de apertar REC:**
   ```bash
   npm run build
   node scripts/demo-wednesday.mjs
   ```
2. **Layout recomendado de gravação (1920×1080, zoom de fonte legível 15–16 pt):**
   - **Esquerda (60%):** Terminal integrado (PowerShell / Windows Terminal) com saída colorida/clara e comando pronto para rodar ao vivo.
   - **Direita (40%):** VS Code alternando entre 4 abas pré-abertas:
     1. [`fixtures/payments-lab/unsafe-rollout.json`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/fixtures/payments-lab/unsafe-rollout.json)
     2. [`packages/jev-judge/src/pipeline.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/jev-judge/src/pipeline.ts)
     3. [`packages/remediation-engine/src/lifecycle.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/lifecycle.ts)
     4. [`packages/kali-mcp-assessment/src/server.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/kali-mcp-assessment/src/server.ts)
3. **Regra de honestidade em tela:** Garanta que `TYPESAFE_API_KEY` esteja **desabilitada** (a menos que queira gravar modo `LIVE` explícito) para mostrar o comportamento transparente *fail-closed* (`providerStatus: "NOT_CONFIGURED"`, `decisionSource: "MOCK"`), reforçando maturidade de engenharia.

---

## 2. Storyboard Cronometrado & Script de Narração (0:00 – 2:45)

### Ato I (`0:00 – 0:30`): O Problema & A Visão ScriptKitty 2.0

* **Visual em Tela:**
  - Mostrar slide/título rápido ou [`README.md`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/README.md) com o mascote PatchCat + comando inicial de status no terminal (e/ou painel [`apps/ui`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/apps/ui/src/main.ts) rodando em `LAB DETERMINISTIC` / `LIVE MCP HTTP`).
  - **Callout visual:** *"90%+ falsos positivos em scanners LLM → Zero-Trust + Prova Determinística."*
* **Comando ao vivo no terminal (ou início do `demo-wednesday.mjs`):**
  ```bash
  node scripts/demo-wednesday.mjs
  ```
* **Narração (PT-BR):**
  > "Scanners de segurança baseados apenas em IA sofrem de dois problemas críticos: geram mais de 90% de falsos positivos e não protegem agentes autônomos e servidores MCP em tempo de execução.  
  > O **ScriptKitty 2.0** resolve isso unificando **AppSec** e **AgentSec** sob um princípio único: *nenhum achado entra sem prova empírica determinística e nenhum agente pode aprovar o próprio trabalho.*  
  > Aqui está o ambiente rodando em modo `LAB` isolado — perceba logo na saída `[1/10] security.status`: `mergeAllowed: false`, `deployAllowed: false`, `HARNESS2_EXPERIMENTS_ENABLED: false` e `kaliMcpStatus: NOT_CONFIGURED` por padrão *fail-closed*."

---

### Ato II (`0:30 – 1:15`): ChainBreak Graph & Detecção do `unsafe-rollout`

* **Visual em Tela:**
  - Focar na saída das etapas **`[2/10]` (`payments-lab/baseline`)** e **`[3/10]` (`payments-lab/unsafe-rollout`)** no terminal.
  - No editor à direita, destacar o grafo em [`fixtures/payments-lab/unsafe-rollout.json`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/fixtures/payments-lab/unsafe-rollout.json).
  - **Callout visual (Zoom no JSON):**
    - `baseline`: `forbiddenPaths: 0` | `legitimateOperationsCount: 3`
    - `unsafe-rollout`: `forbiddenPaths: 1` | `status: "PATH_VALIDATED"` (nunca `"EXPLOIT_CONFIRMED"`)
    - `edgeChain`: `identity:support-agent --[can_invoke]--> mcp_tool:report-exporter --[can_read]--> data_asset:customer-payment-pii --[transfers_data_to]--> destination:external-report-sink`
* **Narração (PT-BR):**
  > "No passo `[2/10]`, o motor determinístico **ChainBreak** analisa a arquitetura baseline do laboratório de pagamentos (`payments-lab/baseline`): **0 caminhos proibidos** e todas as **3 operações legítimas** intactas.  
  > No passo `[3/10]`, simulamos um *rollout* inseguro (`payments-lab/unsafe-rollout`): uma única permissão `can_read` na ferramenta MCP `report-exporter` cria uma cadeia completa até um *sink* externo de PII, violando a política `NO_RESTRICTED_DATA_EXTERNAL_TRANSFER`.  
  > Reparem na disciplina semântica: o status emitido é **`PATH_VALIDATED`** — alcançabilidade determinística ancorada no `sourceRef` exato da política e em `inputSha256` — e **nunca** `EXPLOIT_CONFIRMED`, garantindo honestidade técnica sem exageros."

---

### Ato III (`1:15 – 1:45`): JEV-as-a-Judge & Chamada MCP Streamable HTTP Invokta Ao Vivo

* **Visual em Tela:**
  - Focar na saída **`[4/10]` (`security.judge.evaluate`)** e **`[7/10]` (`MCP Streamable HTTP`)** (ou destacar o bloco `[7/10]` na rolagem) + mostrar rapidamente [`packages/security-actions/src/mcp-http.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/security-actions/src/mcp-http.ts).
  - **Callout visual:**
    - `jev.adjudication`: `decisionSource: "MOCK"`, `providerStatus: "NOT_CONFIGURED"`, `status: "PENDING_REVIEW"`, `p0DefinedByJevAlone: false`, `sanitizedStateDigest`
    - `failClosedChecks`: `crossTenantMcpRead: REJECTED (FORBIDDEN)`, `missingBearerToken: HTTP 401`, `disallowedOrigin: HTTP 403`, `idempotentReplay: true`
* **Narração (PT-BR):**
  > "Em seguida (`[4/10]`), o **JEV-as-a-Judge** avalia o estado sanitizado e resumido do grafo via digest SHA-256 (`sanitizedStateDigest`). Sem chave externa configurada, ele sinaliza explicitamente `providerStatus: NOT_CONFIGURED`, `decisionSource: MOCK`, escala para `PENDING_REVIEW` e bloqueia qualquer definição autônoma de severidade P0.  
  > Tudo isso é exposto via **MCP Streamable HTTP padrão Invokta em `127.0.0.1` (`[7/10]`)**: clientes oficiais listam as 5 capacidades `security.*`, obtêm exatamente o mesmo `analysisId` com `idempotentReplay: true`, enquanto tentativas de leitura *cross-tenant* (`FORBIDDEN`), injeção de `tenantId` no payload, falta de *Bearer token* (`HTTP 401`) ou `Origin` malicioso (`HTTP 403`) são bloqueadas *fail-closed*."

---

### Ato IV (`1:45 – 2:15`): Remediação Autônoma, Runtime Guardian & `@script-kitty/kali-mcp-assessment`

* **Visual em Tela:**
  - Focar nas etapas **`[5/10]` (`RemediationSpec`)**, **`[6/10]` (`remediated`)** mostrando `1 -> 0` caminhos proibidos e `3/3` operações legítimas preservadas, e **`[9/10]` (`@script-kitty/kali-mcp-assessment`)**.
  - Alternar rapidamente para a aba do VS Code com [`packages/kali-mcp-assessment/src/server.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/kali-mcp-assessment/src/server.ts) e [`packages/runtime-guardian/src/middleware.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/middleware.ts).
  - *Opcional (se gravar corte B-roll de 10s):* rodar um reprodutor real de SQLi/CMDi/IDOR em `apps/lab-app`:
    ```bash
    npm test --workspace=@script-kitty/lab-app
    ```
* **Callout visual:**
  - `RemediationSpec`: `REMOVE_EDGE` em `e-rollout-exporter-read-pii`, `requiresHumanApproval: true`, `autoApplyAllowed: false`
  - `@script-kitty/kali-mcp-assessment`: `mode: "LAB_SANDBOX_ONLY"`, `staticArgvSamples` com `--`, `liveContainerWithoutRuntime: "KALI_SANDBOX_UNAVAILABLE"`, `imdsSsrfBlocked`, `cliFlagInjectionBlocked`, `selfCertificationSodBlocked: "E_SOD_SELF_CERTIFICATION"`
* **Narração (PT-BR):**
  > "No ciclo de remediação (`[5/10]` e `[6/10]`), o engine propõe a mudança mínima contrafactual — remover apenas a aresta `e-rollout-exporter-read-pii` — derrubando os caminhos proibidos de **1 para 0**, preservando **3 de 3 operações legítimas** e exigindo aprovação humana (`autoApplyAllowed: false`).  
  > No código de AppSec do nosso `lab-app`, esse mesmo pipeline `FIND -> PROVE -> FIX -> VERIFY -> LEARN` corrige vulnerabilidades reais de SQL Injection, Command Injection e IDOR com *rollback* automático se houver regressão.  
  > E para proteção e verificação em laboratório (`[9/10]`): o pacote **`@script-kitty/kali-mcp-assessment`** opera em `LAB_SANDBOX_ONLY` com 4 ferramentas em *allowlist*, `argv` estático sem shell, proteção contra SSRF IMDS e injeção de flags, falha fechada em `LIVE_CONTAINER` (`KALI_SANDBOX_UNAVAILABLE` sem container host) e envelopes **`RuntimeGuardian`** (`wrapMcpServer`, tokens HMAC e Tri-Party SoD) executando em `LAB_SIMULATION` com raiz Merkle verificada — além do `Dockerfile.kali-sandbox` rootless (`65532:65532`), perfil seccomp `SCMP_ACT_ERRNO` e `docker-compose.kali-lab.yml` isolado."

---

### Ato V (`2:15 – 2:45`): Quality Gate Zero-Trust, PatchCat Orchestrator (`ZenPR` + `EvidenceLedger`) & Encerramento

* **Visual em Tela:**
  - Focar nas etapas **`[8/10]` (`quality-gate-and-delivery`)**, **`[9/10]` (`kali-mcp-assessment.summary`)**, **`[10/10]` (`zenpr-advisory-and-evidence-ledger`)** e no banner final `DEMO RESULT: ALL 10 STAGES PASSED CLEANLY IN ISOLATED LAB MODE (EXIT CODE 0)`.
  - **Callout visual:**
    - `qualityGateTriPartyPass`: `verdict: "PASS"`, `sodValid: true`
    - `qualityGateSelfCertReject`: `verdict: "REJECT"` (`E_SOD_SELF_CERTIFICATION`)
    - `zenpr.advisory.v1` + `evidence.merkle.bundle.v1`: `forbiddenPathDeltaSummary: "1 -> 0"`, `legitimateOperationsSummary: "3/3"`, `inclusionProofValid: true`, `policyMutationBlocked: "E_POLICY_MUTATION_FORBIDDEN"`, `unverifiedAiProseBlocked: "UNVERIFIED_AI_PROSE_REJECTED"`
    - `factoryDeliveryV1` & `zenPrBundle`: `eligible: true`, `stage: "approved"`, **`mergeAllowed: false`**, **`deployAllowed: false`**
* **Narração (PT-BR):**
  > "Em `[8/10]`, `[9/10]` e `[10/10]`, todo o ciclo é selado pelo **`@script-kitty/patchcat-orchestrator`** e pelo **`@script-kitty/evidence`** (`EvidenceLedger`) em cadeias RFC 8785 e pacotes Merkle binários (`evidence.merkle.bundle.v1`) com prova criptográfica de inclusão (`inclusionProofValid: true`).  
  > O **Quality Gate determinístico** e o orquestrador validam a **Separação Tripartite de Deveres** (`A_disc != A_veri != A_auth`) e bloqueiam prosa de LLM não verificada (`UNVERIFIED_AI_PROSE_REJECTED`), leitura *cross-tenant* (`TENANT_ISOLATION_VIOLATION`) e mutação de política (`E_POLICY_MUTATION_FORBIDDEN`).  
  > Mesmo quando o `zenpr.advisory.v1` confirma `1 -> 0` caminhos proibidos e `factory.delivery.v1` retorna `eligible: true`, `mergeAllowed`, `deployAllowed` e `autoApplyAllowed` permanecem **`false`** — prova matemática e auditável no terminal antes de qualquer decisão humana.  
  > **ScriptKitty 2.0**: segurança autônoma com prova determinística, custódia criptográfica e zero auto-confiança cega."

---

## 3. Lista Rápida de Comandos para Rodar Ao Vivo em Tela

```bash
# 1. Build completo dos pacotes TypeScript do monorepo
npm run build

# 2. Demo principal completa HackBR (10 etapas, saída 0, zero sujeira no disco)
node scripts/demo-wednesday.mjs

# 3. Suíte completa de 7 tiers (121/121 testes passando)
node packages/verification-suite/tests/run-all.mts

# 4. Suítes individuais para perguntas técnicas ao vivo dos jurados:
npm test --workspace=@script-kitty/contracts             # 91 testes (RFC 8785 Merkle, Zero-Trust Gate, SoD)
npm test --workspace=@script-kitty/evidence              # 11 testes (EvidenceLedger SQLite, isolamento cross-tenant, rejeição IA)
npm test --workspace=@script-kitty/patchcat-orchestrator #  6 testes (Orquestrador ZenPR, SoD, E_POLICY_MUTATION_FORBIDDEN)
npm test --workspace=@script-kitty/quality-gate          # 29 testes (Quad-State, SoD, .security-pack.json)
npm test --workspace=@script-kitty/chainbreak            # 18 testes (Grafo determinístico & tamper detection)
npm test --workspace=@script-kitty/security-actions      #  3 testes (Invokta MCP HTTP, Auth, Origin, Tenant)
npm test --workspace=@script-kitty/kali-mcp-assessment   # 16 testes (Static argv, Profile A/B, Guardian, SoD)
npm test --workspace=@script-kitty/lab-app               # 10 testes (Baseline real SQLi CWE-89, CMDi CWE-78, IDOR CWE-639)
npm test --workspace=@script-kitty/cli                   #  4 testes (CLI live + encrypted AES-256-GCM credentials)
npm test --workspace=@script-kitty/mcp-server            #  6 testes (MCP stdio v0.2.0 + RuntimeGuardian + 12 tools)
npm test --workspace=@script-kitty/ui                    #  6 testes (PatchCat Live Explorer UI + MCP fallback)
python -m unittest discover -s tests/python -p "test_*.py" -v  # 20 testes (guardrails LLM, remediador AST, PREVC, Kali Docker/seccomp)
```

---

## 4. Q&A Cheat Sheet para Jurados HackBR (Respostas Diretas & Honestas)

| Pergunta Provável do Jurado | Resposta Recomendada (Baseada em Código Observado) |
|---|---|
| **"A LLM pode alucinar e aprovar um patch quebrado ou marcar um bug falso como P0?"** | "Não. Seguimos o **Princípio da Fronteira Determinística**: a LLM/JEV apenas faz triagem consultiva (`PENDING_REVIEW`) e nunca define severidade P0 sozinha (`p0DefinedByJevAlone: false`). Quem decide é código determinístico — reprodutor executável, suíte de regressão, verificador independente, `EvidenceLedger` (que rejeita prosa de IA isolada com `UNVERIFIED_AI_PROSE_REJECTED`) e o `DeterministicQualityGate` em Zod/TypeScript." |
| **"Qual a diferença do comportamento offline vs. com API configurada no JEV-as-a-Judge?"** | "Sem `TYPESAFE_API_KEY`, o sistema falha fechado em `NOT_CONFIGURED` usando `MockTypeSafeJevProvider` (`decisionSource: MOCK`, `thresholdCalibrated: false`, escalado para revisão humana). Com `TYPESAFE_API_KEY` configurada, o cliente HTTP em `packages/jev-judge/src/typesafe-provider.ts` envia o estado sanitizado para `/v1/systemone` — ainda assim mantendo revisão humana obrigatória." |
| **"Vocês fazem merge ou deploy automático em produção?"** | "**Nunca no estado atual.** Em `ChainBreak`, `JEV`, `RemediationSpec`, `QualityGate`, `PatchCatOrchestrator` (`zenpr.advisory.v1`) e no contrato `factory.delivery.v1`, os flags `policyMutationAllowed`, `gateMutationAllowed`, `mergeAllowed`, `deployAllowed`, `autoApplyAllowed` e `externalExecution` estão travados em `false`. Tudo roda em modo `LAB` isolado (`productionTested: false`)." |
| **"Integrar Kali Linux não transforma a plataforma em ferramenta ofensiva?"** | "Não por arquitetura e contrato: tanto [`KaliMcpAdapter`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/adapters/src/kali-mcp-adapter.ts) quanto [`@script-kitty/kali-mcp-assessment`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/kali-mcp-assessment/src/index.ts) operam estritamente em `LAB_SANDBOX_ONLY`, aceitam **somente 4 capacidades em allowlist** (`recon_surface`, `config_audit`, `verify_reproducer`, `sbom_cve_check`), usam `argv` estático com `--` (zero shell), bloqueiam IMDS/metacaracteres/injection, têm imagem rootless (`Dockerfile.kali-sandbox` `65532:65532` sem ferramentas ofensivas + `seccomp-kali-lab.json` `SCMP_ACT_ERRNO` + `docker-compose.kali-lab.yml` `internal: true`), falham fechado em `LIVE_CONTAINER` sem sandbox (`KALI_SANDBOX_UNAVAILABLE`) e aplicam `RuntimeGuardian` + Tri-Party SoD antes de emitir evidências em `LAB_SIMULATION`." |
| **"Como vocês evitam que um agente MCP seja enganado por Prompt Injection ou Confused Deputy?"** | "Pelo `@script-kitty/runtime-guardian`: ele envelopa o servidor e cliente MCP (`wrapMcpServer` e `createGuardianClientInterceptor`) aplicando validação de manifesto SHA-256 contra *tool poisoning*, detecção de injeção/exfiltração (inclusive redação de segredos na saída), *Scope Guard* contra traversal e tokens de delegação HMAC-SHA256 com TTL ≤ 300s e verificação anti-replay." |
| **"Todo esse stack mostrado no repositório está 100% operacional ou existem partes parciais?"** | "Temos transparência total documentada em `docs/IMPLEMENTATION_INVENTORY.md`: todos os pacotes e apps TypeScript do monorepo (`contracts`, `evidence`, `quality-gate`, `chainbreak`, `company-context`, `jev-judge`, `security-actions`, `remediation-engine`, `runtime-guardian`, `adapters`, `kali-mcp-assessment`, `patchcat-orchestrator`, `lab-app`, `cli`, `mcp-server` v0.2.0 e `ui` PatchCat Live), os 5 pacotes Python (`scanners`, `validators`, `remediation`, `agent_runtime`, `plugin_sdk` com `20/20` em `tests/python/test_python_packages.py`) e os manifestos container/seccomp (`Dockerfile`, `Dockerfile.kali-sandbox`, `seccomp-kali-lab.json`, `docker-compose.kali-lab.yml`) estão implementados e verificados localmente (`121/121` na suíte de 7 tiers e `10/10` etapas no `demo-wednesday.mjs`). Permanecem explicitamente *fail-closed* / dependentes de host: `LIVE_CONTAINER` sem daemon OCI/gVisor ou WSL2 (`KALI_SANDBOX_UNAVAILABLE`), `docker build` (sem daemon Docker no host Windows), adaptadores SaaS sem credenciais (`NOT_CONFIGURED`) e `cargo test` nos crates Rust (sem `cargo` no host)." |
