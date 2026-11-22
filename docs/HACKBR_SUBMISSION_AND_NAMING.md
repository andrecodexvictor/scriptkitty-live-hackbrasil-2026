# Hack Brasil — Propostas de Naming, Branding & Checklist de Submissão

**Projeto Base (Monorepo):** ScriptKitty 2.0 / PatchCat Live (`@script-kitty/*`)  
**Idioma:** Português (PT-BR)  
**Modo Operacional Declarado:** `LAB` estritamente isolado (`productionTested: false`, `mergeAllowed: false`, `deployAllowed: false`, `externalExecution: false`)  
**Documentos Relacionados:** [`../README.md`](../README.md) · [`../NOTICE.md`](../NOTICE.md) · [`IMPLEMENTATION_INVENTORY.md`](IMPLEMENTATION_INVENTORY.md) · [`DEMO_WEDNESDAY.md`](DEMO_WEDNESDAY.md) · [`HACKBR_VIDEO_DEMO_GUIDE.md`](HACKBR_VIDEO_DEMO_GUIDE.md) · [`SECURITY_BOUNDARIES.md`](SECURITY_BOUNDARIES.md)

---

## 1. Contexto de Branding: Por que Revisar o Nome do Repositório de Submissão?

O monorepo técnico nasceu como **Script Kitty** (`@script-kitty/*`) com o mascote **PatchCat** (*"Your Patch Cat"*). Embora memorável na comunidade open-source, o termo *"script kiddie / script kitty"* pode gerar uma primeira impressão ambígua em bancas corporativas ou jurados de segurança — soando inicialmente como ferramenta ofensiva amadora, quando na verdade o produto é o **exato oposto**: uma plataforma **defensiva, Zero-Trust, determinística e auditável criptograficamente** para **AppSec + AgentSec/MCP**.

Por isso, abaixo apresentamos **6 propostas cuidadosamente elaboradas** para o nome do produto e slug do repositório GitHub de submissão no **Hack Brasil**, preservando coerência com o código (`@script-kitty/*`), com o mascote **PatchCat** e com o motor determinístico **ChainBreak**.

---

## 2. Seis Propostas de Nome & Slug de Repositório (Hack Brasil)

### Proposta 1 — `patchcat-live` *(Recomendação Principal)*
- **Slug GitHub:** `github.com/<org-ou-usuario>/patchcat-live`
- **Nome do Produto:** **PatchCat Live** *(by ScriptKitty 2.0)*
- **Tagline (PT-BR):** *"Prova determinística de caminhos de risco, remediação contrafactual e defesa MCP Zero-Trust em tempo real."*
- **Tagline (EN):** *"Deterministic policy-graph verification, counterfactual remediation, and Zero-Trust MCP runtime defense."*
- **Posicionamento:** Produto defensivo moderno, imediatamente ligado ao mascote visual (`assets/mascot.png`), ao painel interativo (`PatchCat Interactive Lab Explorer`) e ao orquestrador `@script-kitty/patchcat-orchestrator`.
- **Prós:**
  - Elimina 100% a ambiguidade pejorativa de "script kiddie" já no título do repositório e na URL do HackBR.
  - Alinhamento total com a interface (`apps/ui`), com a especificação `SK-SPEC-V2-LIVE-001` e com o fluxo ao vivo (`npm run demo:live`).
  - Curto, memorável, amigável em pitch de 2:30 e forte para marca open-source e produto SaaS futuro.
- **Contras:**
  - Escopos internos npm continuam `@script-kitty/*` (facilmente resolvido explicando no cabeçalho do README: *"PatchCat Live — Powered by the ScriptKitty 2.0 Monorepo"*).

### Proposta 2 — `chainbreak-sec`
- **Slug GitHub:** `github.com/<org-ou-usuario>/chainbreak-sec`
- **Nome do Produto:** **ChainBreak Sec**
- **Tagline (PT-BR):** *"Quebre cadeias de ataque em grafos de políticas e agentes MCP antes do deploy — com prova determinística."*
- **Tagline (EN):** *"Break unauthorized attack chains across policy graphs and MCP agents before rollout — with deterministic proof."*
- **Posicionamento:** Foco direto no mecanismo central de negócio (quebrar cadeias de ataque `1 -> 0` preservando `3/3` operações legítimas).
- **Prós:**
  - Comunica valor executivo instantâneo para CISOs e jurados técnicos.
  - Descreve com precisão cirúrgica o motor `@script-kitty/chainbreak` e o caso `payments-lab/unsafe-rollout`.
- **Contras:**
  - Sub-representa o lado de **AppSec** (`remediation-engine` para SQLi/CMDi/IDOR), o **Runtime Guardian** e o mascote **PatchCat** já presente na UI e nos assets.

### Proposta 3 — `scriptkitty-live`
- **Slug GitHub:** `github.com/<org-ou-usuario>/scriptkitty-live`
- **Nome do Produto:** **ScriptKitty Live**
- **Tagline (PT-BR):** *"ScriptKitty 2.0 (PatchCat): verificação determinística AppSec + AgentSec/MCP com custódia criptográfica."*
- **Tagline (EN):** *"ScriptKitty 2.0 (PatchCat): deterministic AppSec + AgentSec/MCP verification with cryptographic custody."*
- **Posicionamento:** Continuidade total com o nome original do projeto e com todos os pacotes `@script-kitty/*`.
- **Prós:**
  - Zero fricção entre slug do repositório, escopos `@script-kitty/*`, CLI (`apps/cli`) e histórico do projeto.
  - Carrega personalidade forte e fácil de lembrar em hackathons.
- **Contras:**
  - Exige sempre um esclarecimento de 10 segundos no início do pitch para deixar claro que não se trata de ferramenta ofensiva (*"script kiddie"*), mas sim de defesa Zero-Trust em modo `LAB`.

### Proposta 4 — `patchcat-zero`
- **Slug GitHub:** `github.com/<org-ou-usuario>/patchcat-zero`
- **Nome do Produto:** **PatchCat Zero**
- **Tagline (PT-BR):** *"Zero falsos positivos sem prova, zero auto-certificação de agentes, zero deploy sem aprovação humana."*
- **Tagline (EN):** *"Zero unproven alerts, zero agent self-certification, zero unapproved rollouts."*
- **Posicionamento:** Enfatiza a arquitetura **Zero-Trust** (Tri-Party SoD $A_{\text{disc}} \ne A_{\text{veri}} \ne A_{\text{auth}}$, RFC 8785 Merkle, fail-closed).
- **Prós:**
  - Gancho retórico fortíssimo para a banca (*"Regra dos Três Zeros"*).
  - Combina identidade de marca (**PatchCat**) com autoridade de engenharia de segurança (**Zero-Trust**).
- **Contras:**
  - Pode sugerir foco exclusivo em "0-day hunting", exigindo deixar claro que o escopo atual é validação defensiva determinística (`PATH_VALIDATED`, nunca `EXPLOIT_CONFIRMED`).

### Proposta 5 — `clawgate-sec`
- **Slug GitHub:** `github.com/<org-ou-usuario>/clawgate-sec`
- **Nome do Produto:** **ClawGate Sec**
- **Tagline (PT-BR):** *"O portão determinístico de qualidade e segurança para código, políticas e servidores MCP."*
- **Tagline (EN):** *"The deterministic quality and security gate for code, policy graphs, and MCP servers."*
- **Posicionamento:** Foco no **Quality Gate Determinístico**, `RuntimeGuardian` e `factory.delivery.v1`, mantendo um aceno sutil felino ("Claw").
- **Prós:**
  - Soa empresarial, sério e diretamente associado a gates CI/CD e controle de acesso MCP.
  - Distinto e fácil de registrar como domínio/org.
- **Contras:**
  - Não aparece no código existente hoje (`PatchCat`, `ChainBreak`, `ScriptKitty`), criando um nome completamente novo de última hora que pode confundir quem ler o código ou assistir ao vídeo.

### Proposta 6 — `aegis-patchcat`
- **Slug GitHub:** `github.com/<org-ou-usuario>/aegis-patchcat`
- **Nome do Produto:** **Aegis PatchCat**
- **Tagline (PT-BR):** *"Blindagem determinística para pipelines de código e agentes autônomos MCP."*
- **Tagline (EN):** *"Deterministic shielding for software delivery pipelines and autonomous MCP agents."*
- **Posicionamento:** Fusão de arquétipo clássico de defesa cibernética (*Aegis*) com a identidade do mascote (*PatchCat*).
- **Prós:**
  - Transmite imediatamente proteção defensiva e governança.
  - Preserva o elo com o mascote PatchCat.
- **Contras:**
  - "Aegis" é um termo muito saturado em projetos de segurança e hackathons; reduz originalidade e alonga o slug.

---

### Tabela Comparativa Rápida

| # | Slug GitHub | Nome | Clareza Defensiva | Aderência ao Código | Memorabilidade | Veredito |
|---|---|---|---|---|---|---|
| 1 | `patchcat-live` | **PatchCat Live** | Muito Alta | Muito Alta (`PatchCat` + `LIVE`) | Muito Alta | **Recomendação #1** |
| 2 | `patchcat-zero` | **PatchCat Zero** | Muito Alta | Alta (`Zero-Trust` + `PatchCat`) | Alta | **Runner-Up (#2)** |
| 3 | `chainbreak-sec` | **ChainBreak Sec** | Muito Alta | Média-Alta (foco grafo) | Alta | Forte para produto B2B |
| 4 | `scriptkitty-live` | **ScriptKitty Live** | Média (pede ressalva) | Máxima (`@script-kitty/*`) | Muito Alta | Melhor se manter legado |
| 5 | `clawgate-sec` | **ClawGate Sec** | Muito Alta | Média (termo novo) | Média-Alta | Exige rebranding extra |
| 6 | `aegis-patchcat` | **Aegis PatchCat** | Alta | Média-Alta | Média (genérico) | Menor diferenciação |

---

## 3. Recomendação Final & Enquadramento Limpo de Pitch (Hack Brasil)

### Escolha Recomendada
- **Repositório de Submissão:** **`patchcat-live`**
- **Título Oficial no Portal HackBR:** **PatchCat Live (ScriptKitty 2.0) — Verificação Determinística de Segurança para AppSec & Agentes MCP**
- **Alternativa imediata caso o slug esteja ocupado:** **`patchcat-zero`**

### Por que `patchcat-live` vence para a banca HackBR?
1. **Primeira impressão 100% defensiva:** nenhum jurado confunde com ferramenta ofensiva.
2. **Coerência fim a fim:** o painel web já exibe *"ScriptKitty Live — PatchCat Interactive Lab Explorer"*, o mascote 2D/3D é o PatchCat, o orquestrador é `@script-kitty/patchcat-orchestrator`, e o comando de demonstração é `npm run demo:live`.
3. **Diferenciação real:** enquanto projetos comuns de IA em segurança mostram um chat chamando um LLM, **PatchCat Live** mostra um grafo determinístico, um servidor MCP Streamable HTTP real com autenticação/CORS *fail-closed*, custódia criptográfica RFC 8785 e provas reproduzíveis rodando ao vivo em `127.0.0.1`.

### Enquadramento de Pitch (30 Segundos — Elevator Pitch Limpo)
> *"Scanners de segurança baseados apenas em LLM sofrem de dois problemas críticos: excesso de falsos positivos não comprovados e cegueira total para agentes autônomos e ferramentas MCP. O **PatchCat Live (ScriptKitty 2.0)** transforma segurança de opinião probabilística em engenharia determinística: o motor **ChainBreak** comprova matematicamente cadeias de risco em grafos de políticas (`PATH_VALIDATED`), sintetiza a correção mínima que reduz caminhos proibidos de `1 -> 0` preservando `3/3` operações legítimas, expõe tudo via **MCP Streamable HTTP fail-closed** em `127.0.0.1`, protege ferramentas MCP com **Runtime Guardian**, e sela cada evidência em árvores **Merkle RFC 8785** sob **Separação Tripartite de Deveres** ($A_{\text{disc}} \ne A_{\text{veri}} \ne A_{\text{auth}}$) — onde nenhum agente aprova o próprio patch e o humano mantém o controle final (`mergeAllowed: false`, `deployAllowed: false`)."*

### 3 Pilares para Destacar no Formulário & Q&A dos Jurados
1. **Determinismo antes de IA:** Graph reachability (`@script-kitty/chainbreak`) + reprodutores isolados em `apps/lab-app` (`CWE-89`, `CWE-78`, `CWE-639`) rodam **antes** do triage consultivo **JEV-as-a-Judge** (`PENDING_REVIEW`, nunca define P0 sozinho).
2. **Zero-Trust Real no Protocolo MCP:** Servidor Invokta MCP Streamable HTTP (`127.0.0.1:3847/mcp`) com `Host` anti-DNS-rebinding, CORS *fail-closed* por allowlist loopback, Bearer auth (`401`), isolamento multi-tenant (`FORBIDDEN`) e `RuntimeGuardian` (`168/168` testes contra tool poisoning, prompt injection, path traversal e confused deputy).
3. **Honestidade Radical de Engenharia:** 100% executável offline em modo `LAB`, zero segredos no repositório, integrações externas explicitamente marcadas como `NOT_CONFIGURED`, `MOCK` ou `DISABLED_BY_FLAG`, e mais de **620 testes automatizados** (TypeScript + Python + 7 tiers E2E) verificáveis em um comando.

---

## 4. Checklist Completo de Prontidão para Submissão (Hack Brasil)

### 4.1 Varredura de Segredos Pré-Push (Pre-Push Secret Scan)
Execute antes de fazer `git push` para o repositório público da submissão:

```powershell
# 1. Revisar arquivos novos, modificados e não rastreados
git status --short

# 2. Garantir que nenhum arquivo sensível foi adicionado por engano
git ls-files | Select-String -Pattern '\.env$|\.pem$|\.key$|\.sqlite$|\.db$|credentials'

# 3. Varredura de padrões de credenciais reais em código versionado
git grep -n -E "(sk-proj-|sk-live-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)"
```

- [ ] Nenhum arquivo `.env`, `.env.local`, `*.pem`, `*.key` ou banco `.sqlite` persistente está rastreado no Git.
- [ ] Nenhuma chave real (`TYPESAFE_API_KEY`, `OPENAI_API_KEY`, `CLOUDFLARE_API_TOKEN`, `GOOGLE_API_KEY`, `ANTHROPIC_API_KEY`) existe no working tree ou no histórico de commits.
- [ ] **Nota explícita de auditoria:** o valor padrão `sk-live-demo-token-2026` em [`../scripts/start-live-demo.mjs`](../scripts/start-live-demo.mjs) é exclusivamente um token de sessão **local loopback (`127.0.0.1`) em modo `LAB`**, sobrescrevível via `DEMO_TOKEN` / `--token`, e nunca dá acesso a qualquer serviço externo ou produção. Da mesma forma, strings de teste em `packages/verification-suite/` (ex.: `ghp_` sintético em teste de redação de segredos) são sintéticas e existem apenas para provar que o redator remove segredos dos relatórios.

### 4.2 Higiene do `.gitignore` e Integridade do Repositório
Confira [`../.gitignore`](../.gitignore) e o estado do repositório:

- [ ] `node_modules/`, `dist/`, `build/`, `target/`, `.env`, `.env.local`, `*.pem`, `*.key`, `*.log`, `internal_lab/`, `scratch/` permanecem ignorados em [`../.gitignore`](../.gitignore).
- [ ] Confirmar que os arquivos vulneráveis intencionais do alvo de laboratório (`apps/lab-app/src/routes/search.ts`, `diagnostics.ts`, `reports.ts`) permanecem exatamente na baseline canônica do `LAB` (nenhum patch de teste sobrescreveu o alvo de laboratório permanentemente).
- [ ] Confirmar ausência de servidores Node/Vite órfãos rodando nas portas `3847` ou `5173` após os testes (`Get-NetTCPConnection -LocalPort 3847,5173 -ErrorAction SilentlyContinue`).
- [ ] Verificar se arquivos grandes de vídeo (`demo-video/*.mp4`) devem subir via Git LFS, GitHub Release asset ou link do portal HackBR (evitar estourar o limite de 100 MB do GitHub caso o MP4 cresça; o MP4 de 2:30 otimizado em H.264 deve ficar bem abaixo disso).

### 4.3 Comandos Obrigatórios de Verificação Pré-Submissão
Rode todos os comandos abaixo a partir da raiz do monorepo e confirme **exit code `0`** em todos:

```bash
# 1. Build completo dos 16 workspaces compiláveis
npm run build

# 2. Typecheck estrito em todos os workspaces TypeScript
npm run typecheck --workspaces --if-present

# 3. Suíte completa de testes unitários e de integração (todos os 17 workspaces npm)
npm test

# 4. Suíte Python (validators, remediation, agent_runtime, scanners, plugin_sdk, Kali sandbox)
npm run test:python

# 5. Suíte E2E e Adversarial de 7 Tiers (packages/verification-suite)
npm run verify

# 6. Demo completa de 10 etapas em CLI (modo LAB, :memory: SQLite)
npm run demo

# 7. Auto-verificação do lançador PoC ao vivo (UI 127.0.0.1 + Invokta MCP HTTP + CORS + 403/401)
node scripts/start-live-demo.mjs --check
```

- [ ] `npm run build` -> exit `0`
- [ ] `npm run typecheck --workspaces --if-present` -> exit `0`
- [ ] `npm test` -> exit `0` (`0` falhas)
- [ ] `npm run test:python` -> exit `0` (`20/20` passando)
- [ ] `npm run verify` -> exit `0` (`121/121` passando nos Tiers 1–7)
- [ ] `npm run demo` -> exit `0` (`10/10` estágios passando)
- [ ] `node scripts/start-live-demo.mjs --check` -> exit `0` (`"check": "PASS"`)

### 4.4 Instruções Reproduzíveis de Demo Ao Vivo (Para Jurados & Revisores)

#### Opção A — Lançador PoC Ao Vivo em 1 Comando (UI + Invokta MCP Streamable HTTP)
```bash
npm run build
npm run demo:live
```
- **Painel PatchCat Live (UI):** `http://127.0.0.1:5173`
- **Servidor Invokta MCP Streamable HTTP:** `http://127.0.0.1:3847/mcp`
- **Token Bearer padrão de laboratório:** `sk-live-demo-token-2026` *(configurável via `DEMO_TOKEN` ou `--token=<valor>`)*
- **Customização opcional de portas:** `MCP_PORT=3847 UI_PORT=5173 node scripts/start-live-demo.mjs` (ou `--mcp-port=... --ui-port=...`)
- **Fluxo interativo na UI:** conectar ao endpoint loopback (`MODE: LIVE MCP HTTP`) e alternar entre `payments-lab/baseline` (`0` caminhos proibidos, `3/3` ops), `payments-lab/unsafe-rollout` (`1` cadeia `PATH_VALIDATED` + `JEV-as-a-Judge` `PENDING_REVIEW` + `RemediationSpec` contrafactual), `payments-lab/remediated` (`1 -> 0` caminhos, `3/3` ops intactas) e o toggle de **Tri-Party SoD** (`E_SOD_SELF_CERTIFICATION`).
- **Encerramento limpo:** `Ctrl+C` (`SIGINT`/`SIGTERM`) finaliza ambos os servidores loopback sem deixar processos ou arquivos `.sqlite` no disco.

#### Opção B — Demo Determinística de 10 Etapas no Terminal
```bash
npm run demo
```
Executa todas as 10 etapas documentadas em [`DEMO_WEDNESDAY.md`](DEMO_WEDNESDAY.md) (`security.status`, `baseline`, `unsafe-rollout`, `JEV-as-a-Judge`, `RemediationSpec`, `remediated` + `negative-control`, Invokta MCP HTTP + bloqueios `401`/`403`/`FORBIDDEN`, Quality Gate + Merkle + `factory.delivery.v1`, Kali MCP `LAB_SANDBOX_ONLY`, e `PatchCatOrchestrator` + `EvidenceLedger` `zenpr.advisory.v1`).

#### Opção C — Vídeo PoC de 2:30 (Demonstração Assíncrona para o Portal HackBR)
- **Vídeo MP4 (`1920x1080`, H.264 + AAC):** `demo-video/scriptkitty-live-poc-demo-2m30s.mp4`
- **Legendas sincronizadas PT-BR:** `demo-video/scriptkitty-live-poc-demo-2m30s.srt`
- **Roteiro & Q&A de referência:** [`HACKBR_VIDEO_DEMO_GUIDE.md`](HACKBR_VIDEO_DEMO_GUIDE.md)

### 4.5 Divulgações Explícitas e Honestas de Modo `LAB` (Obrigatório na Submissão)
Para manter integridade técnica máxima diante dos jurados do Hack Brasil, inclua estas divulgações claras no texto da submissão e na apresentação:

1. **Somente Modo `LAB` (`productionTested: false`):** Todo o sistema opera exclusivamente em ambiente local loopback (`127.0.0.1`) e fixtures sintéticas (`fixtures/payments-lab/*`, `apps/lab-app/`). Nenhuma credencial ou infraestrutura de produção é tocada.
2. **Zero Mutação Autônoma em Produção:** Todas as entregas e orquestrações travam permanentemente `mergeAllowed: false`, `deployAllowed: false`, `autoApplyAllowed: false`, `externalExecution: false`, `policyMutationAllowed: false`, `gateMutationAllowed: false` e `requiresHumanApproval: true`.
3. **Semântica Honesta (`PATH_VALIDATED` ≠ `EXPLOIT_CONFIRMED`):** O motor ChainBreak comprova alcançabilidade determinística em grafos de políticas modelados com `sourceRef` e `inputSha256`. O rótulo `EXPLOIT_CONFIRMED` não existe no MVP.
4. **Integrações Externas *Fail-Closed* por Padrão:**
   - **TypeSafe JEV:** roda offline via `MockTypeSafeJevProvider` (`providerStatus: "NOT_CONFIGURED"`, `decisionSource: "MOCK"`, `status: "PENDING_REVIEW"`, `p0DefinedByJevAlone: false`) quando `TYPESAFE_API_KEY` não é informada.
   - **Google Mantis, OpenAI Codex Security, Cloudflare Security Center & Quality Engine externo:** reportam `NOT_CONFIGURED` / `skipped` sem credenciais/daemon local.
   - **Google Harness²:** desabilitado por padrão (`HARNESS2_EXPERIMENTS_ENABLED=false`, `DISABLED_BY_FLAG`).
   - **Kali Linux Verification MCP (`@script-kitty/kali-mcp-assessment`):** opera em `LAB_SANDBOX_ONLY` com 4 capacidades defensivas em allowlist e execução determinística `LAB_SIMULATION`; o modo `LIVE_CONTAINER` falha fechado (`KALI_SANDBOX_UNAVAILABLE`) até que o operador provisione um sandbox rootless OCI+gVisor (`runsc`) ou WSL2 dedicado (ver [`KALI_MCP_ARCHITECTURE_PLAN.md`](KALI_MCP_ARCHITECTURE_PLAN.md)).
5. **Toolchains Não Executadas no Host de Build Windows:**
   - **Rust (`packages/policies`, `packages/audit`):** código-fonte e testes `#[cfg(test)]` existem no repositório, porém `cargo` não está instalado no host Windows de build (status divulgado em [`IMPLEMENTATION_INVENTORY.md`](IMPLEMENTATION_INVENTORY.md) como não compilado localmente; as garantias equivalentes rodam verificadas em TypeScript `@script-kitty/contracts` e `@script-kitty/quality-gate`).
   - **Docker (`Dockerfile`, `Dockerfile.kali-sandbox`, `docker-compose.kali-lab.yml`):** manifestos endurecidos (`USER 65532:65532`, `cap_drop: ALL`, `read_only: true`, seccomp `SCMP_ACT_ERRNO`) estão implementados e validados estruturalmente no Tier 7 e na suíte Python (`20/20`), mas `docker build`/`compose` não foi executado sem daemon Docker no host Windows.

### 4.6 Conferência Final de Licenças, Proveniência & Links
- [ ] [`../NOTICE.md`](../NOTICE.md) revisado com todas as 9 atribuições externas e checklist de licenças (`Invokta`, `Factory Starter Kit`, `OWASP Security Skills Pack`, `Google Mantis`, `Google Harness²`, `OpenAI Codex Security`, `Cloudflare Security Center`, `Quality Engine`, `TypeSafe JEV`).
- [ ] [`../LICENSE`](../LICENSE) (MIT) e [`../scope.md`](../scope.md) presentes na raiz do repositório.
- [ ] [`../package.json`](../package.json) com scripts de raiz testados (`demo`, `demo:live`, `test:python`, `verify`).
- [ ] Vídeo de 2:30 (`demo-video/scriptkitty-live-poc-demo-2m30s.mp4`) verificado com áudio PT-BR, legendas legíveis (`1920x1080`, `H.264`/`yuv420p` + `AAC`) e quadros reais da aplicação rodando ao vivo.
