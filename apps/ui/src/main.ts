/**
 * @file apps/ui/src/main.ts
 * @description Browser entrypoint for ScriptKitty Live — PatchCat Interactive Lab Explorer.
 */

import './style.css';
import { mountPatchCatDashboard } from './dashboard-view.ts';
import { CANONICAL_FIXTURE_IDS, type CanonicalFixtureId } from './lab-fixtures.ts';
import {
  createLiveController,
  DEFAULT_MCP_URL,
  type SupportedLanguage,
} from './live-controller.ts';

declare global {
  interface Window {
    __PATCHCAT_CONTROLLER__?: ReturnType<typeof createLiveController>;
  }
}

interface BootstrapQueryConfig {
  mcpUrl: string;
  bearerToken?: string;
  autoConnect: boolean;
  initialFixture: CanonicalFixtureId;
  language?: SupportedLanguage;
}

function readBootstrapQueryConfig(): BootstrapQueryConfig {
  const defaults: BootstrapQueryConfig = {
    mcpUrl: DEFAULT_MCP_URL,
    autoConnect: false,
    initialFixture: 'payments-lab/baseline',
  };
  if (typeof window === 'undefined' || !window.location?.search) {
    return defaults;
  }

  const params = new URLSearchParams(window.location.search);
  const rawMcpUrl = params.get('mcpUrl')?.trim();
  const rawToken = params.get('token')?.trim();
  const rawAuto = params.get('autoConnect')?.trim().toLowerCase();
  const rawFixture = params.get('fixture')?.trim();
  const rawLang = params.get('lang')?.trim().toLowerCase();

  // Scrub bearer token from browser URL/history immediately so it stays strictly in volatile memory
  if (rawToken && typeof window.history?.replaceState === 'function') {
    const cleanParams = new URLSearchParams(window.location.search);
    cleanParams.delete('token');
    const cleanQuery = cleanParams.toString();
    const cleanUrl = `${window.location.pathname}${cleanQuery ? `?${cleanQuery}` : ''}${window.location.hash}`;
    window.history.replaceState(null, '', cleanUrl);
  }

  const initialFixture =
    rawFixture && (CANONICAL_FIXTURE_IDS as readonly string[]).includes(rawFixture)
      ? (rawFixture as CanonicalFixtureId)
      : defaults.initialFixture;

  const language: SupportedLanguage | undefined =
    rawLang === 'en' || rawLang === 'pt' || rawLang === 'es' ? rawLang : undefined;

  return {
    mcpUrl: rawMcpUrl || DEFAULT_MCP_URL,
    bearerToken: rawToken || undefined,
    autoConnect: rawAuto === '1' || rawAuto === 'true',
    initialFixture,
    language,
  };
}

export function bootstrapPatchCatApp(rootElement?: Element | null): void {
  const appRoot = rootElement ?? document.querySelector('#app');
  if (!appRoot) return;

  const config = readBootstrapQueryConfig();
  const controller = createLiveController({
    initialFixture: config.initialFixture,
    mcpUrl: config.mcpUrl,
    bearerToken: config.bearerToken,
    mcpAutoProbe: config.autoConnect,
  });

  if (config.language) {
    controller.setLanguage(config.language);
  }

  if (typeof window !== 'undefined') {
    window.__PATCHCAT_CONTROLLER__ = controller;
  }

  mountPatchCatDashboard(appRoot, controller);

  if (config.autoConnect) {
    void controller.connectAndSyncMcp();
  }
}

if (typeof document !== 'undefined') {
  bootstrapPatchCatApp();
}
