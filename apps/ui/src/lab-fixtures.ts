/**
 * @file apps/ui/src/lab-fixtures.ts
 * @description Browser-safe canonical `fixtures/payments-lab/*.json` policy graph fixtures
 * for offline/deterministic ChainBreak evaluation in `@script-kitty/ui`.
 * Verified against on-disk JSON fixtures and SHA-256 hashes in `tests/ui-controller.test.mts`.
 */

export const CANONICAL_FIXTURE_IDS = [
  'payments-lab/baseline',
  'payments-lab/unsafe-rollout',
  'payments-lab/remediated',
  'payments-lab/negative-control',
] as const;

export type CanonicalFixtureId = (typeof CANONICAL_FIXTURE_IDS)[number];

export type DataClassification =
  | 'PUBLIC'
  | 'INTERNAL'
  | 'CONFIDENTIAL'
  | 'RESTRICTED';

export type TrustZone = 'INTERNAL' | 'DMZ' | 'EXTERNAL';

export type AttackGraphNodeKind =
  | 'identity'
  | 'agent'
  | 'mcp_tool'
  | 'api'
  | 'service'
  | 'data_asset'
  | 'destination';

export type AttackGraphEdgeKind =
  | 'can_invoke'
  | 'can_read'
  | 'can_write'
  | 'transfers_data_to'
  | 'assumes_role'
  | 'delegates_to';

export interface PolicyRule {
  policyId: string;
  description: string;
  forbiddenTargetClassification: DataClassification;
  forbiddenDestinationTrustZone: TrustZone;
  riskRecommendation: 'P0' | 'P1' | 'P2' | 'P3' | 'UNDETERMINED';
  policyVersion: string;
  sourceRef: string;
}

export interface AttackGraphNode {
  nodeId: string;
  kind: AttackGraphNodeKind;
  label: string;
  tenantId: string;
  scope: string;
  allowedScopes?: string[];
  roles?: string[];
  dataClassification?: DataClassification;
  allowedClassifications?: DataClassification[];
  trustZone: TrustZone;
  isEntryIdentity?: boolean;
  isRestrictedAsset?: boolean;
  isUnauthorizedDestination?: boolean;
  sourceRef: string;
  metadata?: Record<string, unknown>;
}

export interface EdgeConditions {
  effect?: 'ALLOW' | 'DENY';
  active?: boolean;
  requiredScopes?: string[];
  requiredRoles?: string[];
  grantedRoles?: string[];
  allowedDataClassifications?: DataClassification[];
  deniedDataClassifications?: DataClassification[];
  requiresExplicitGrant?: boolean;
  explicitGrantPresent?: boolean;
  requiresMfa?: boolean;
  mfaVerified?: boolean;
  requiresPiiMasking?: boolean;
  piiMaskingApplied?: boolean;
  allowedPurposes?: string[];
  purpose?: string;
  networkZone?: 'INTERNAL' | 'DMZ' | 'EXTERNAL' | 'ANY';
}

export interface AttackGraphEdge {
  edgeId: string;
  from: string;
  to: string;
  kind: AttackGraphEdgeKind;
  tenantId: string;
  scope: string;
  conditions: EdgeConditions;
  sourceRef: string;
  policyId?: string;
  policyVersion: string;
  dataClassification: DataClassification;
}

export interface LegitimateOperation {
  operationId: string;
  description: string;
  startIdentity: string;
  requiredEdgeIds: string[];
  targetNodeId: string;
  expectedDataClassification?: DataClassification;
  sourceRef: string;
}

export interface PolicyGraphFixture {
  schemaVersion: 'chainbreak.graph.v1';
  fixtureId: CanonicalFixtureId;
  tenantId: string;
  policyVersion: string;
  declaredInputSha256: string;
  description: string;
  startIdentities: string[];
  policies: PolicyRule[];
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  legitimateOperations: LegitimateOperation[];
}

export const BASELINE_FIXTURE: PolicyGraphFixture = {
  schemaVersion: 'chainbreak.graph.v1',
  fixtureId: 'payments-lab/baseline',
  tenantId: 'payments-lab',
  policyVersion: '2026.11.09-baseline',
  declaredInputSha256:
    '76c07c4340acfc748443a496435867c819354f99241cd361cd585d2dc85a8bbc',
  description:
    'Payments Lab baseline: support agent can read synthetic customer profile and export non-sensitive summaries; finance service processes payments strictly within finance-core scope.',
  startIdentities: ['identity:support-agent', 'identity:finance-operator'],
  policies: [
    {
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      description:
        'RESTRICTED payment and PII data assets must never be transferred to EXTERNAL trust-zone destinations lacking explicit RESTRICTED clearance.',
      forbiddenTargetClassification: 'RESTRICTED',
      forbiddenDestinationTrustZone: 'EXTERNAL',
      riskRecommendation: 'P1',
      policyVersion: '2026.11.09-baseline',
      sourceRef:
        'policies/payments-lab/baseline.policy.yaml#rules.no_restricted_external',
    },
  ],
  nodes: [
    {
      nodeId: 'identity:support-agent',
      kind: 'identity',
      label: 'Support Agent Identity',
      tenantId: 'payments-lab',
      scope: 'support-ops',
      allowedScopes: ['support-ops', 'reporting-public'],
      roles: ['support-reader'],
      trustZone: 'INTERNAL',
      isEntryIdentity: true,
      sourceRef:
        'policies/payments-lab/baseline.policy.yaml#identities.support_agent',
    },
    {
      nodeId: 'identity:finance-operator',
      kind: 'identity',
      label: 'Finance Operator Identity',
      tenantId: 'payments-lab',
      scope: 'finance-core',
      allowedScopes: ['finance-core'],
      roles: ['finance-operator'],
      trustZone: 'INTERNAL',
      isEntryIdentity: true,
      sourceRef:
        'policies/payments-lab/baseline.policy.yaml#identities.finance_operator',
    },
    {
      nodeId: 'mcp_tool:report-exporter',
      kind: 'mcp_tool',
      label: 'MCP Report Exporter Tool',
      tenantId: 'payments-lab',
      scope: 'reporting-public',
      roles: ['report-exporter'],
      trustZone: 'INTERNAL',
      sourceRef:
        'policies/payments-lab/baseline.policy.yaml#tools.report_exporter',
    },
    {
      nodeId: 'service:finance-processor',
      kind: 'service',
      label: 'Finance Payment Processor Service',
      tenantId: 'payments-lab',
      scope: 'finance-core',
      roles: ['payment-processor'],
      trustZone: 'INTERNAL',
      sourceRef:
        'policies/payments-lab/baseline.policy.yaml#services.finance_processor',
    },
    {
      nodeId: 'data_asset:customer-profile-synthetic',
      kind: 'data_asset',
      label: 'Synthetic Customer Support Profile',
      tenantId: 'payments-lab',
      scope: 'support-ops',
      dataClassification: 'INTERNAL',
      trustZone: 'INTERNAL',
      isRestrictedAsset: false,
      sourceRef:
        'policies/payments-lab/baseline.policy.yaml#assets.customer_profile_synthetic',
    },
    {
      nodeId: 'data_asset:non-sensitive-summary',
      kind: 'data_asset',
      label: 'Aggregated Non-Sensitive Report Summary',
      tenantId: 'payments-lab',
      scope: 'reporting-public',
      dataClassification: 'PUBLIC',
      trustZone: 'INTERNAL',
      isRestrictedAsset: false,
      sourceRef:
        'policies/payments-lab/baseline.policy.yaml#assets.non_sensitive_summary',
    },
    {
      nodeId: 'data_asset:customer-payment-pii',
      kind: 'data_asset',
      label: 'Restricted Customer Payment & PII Vault',
      tenantId: 'payments-lab',
      scope: 'finance-core',
      dataClassification: 'RESTRICTED',
      trustZone: 'INTERNAL',
      isRestrictedAsset: true,
      sourceRef:
        'policies/payments-lab/baseline.policy.yaml#assets.customer_payment_pii',
    },
    {
      nodeId: 'data_asset:payment-ledger-internal',
      kind: 'data_asset',
      label: 'Internal Settlement Ledger',
      tenantId: 'payments-lab',
      scope: 'finance-core',
      dataClassification: 'RESTRICTED',
      trustZone: 'INTERNAL',
      isRestrictedAsset: true,
      sourceRef:
        'policies/payments-lab/baseline.policy.yaml#assets.payment_ledger_internal',
    },
    {
      nodeId: 'destination:external-report-sink',
      kind: 'destination',
      label: 'External Partner Reporting Sink',
      tenantId: 'payments-lab',
      scope: 'reporting-public',
      dataClassification: 'PUBLIC',
      allowedClassifications: ['PUBLIC'],
      trustZone: 'EXTERNAL',
      isUnauthorizedDestination: true,
      sourceRef:
        'policies/payments-lab/baseline.policy.yaml#destinations.external_report_sink',
    },
  ],
  edges: [
    {
      edgeId: 'e-support-read-profile',
      from: 'identity:support-agent',
      to: 'data_asset:customer-profile-synthetic',
      kind: 'can_read',
      tenantId: 'payments-lab',
      scope: 'support-ops',
      conditions: {
        effect: 'ALLOW',
        active: true,
        requiredRoles: ['support-reader'],
      },
      sourceRef:
        'policies/payments-lab/baseline.policy.yaml#edges.support_read_profile',
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      policyVersion: '2026.11.09-baseline',
      dataClassification: 'INTERNAL',
    },
    {
      edgeId: 'e-support-invoke-exporter',
      from: 'identity:support-agent',
      to: 'mcp_tool:report-exporter',
      kind: 'can_invoke',
      tenantId: 'payments-lab',
      scope: 'reporting-public',
      conditions: {
        effect: 'ALLOW',
        active: true,
        allowedDataClassifications: ['PUBLIC'],
      },
      sourceRef:
        'policies/payments-lab/baseline.policy.yaml#edges.support_invoke_exporter',
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      policyVersion: '2026.11.09-baseline',
      dataClassification: 'PUBLIC',
    },
    {
      edgeId: 'e-exporter-read-summary',
      from: 'mcp_tool:report-exporter',
      to: 'data_asset:non-sensitive-summary',
      kind: 'can_read',
      tenantId: 'payments-lab',
      scope: 'reporting-public',
      conditions: {
        effect: 'ALLOW',
        active: true,
        allowedDataClassifications: ['PUBLIC'],
      },
      sourceRef:
        'policies/payments-lab/baseline.policy.yaml#edges.exporter_read_summary',
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      policyVersion: '2026.11.09-baseline',
      dataClassification: 'PUBLIC',
    },
    {
      edgeId: 'e-exporter-transfer-external',
      from: 'mcp_tool:report-exporter',
      to: 'destination:external-report-sink',
      kind: 'transfers_data_to',
      tenantId: 'payments-lab',
      scope: 'reporting-public',
      conditions: {
        effect: 'ALLOW',
        active: true,
        allowedDataClassifications: ['PUBLIC'],
      },
      sourceRef:
        'policies/payments-lab/baseline.policy.yaml#edges.exporter_transfer_external',
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      policyVersion: '2026.11.09-baseline',
      dataClassification: 'PUBLIC',
    },
    {
      edgeId: 'e-finance-assume-processor',
      from: 'identity:finance-operator',
      to: 'service:finance-processor',
      kind: 'assumes_role',
      tenantId: 'payments-lab',
      scope: 'finance-core',
      conditions: {
        effect: 'ALLOW',
        active: true,
        requiredRoles: ['finance-operator'],
      },
      sourceRef:
        'policies/payments-lab/baseline.policy.yaml#edges.finance_assume_processor',
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      policyVersion: '2026.11.09-baseline',
      dataClassification: 'RESTRICTED',
    },
    {
      edgeId: 'e-finance-read-payment-pii',
      from: 'service:finance-processor',
      to: 'data_asset:customer-payment-pii',
      kind: 'can_read',
      tenantId: 'payments-lab',
      scope: 'finance-core',
      conditions: {
        effect: 'ALLOW',
        active: true,
        requiredRoles: ['payment-processor'],
      },
      sourceRef:
        'policies/payments-lab/baseline.policy.yaml#edges.finance_read_payment_pii',
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      policyVersion: '2026.11.09-baseline',
      dataClassification: 'RESTRICTED',
    },
    {
      edgeId: 'e-finance-write-ledger',
      from: 'service:finance-processor',
      to: 'data_asset:payment-ledger-internal',
      kind: 'can_write',
      tenantId: 'payments-lab',
      scope: 'finance-core',
      conditions: {
        effect: 'ALLOW',
        active: true,
        networkZone: 'INTERNAL',
      },
      sourceRef:
        'policies/payments-lab/baseline.policy.yaml#edges.finance_write_ledger',
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      policyVersion: '2026.11.09-baseline',
      dataClassification: 'RESTRICTED',
    },
  ],
  legitimateOperations: [
    {
      operationId: 'op-support-read-profile',
      description:
        'Support agent reads synthetic customer support profile within support-ops scope',
      startIdentity: 'identity:support-agent',
      requiredEdgeIds: ['e-support-read-profile'],
      targetNodeId: 'data_asset:customer-profile-synthetic',
      expectedDataClassification: 'INTERNAL',
      sourceRef: 'policies/payments-lab/legitimate-ops.yaml#support_read_profile',
    },
    {
      operationId: 'op-non-sensitive-export',
      description:
        'Support agent invokes report-exporter to export PUBLIC non-sensitive summary to external report sink',
      startIdentity: 'identity:support-agent',
      requiredEdgeIds: [
        'e-support-invoke-exporter',
        'e-exporter-read-summary',
        'e-exporter-transfer-external',
      ],
      targetNodeId: 'destination:external-report-sink',
      expectedDataClassification: 'PUBLIC',
      sourceRef: 'policies/payments-lab/legitimate-ops.yaml#non_sensitive_export',
    },
    {
      operationId: 'op-finance-process-payments',
      description:
        'Finance operator assumes finance-processor service role to read payment PII and write internal settlement ledger',
      startIdentity: 'identity:finance-operator',
      requiredEdgeIds: [
        'e-finance-assume-processor',
        'e-finance-read-payment-pii',
        'e-finance-write-ledger',
      ],
      targetNodeId: 'data_asset:payment-ledger-internal',
      expectedDataClassification: 'RESTRICTED',
      sourceRef:
        'policies/payments-lab/legitimate-ops.yaml#finance_process_payments',
    },
  ],
};

export const UNSAFE_ROLLOUT_FIXTURE: PolicyGraphFixture = {
  schemaVersion: 'chainbreak.graph.v1',
  fixtureId: 'payments-lab/unsafe-rollout',
  tenantId: 'payments-lab',
  policyVersion: '2026.11.09-unsafe-rollout',
  declaredInputSha256:
    '142cdbbd10b23de6967672f56587b29a5ef028dc727213810a85cc8bcf5b3da0',
  description:
    'Payments Lab unsafe rollout: misconfigured policy update on mcp_tool:report-exporter grants read access to customer-payment-pii and widens external transfer classification to RESTRICTED.',
  startIdentities: ['identity:support-agent', 'identity:finance-operator'],
  policies: [
    {
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      description:
        'RESTRICTED payment and PII data assets must never be transferred to EXTERNAL trust-zone destinations lacking explicit RESTRICTED clearance.',
      forbiddenTargetClassification: 'RESTRICTED',
      forbiddenDestinationTrustZone: 'EXTERNAL',
      riskRecommendation: 'P1',
      policyVersion: '2026.11.09-unsafe-rollout',
      sourceRef:
        'policies/payments-lab/unsafe-rollout.policy.yaml#rules.no_restricted_external',
    },
  ],
  nodes: [
    {
      nodeId: 'identity:support-agent',
      kind: 'identity',
      label: 'Support Agent Identity',
      tenantId: 'payments-lab',
      scope: 'support-ops',
      allowedScopes: ['support-ops', 'reporting-public'],
      roles: ['support-reader'],
      trustZone: 'INTERNAL',
      isEntryIdentity: true,
      sourceRef:
        'policies/payments-lab/unsafe-rollout.policy.yaml#identities.support_agent',
    },
    {
      nodeId: 'identity:finance-operator',
      kind: 'identity',
      label: 'Finance Operator Identity',
      tenantId: 'payments-lab',
      scope: 'finance-core',
      allowedScopes: ['finance-core'],
      roles: ['finance-operator'],
      trustZone: 'INTERNAL',
      isEntryIdentity: true,
      sourceRef:
        'policies/payments-lab/unsafe-rollout.policy.yaml#identities.finance_operator',
    },
    {
      nodeId: 'mcp_tool:report-exporter',
      kind: 'mcp_tool',
      label: 'MCP Report Exporter Tool',
      tenantId: 'payments-lab',
      scope: 'reporting-public',
      roles: ['report-exporter'],
      trustZone: 'INTERNAL',
      sourceRef:
        'policies/payments-lab/unsafe-rollout.policy.yaml#tools.report_exporter',
    },
    {
      nodeId: 'service:finance-processor',
      kind: 'service',
      label: 'Finance Payment Processor Service',
      tenantId: 'payments-lab',
      scope: 'finance-core',
      roles: ['payment-processor'],
      trustZone: 'INTERNAL',
      sourceRef:
        'policies/payments-lab/unsafe-rollout.policy.yaml#services.finance_processor',
    },
    {
      nodeId: 'data_asset:customer-profile-synthetic',
      kind: 'data_asset',
      label: 'Synthetic Customer Support Profile',
      tenantId: 'payments-lab',
      scope: 'support-ops',
      dataClassification: 'INTERNAL',
      trustZone: 'INTERNAL',
      isRestrictedAsset: false,
      sourceRef:
        'policies/payments-lab/unsafe-rollout.policy.yaml#assets.customer_profile_synthetic',
    },
    {
      nodeId: 'data_asset:non-sensitive-summary',
      kind: 'data_asset',
      label: 'Aggregated Non-Sensitive Report Summary',
      tenantId: 'payments-lab',
      scope: 'reporting-public',
      dataClassification: 'PUBLIC',
      trustZone: 'INTERNAL',
      isRestrictedAsset: false,
      sourceRef:
        'policies/payments-lab/unsafe-rollout.policy.yaml#assets.non_sensitive_summary',
    },
    {
      nodeId: 'data_asset:customer-payment-pii',
      kind: 'data_asset',
      label: 'Restricted Customer Payment & PII Vault',
      tenantId: 'payments-lab',
      scope: 'finance-core',
      dataClassification: 'RESTRICTED',
      trustZone: 'INTERNAL',
      isRestrictedAsset: true,
      sourceRef:
        'policies/payments-lab/unsafe-rollout.policy.yaml#assets.customer_payment_pii',
    },
    {
      nodeId: 'data_asset:payment-ledger-internal',
      kind: 'data_asset',
      label: 'Internal Settlement Ledger',
      tenantId: 'payments-lab',
      scope: 'finance-core',
      dataClassification: 'RESTRICTED',
      trustZone: 'INTERNAL',
      isRestrictedAsset: true,
      sourceRef:
        'policies/payments-lab/unsafe-rollout.policy.yaml#assets.payment_ledger_internal',
    },
    {
      nodeId: 'destination:external-report-sink',
      kind: 'destination',
      label: 'External Partner Reporting Sink',
      tenantId: 'payments-lab',
      scope: 'reporting-public',
      dataClassification: 'PUBLIC',
      allowedClassifications: ['PUBLIC'],
      trustZone: 'EXTERNAL',
      isUnauthorizedDestination: true,
      sourceRef:
        'policies/payments-lab/unsafe-rollout.policy.yaml#destinations.external_report_sink',
    },
  ],
  edges: [
    {
      edgeId: 'e-support-read-profile',
      from: 'identity:support-agent',
      to: 'data_asset:customer-profile-synthetic',
      kind: 'can_read',
      tenantId: 'payments-lab',
      scope: 'support-ops',
      conditions: {
        effect: 'ALLOW',
        active: true,
        requiredRoles: ['support-reader'],
      },
      sourceRef:
        'policies/payments-lab/unsafe-rollout.policy.yaml#edges.support_read_profile',
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      policyVersion: '2026.11.09-unsafe-rollout',
      dataClassification: 'INTERNAL',
    },
    {
      edgeId: 'e-support-invoke-exporter',
      from: 'identity:support-agent',
      to: 'mcp_tool:report-exporter',
      kind: 'can_invoke',
      tenantId: 'payments-lab',
      scope: 'reporting-public',
      conditions: {
        effect: 'ALLOW',
        active: true,
        allowedDataClassifications: ['PUBLIC'],
      },
      sourceRef:
        'policies/payments-lab/unsafe-rollout.policy.yaml#edges.support_invoke_exporter',
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      policyVersion: '2026.11.09-unsafe-rollout',
      dataClassification: 'PUBLIC',
    },
    {
      edgeId: 'e-exporter-read-summary',
      from: 'mcp_tool:report-exporter',
      to: 'data_asset:non-sensitive-summary',
      kind: 'can_read',
      tenantId: 'payments-lab',
      scope: 'reporting-public',
      conditions: {
        effect: 'ALLOW',
        active: true,
        allowedDataClassifications: ['PUBLIC'],
      },
      sourceRef:
        'policies/payments-lab/unsafe-rollout.policy.yaml#edges.exporter_read_summary',
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      policyVersion: '2026.11.09-unsafe-rollout',
      dataClassification: 'PUBLIC',
    },
    {
      edgeId: 'e-rollout-exporter-read-pii',
      from: 'mcp_tool:report-exporter',
      to: 'data_asset:customer-payment-pii',
      kind: 'can_read',
      tenantId: 'payments-lab',
      scope: 'reporting-public',
      conditions: {
        effect: 'ALLOW',
        active: true,
        requiredRoles: ['report-exporter'],
        allowedDataClassifications: ['PUBLIC', 'INTERNAL', 'RESTRICTED'],
      },
      sourceRef: 'policies/payments-lab/report-exporter-rollout.yaml#L24',
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      policyVersion: '2026.11.09-unsafe-rollout',
      dataClassification: 'RESTRICTED',
    },
    {
      edgeId: 'e-exporter-transfer-external',
      from: 'mcp_tool:report-exporter',
      to: 'destination:external-report-sink',
      kind: 'transfers_data_to',
      tenantId: 'payments-lab',
      scope: 'reporting-public',
      conditions: {
        effect: 'ALLOW',
        active: true,
        allowedDataClassifications: ['PUBLIC', 'INTERNAL', 'RESTRICTED'],
      },
      sourceRef: 'policies/payments-lab/report-exporter-rollout.yaml#L38',
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      policyVersion: '2026.11.09-unsafe-rollout',
      dataClassification: 'RESTRICTED',
    },
    {
      edgeId: 'e-finance-assume-processor',
      from: 'identity:finance-operator',
      to: 'service:finance-processor',
      kind: 'assumes_role',
      tenantId: 'payments-lab',
      scope: 'finance-core',
      conditions: {
        effect: 'ALLOW',
        active: true,
        requiredRoles: ['finance-operator'],
      },
      sourceRef:
        'policies/payments-lab/unsafe-rollout.policy.yaml#edges.finance_assume_processor',
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      policyVersion: '2026.11.09-unsafe-rollout',
      dataClassification: 'RESTRICTED',
    },
    {
      edgeId: 'e-finance-read-payment-pii',
      from: 'service:finance-processor',
      to: 'data_asset:customer-payment-pii',
      kind: 'can_read',
      tenantId: 'payments-lab',
      scope: 'finance-core',
      conditions: {
        effect: 'ALLOW',
        active: true,
        requiredRoles: ['payment-processor'],
      },
      sourceRef:
        'policies/payments-lab/unsafe-rollout.policy.yaml#edges.finance_read_payment_pii',
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      policyVersion: '2026.11.09-unsafe-rollout',
      dataClassification: 'RESTRICTED',
    },
    {
      edgeId: 'e-finance-write-ledger',
      from: 'service:finance-processor',
      to: 'data_asset:payment-ledger-internal',
      kind: 'can_write',
      tenantId: 'payments-lab',
      scope: 'finance-core',
      conditions: {
        effect: 'ALLOW',
        active: true,
        networkZone: 'INTERNAL',
      },
      sourceRef:
        'policies/payments-lab/unsafe-rollout.policy.yaml#edges.finance_write_ledger',
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      policyVersion: '2026.11.09-unsafe-rollout',
      dataClassification: 'RESTRICTED',
    },
  ],
  legitimateOperations: BASELINE_FIXTURE.legitimateOperations,
};

export const REMEDIATED_FIXTURE: PolicyGraphFixture = {
  schemaVersion: 'chainbreak.graph.v1',
  fixtureId: 'payments-lab/remediated',
  tenantId: 'payments-lab',
  policyVersion: '2026.11.09-remediated',
  declaredInputSha256:
    '49dfd23089baf48d8d86e323f5604cbba6d33d81dbac42cebbb071ecc932b5d1',
  description:
    'Payments Lab remediated: removes the excessive rollout edge e-rollout-exporter-read-pii and restores PUBLIC classification ceiling on external report transfer, preserving all legitimate operations.',
  startIdentities: ['identity:support-agent', 'identity:finance-operator'],
  policies: [
    {
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      description:
        'RESTRICTED payment and PII data assets must never be transferred to EXTERNAL trust-zone destinations lacking explicit RESTRICTED clearance.',
      forbiddenTargetClassification: 'RESTRICTED',
      forbiddenDestinationTrustZone: 'EXTERNAL',
      riskRecommendation: 'P1',
      policyVersion: '2026.11.09-remediated',
      sourceRef:
        'policies/payments-lab/remediated.policy.yaml#rules.no_restricted_external',
    },
  ],
  nodes: [
    {
      nodeId: 'identity:support-agent',
      kind: 'identity',
      label: 'Support Agent Identity',
      tenantId: 'payments-lab',
      scope: 'support-ops',
      allowedScopes: ['support-ops', 'reporting-public'],
      roles: ['support-reader'],
      trustZone: 'INTERNAL',
      isEntryIdentity: true,
      sourceRef:
        'policies/payments-lab/remediated.policy.yaml#identities.support_agent',
    },
    {
      nodeId: 'identity:finance-operator',
      kind: 'identity',
      label: 'Finance Operator Identity',
      tenantId: 'payments-lab',
      scope: 'finance-core',
      allowedScopes: ['finance-core'],
      roles: ['finance-operator'],
      trustZone: 'INTERNAL',
      isEntryIdentity: true,
      sourceRef:
        'policies/payments-lab/remediated.policy.yaml#identities.finance_operator',
    },
    {
      nodeId: 'mcp_tool:report-exporter',
      kind: 'mcp_tool',
      label: 'MCP Report Exporter Tool',
      tenantId: 'payments-lab',
      scope: 'reporting-public',
      roles: ['report-exporter'],
      trustZone: 'INTERNAL',
      sourceRef:
        'policies/payments-lab/remediated.policy.yaml#tools.report_exporter',
    },
    {
      nodeId: 'service:finance-processor',
      kind: 'service',
      label: 'Finance Payment Processor Service',
      tenantId: 'payments-lab',
      scope: 'finance-core',
      roles: ['payment-processor'],
      trustZone: 'INTERNAL',
      sourceRef:
        'policies/payments-lab/remediated.policy.yaml#services.finance_processor',
    },
    {
      nodeId: 'data_asset:customer-profile-synthetic',
      kind: 'data_asset',
      label: 'Synthetic Customer Support Profile',
      tenantId: 'payments-lab',
      scope: 'support-ops',
      dataClassification: 'INTERNAL',
      trustZone: 'INTERNAL',
      isRestrictedAsset: false,
      sourceRef:
        'policies/payments-lab/remediated.policy.yaml#assets.customer_profile_synthetic',
    },
    {
      nodeId: 'data_asset:non-sensitive-summary',
      kind: 'data_asset',
      label: 'Aggregated Non-Sensitive Report Summary',
      tenantId: 'payments-lab',
      scope: 'reporting-public',
      dataClassification: 'PUBLIC',
      trustZone: 'INTERNAL',
      isRestrictedAsset: false,
      sourceRef:
        'policies/payments-lab/remediated.policy.yaml#assets.non_sensitive_summary',
    },
    {
      nodeId: 'data_asset:customer-payment-pii',
      kind: 'data_asset',
      label: 'Restricted Customer Payment & PII Vault',
      tenantId: 'payments-lab',
      scope: 'finance-core',
      dataClassification: 'RESTRICTED',
      trustZone: 'INTERNAL',
      isRestrictedAsset: true,
      sourceRef:
        'policies/payments-lab/remediated.policy.yaml#assets.customer_payment_pii',
    },
    {
      nodeId: 'data_asset:payment-ledger-internal',
      kind: 'data_asset',
      label: 'Internal Settlement Ledger',
      tenantId: 'payments-lab',
      scope: 'finance-core',
      dataClassification: 'RESTRICTED',
      trustZone: 'INTERNAL',
      isRestrictedAsset: true,
      sourceRef:
        'policies/payments-lab/remediated.policy.yaml#assets.payment_ledger_internal',
    },
    {
      nodeId: 'destination:external-report-sink',
      kind: 'destination',
      label: 'External Partner Reporting Sink',
      tenantId: 'payments-lab',
      scope: 'reporting-public',
      dataClassification: 'PUBLIC',
      allowedClassifications: ['PUBLIC'],
      trustZone: 'EXTERNAL',
      isUnauthorizedDestination: true,
      sourceRef:
        'policies/payments-lab/remediated.policy.yaml#destinations.external_report_sink',
    },
  ],
  edges: [
    {
      edgeId: 'e-support-read-profile',
      from: 'identity:support-agent',
      to: 'data_asset:customer-profile-synthetic',
      kind: 'can_read',
      tenantId: 'payments-lab',
      scope: 'support-ops',
      conditions: {
        effect: 'ALLOW',
        active: true,
        requiredRoles: ['support-reader'],
      },
      sourceRef:
        'policies/payments-lab/remediated.policy.yaml#edges.support_read_profile',
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      policyVersion: '2026.11.09-remediated',
      dataClassification: 'INTERNAL',
    },
    {
      edgeId: 'e-support-invoke-exporter',
      from: 'identity:support-agent',
      to: 'mcp_tool:report-exporter',
      kind: 'can_invoke',
      tenantId: 'payments-lab',
      scope: 'reporting-public',
      conditions: {
        effect: 'ALLOW',
        active: true,
        allowedDataClassifications: ['PUBLIC'],
      },
      sourceRef:
        'policies/payments-lab/remediated.policy.yaml#edges.support_invoke_exporter',
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      policyVersion: '2026.11.09-remediated',
      dataClassification: 'PUBLIC',
    },
    {
      edgeId: 'e-exporter-read-summary',
      from: 'mcp_tool:report-exporter',
      to: 'data_asset:non-sensitive-summary',
      kind: 'can_read',
      tenantId: 'payments-lab',
      scope: 'reporting-public',
      conditions: {
        effect: 'ALLOW',
        active: true,
        allowedDataClassifications: ['PUBLIC'],
      },
      sourceRef:
        'policies/payments-lab/remediated.policy.yaml#edges.exporter_read_summary',
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      policyVersion: '2026.11.09-remediated',
      dataClassification: 'PUBLIC',
    },
    {
      edgeId: 'e-exporter-transfer-external',
      from: 'mcp_tool:report-exporter',
      to: 'destination:external-report-sink',
      kind: 'transfers_data_to',
      tenantId: 'payments-lab',
      scope: 'reporting-public',
      conditions: {
        effect: 'ALLOW',
        active: true,
        allowedDataClassifications: ['PUBLIC'],
      },
      sourceRef:
        'policies/payments-lab/remediated.policy.yaml#edges.exporter_transfer_external',
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      policyVersion: '2026.11.09-remediated',
      dataClassification: 'PUBLIC',
    },
    {
      edgeId: 'e-finance-assume-processor',
      from: 'identity:finance-operator',
      to: 'service:finance-processor',
      kind: 'assumes_role',
      tenantId: 'payments-lab',
      scope: 'finance-core',
      conditions: {
        effect: 'ALLOW',
        active: true,
        requiredRoles: ['finance-operator'],
      },
      sourceRef:
        'policies/payments-lab/remediated.policy.yaml#edges.finance_assume_processor',
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      policyVersion: '2026.11.09-remediated',
      dataClassification: 'RESTRICTED',
    },
    {
      edgeId: 'e-finance-read-payment-pii',
      from: 'service:finance-processor',
      to: 'data_asset:customer-payment-pii',
      kind: 'can_read',
      tenantId: 'payments-lab',
      scope: 'finance-core',
      conditions: {
        effect: 'ALLOW',
        active: true,
        requiredRoles: ['payment-processor'],
      },
      sourceRef:
        'policies/payments-lab/remediated.policy.yaml#edges.finance_read_payment_pii',
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      policyVersion: '2026.11.09-remediated',
      dataClassification: 'RESTRICTED',
    },
    {
      edgeId: 'e-finance-write-ledger',
      from: 'service:finance-processor',
      to: 'data_asset:payment-ledger-internal',
      kind: 'can_write',
      tenantId: 'payments-lab',
      scope: 'finance-core',
      conditions: {
        effect: 'ALLOW',
        active: true,
        networkZone: 'INTERNAL',
      },
      sourceRef:
        'policies/payments-lab/remediated.policy.yaml#edges.finance_write_ledger',
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      policyVersion: '2026.11.09-remediated',
      dataClassification: 'RESTRICTED',
    },
  ],
  legitimateOperations: BASELINE_FIXTURE.legitimateOperations,
};

export const NEGATIVE_CONTROL_FIXTURE: PolicyGraphFixture = {
  schemaVersion: 'chainbreak.graph.v1',
  fixtureId: 'payments-lab/negative-control',
  tenantId: 'payments-lab',
  policyVersion: '2026.11.09-negative-control',
  declaredInputSha256:
    '156320fa4255cd72eb812ed0186833c2c06d915ceeb33da34717291ee40bc2e1',
  description:
    'Payments Lab negative control: structural edges exist in the graph, but incompatible edge types, mismatched scopes, unsatisfied conditions (MFA/explicit grant/DENY), and missing data acquisition prevent valid attack paths (must return 0 paths).',
  startIdentities: ['identity:support-agent', 'identity:auditor-agent'],
  policies: [
    {
      policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      description:
        'RESTRICTED payment and PII data assets must never be transferred to EXTERNAL trust-zone destinations lacking explicit RESTRICTED clearance.',
      forbiddenTargetClassification: 'RESTRICTED',
      forbiddenDestinationTrustZone: 'EXTERNAL',
      riskRecommendation: 'P1',
      policyVersion: '2026.11.09-negative-control',
      sourceRef:
        'policies/payments-lab/negative-control.policy.yaml#rules.no_restricted_external',
    },
  ],
  nodes: [
    {
      nodeId: 'identity:support-agent',
      kind: 'identity',
      label: 'Support Agent Identity',
      tenantId: 'payments-lab',
      scope: 'support-ops',
      allowedScopes: ['support-ops', 'reporting-public'],
      roles: ['support-reader'],
      trustZone: 'INTERNAL',
      isEntryIdentity: true,
      sourceRef:
        'policies/payments-lab/negative-control.policy.yaml#identities.support_agent',
    },
    {
      nodeId: 'identity:auditor-agent',
      kind: 'identity',
      label: 'Auditor Agent Identity',
      tenantId: 'payments-lab',
      scope: 'audit-ops',
      allowedScopes: ['audit-ops'],
      roles: ['auditor'],
      trustZone: 'INTERNAL',
      isEntryIdentity: true,
      sourceRef:
        'policies/payments-lab/negative-control.policy.yaml#identities.auditor_agent',
    },
    {
      nodeId: 'mcp_tool:report-exporter',
      kind: 'mcp_tool',
      label: 'MCP Report Exporter Tool',
      tenantId: 'payments-lab',
      scope: 'reporting-public',
      roles: ['report-exporter'],
      trustZone: 'INTERNAL',
      sourceRef:
        'policies/payments-lab/negative-control.policy.yaml#tools.report_exporter',
    },
    {
      nodeId: 'service:audit-exporter',
      kind: 'service',
      label: 'Audit Export Service',
      tenantId: 'payments-lab',
      scope: 'audit-ops',
      roles: ['audit-exporter'],
      trustZone: 'INTERNAL',
      sourceRef:
        'policies/payments-lab/negative-control.policy.yaml#services.audit_exporter',
    },
    {
      nodeId: 'data_asset:customer-payment-pii',
      kind: 'data_asset',
      label: 'Restricted Customer Payment & PII Vault',
      tenantId: 'payments-lab',
      scope: 'finance-core',
      dataClassification: 'RESTRICTED',
      trustZone: 'INTERNAL',
      isRestrictedAsset: true,
      sourceRef:
        'policies/payments-lab/negative-control.policy.yaml#assets.customer_payment_pii',
    },
    {
      nodeId: 'destination:external-report-sink',
      kind: 'destination',
      label: 'External Partner Reporting Sink',
      tenantId: 'payments-lab',
      scope: 'reporting-public',
      dataClassification: 'PUBLIC',
      allowedClassifications: ['PUBLIC'],
      trustZone: 'EXTERNAL',
      isUnauthorizedDestination: true,
      sourceRef:
        'policies/payments-lab/negative-control.policy.yaml#destinations.external_report_sink',
    },
  ],
  edges: [
    {
      edgeId: 'e-neg-incompatible-read-dest',
      from: 'identity:support-agent',
      to: 'destination:external-report-sink',
      kind: 'can_read',
      tenantId: 'payments-lab',
      scope: 'support-ops',
      conditions: { effect: 'ALLOW', active: true },
      sourceRef:
        'policies/payments-lab/negative-control.policy.yaml#edges.incompatible_read_dest',
      policyVersion: '2026.11.09-negative-control',
      dataClassification: 'RESTRICTED',
    },
    {
      edgeId: 'e-neg-incompatible-invoke-asset',
      from: 'mcp_tool:report-exporter',
      to: 'data_asset:customer-payment-pii',
      kind: 'can_invoke',
      tenantId: 'payments-lab',
      scope: 'reporting-public',
      conditions: { effect: 'ALLOW', active: true },
      sourceRef:
        'policies/payments-lab/negative-control.policy.yaml#edges.incompatible_invoke_asset',
      policyVersion: '2026.11.09-negative-control',
      dataClassification: 'RESTRICTED',
    },
    {
      edgeId: 'e-neg-support-invoke-exporter',
      from: 'identity:support-agent',
      to: 'mcp_tool:report-exporter',
      kind: 'can_invoke',
      tenantId: 'payments-lab',
      scope: 'reporting-public',
      conditions: { effect: 'ALLOW', active: true },
      sourceRef:
        'policies/payments-lab/negative-control.policy.yaml#edges.support_invoke_exporter',
      policyVersion: '2026.11.09-negative-control',
      dataClassification: 'RESTRICTED',
    },
    {
      edgeId: 'e-neg-scope-mismatched-read',
      from: 'mcp_tool:report-exporter',
      to: 'data_asset:customer-payment-pii',
      kind: 'can_read',
      tenantId: 'payments-lab',
      scope: 'finance-core',
      conditions: { effect: 'ALLOW', active: true },
      sourceRef:
        'policies/payments-lab/negative-control.policy.yaml#edges.scope_mismatched_read',
      policyVersion: '2026.11.09-negative-control',
      dataClassification: 'RESTRICTED',
    },
    {
      edgeId: 'e-neg-transfer-without-read',
      from: 'mcp_tool:report-exporter',
      to: 'destination:external-report-sink',
      kind: 'transfers_data_to',
      tenantId: 'payments-lab',
      scope: 'reporting-public',
      conditions: { effect: 'ALLOW', active: true },
      sourceRef:
        'policies/payments-lab/negative-control.policy.yaml#edges.transfer_without_read',
      policyVersion: '2026.11.09-negative-control',
      dataClassification: 'RESTRICTED',
    },
    {
      edgeId: 'e-neg-audit-invoke',
      from: 'identity:auditor-agent',
      to: 'service:audit-exporter',
      kind: 'can_invoke',
      tenantId: 'payments-lab',
      scope: 'audit-ops',
      conditions: { effect: 'ALLOW', active: true },
      sourceRef:
        'policies/payments-lab/negative-control.policy.yaml#edges.audit_invoke',
      policyVersion: '2026.11.09-negative-control',
      dataClassification: 'RESTRICTED',
    },
    {
      edgeId: 'e-neg-unsatisfied-mfa-grant',
      from: 'service:audit-exporter',
      to: 'data_asset:customer-payment-pii',
      kind: 'can_read',
      tenantId: 'payments-lab',
      scope: 'audit-ops',
      conditions: {
        effect: 'ALLOW',
        active: true,
        requiresMfa: true,
        mfaVerified: false,
        requiresExplicitGrant: true,
        explicitGrantPresent: false,
      },
      sourceRef:
        'policies/payments-lab/negative-control.policy.yaml#edges.unsatisfied_mfa_grant',
      policyVersion: '2026.11.09-negative-control',
      dataClassification: 'RESTRICTED',
    },
    {
      edgeId: 'e-neg-explicit-deny-transfer',
      from: 'service:audit-exporter',
      to: 'destination:external-report-sink',
      kind: 'transfers_data_to',
      tenantId: 'payments-lab',
      scope: 'audit-ops',
      conditions: {
        effect: 'DENY',
        active: true,
      },
      sourceRef:
        'policies/payments-lab/negative-control.policy.yaml#edges.explicit_deny_transfer',
      policyVersion: '2026.11.09-negative-control',
      dataClassification: 'RESTRICTED',
    },
  ],
  legitimateOperations: [],
};

export const LAB_FIXTURES: Record<CanonicalFixtureId, PolicyGraphFixture> = {
  'payments-lab/baseline': BASELINE_FIXTURE,
  'payments-lab/unsafe-rollout': UNSAFE_ROLLOUT_FIXTURE,
  'payments-lab/remediated': REMEDIATED_FIXTURE,
  'payments-lab/negative-control': NEGATIVE_CONTROL_FIXTURE,
};
