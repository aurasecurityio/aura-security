// Strict JSON Schema for Auditor Input validation

export const auditorInputSchema = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  type: 'object',
  required: ['change_event', 'evidence_bundle', 'policy_context'],
  additionalProperties: false,
  properties: {
    change_event: {
      type: 'object',
      required: ['id', 'type', 'environment', 'repo', 'commit', 'files_changed', 'diff'],
      additionalProperties: false,
      properties: {
        id: { type: 'string', minLength: 1 },
        type: { type: 'string', enum: ['pull_request', 'deploy', 'infra_change'] },
        environment: { type: 'string', enum: ['dev', 'staging', 'prod'] },
        repo: { type: 'string', minLength: 1 },
        commit: { type: 'string', pattern: '^[a-f0-9]{40}$' },
        files_changed: { type: 'array', items: { type: 'string' }, minItems: 1 },
        diff: { type: 'string' }
      }
    },
    evidence_bundle: {
      type: 'object',
      additionalProperties: false,
      properties: {
        sbom: { type: 'string' },
        vuln_scan: { type: 'string' },
        sast_results: { type: 'string' },
        iac_scan: { type: 'string' },
        provenance: { type: 'string' },
        runtime_delta: { type: 'string' }
      }
    },
    policy_context: {
      type: 'object',
      required: ['critical_assets', 'risk_tolerance'],
      additionalProperties: false,
      properties: {
        critical_assets: { type: 'array', items: { type: 'string' }, minItems: 1 },
        risk_tolerance: { type: 'string', enum: ['low', 'medium', 'high'] }
      }
    }
  }
} as const;
