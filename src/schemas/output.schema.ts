// Strict JSON Schema for Auditor Output validation

export const auditorOutputSchema = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  type: 'object',
  required: ['agent_id', 'agent_state', 'events', 'meta'],
  additionalProperties: false,
  properties: {
    agent_id: { type: 'string', const: 'exploit-reviewer' },
    agent_state: { type: 'string', enum: ['idle', 'analyzing', 'conflict', 'escalated', 'blocked'] },
    events: {
      type: 'array',
      items: {
        type: 'object',
        required: ['event_type', 'target', 'payload', 'timestamp'],
        additionalProperties: false,
        properties: {
          event_type: {
            type: 'string',
            enum: ['analysis_started', 'finding_raised', 'conflict_detected', 'escalation_triggered']
          },
          target: { type: 'string', minLength: 1 },
          payload: {
            type: 'object',
            required: ['severity', 'claim', 'attack_path', 'affected_assets', 'evidence_refs', 'assurance_break', 'confidence'],
            additionalProperties: false,
            properties: {
              severity: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] },
              claim: { type: 'string', minLength: 1 },
              attack_path: { type: 'array', items: { type: 'string' }, minItems: 1 },
              affected_assets: { type: 'array', items: { type: 'string' } },
              evidence_refs: {
                type: 'array',
                items: {
                  type: 'object',
                  required: ['type', 'pointer'],
                  additionalProperties: false,
                  properties: {
                    type: { type: 'string', enum: ['diff', 'sbom', 'scan', 'provenance', 'runtime'] },
                    pointer: { type: 'string', minLength: 1 }
                  }
                }
              },
              assurance_break: {
                type: 'array',
                items: { type: 'string', enum: ['integrity', 'access_control', 'isolation', 'auditability'] }
              },
              confidence: { type: 'number', minimum: 0, maximum: 1 }
            }
          },
          timestamp: { type: 'string', format: 'date-time' }
        }
      }
    },
    meta: {
      type: 'object',
      required: ['assumptions', 'uncertainties'],
      additionalProperties: false,
      properties: {
        assumptions: { type: 'array', items: { type: 'string' } },
        uncertainties: { type: 'array', items: { type: 'string' } }
      }
    }
  }
} as const;
