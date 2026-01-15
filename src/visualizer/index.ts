// SLOP Visualizer - Renders audit findings to console/terminal
// Slopcraft-style visualization

import type { AuditorOutput, AuditEvent, Severity, AgentState } from '../types/events.js';

const COLORS = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m',
  bgBlue: '\x1b[44m'
};

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: COLORS.bgRed + COLORS.white,
  high: COLORS.red,
  medium: COLORS.yellow,
  low: COLORS.green
};

const STATE_ICONS: Record<AgentState, string> = {
  idle: '○',
  analyzing: '◐',
  conflict: '⚡',
  escalated: '▲',
  blocked: '■'
};

const STATE_COLORS: Record<AgentState, string> = {
  idle: COLORS.dim,
  analyzing: COLORS.cyan,
  conflict: COLORS.yellow,
  escalated: COLORS.magenta,
  blocked: COLORS.red
};

export function visualize(output: AuditorOutput): string {
  const lines: string[] = [];

  // Header
  lines.push('');
  lines.push(`${COLORS.bright}╔══════════════════════════════════════════════════════════════╗${COLORS.reset}`);
  lines.push(`${COLORS.bright}║           SLOP AUDITOR - SECURITY ANALYSIS REPORT            ║${COLORS.reset}`);
  lines.push(`${COLORS.bright}╚══════════════════════════════════════════════════════════════╝${COLORS.reset}`);
  lines.push('');

  // Agent Status
  const stateColor = STATE_COLORS[output.agent_state];
  const stateIcon = STATE_ICONS[output.agent_state];
  lines.push(`${COLORS.bright}AGENT:${COLORS.reset} ${output.agent_id}`);
  lines.push(`${COLORS.bright}STATE:${COLORS.reset} ${stateColor}${stateIcon} ${output.agent_state.toUpperCase()}${COLORS.reset}`);
  lines.push('');

  // Findings Summary
  const criticalCount = output.events.filter(e => e.payload.severity === 'critical').length;
  const highCount = output.events.filter(e => e.payload.severity === 'high').length;
  const mediumCount = output.events.filter(e => e.payload.severity === 'medium').length;
  const lowCount = output.events.filter(e => e.payload.severity === 'low').length;

  lines.push(`${COLORS.bright}FINDINGS SUMMARY:${COLORS.reset}`);
  lines.push(`  ${SEVERITY_COLORS.critical} CRITICAL ${COLORS.reset} ${criticalCount}`);
  lines.push(`  ${SEVERITY_COLORS.high} HIGH ${COLORS.reset}     ${highCount}`);
  lines.push(`  ${SEVERITY_COLORS.medium} MEDIUM ${COLORS.reset}   ${mediumCount}`);
  lines.push(`  ${SEVERITY_COLORS.low} LOW ${COLORS.reset}      ${lowCount}`);
  lines.push('');

  // Events Detail
  lines.push(`${COLORS.bright}─────────────────────────────────────────────────────────────────${COLORS.reset}`);
  lines.push(`${COLORS.bright}EVENTS:${COLORS.reset}`);
  lines.push('');

  for (const event of output.events) {
    lines.push(formatEvent(event));
    lines.push('');
  }

  // Meta
  if (output.meta.assumptions.length > 0 || output.meta.uncertainties.length > 0) {
    lines.push(`${COLORS.bright}─────────────────────────────────────────────────────────────────${COLORS.reset}`);
    lines.push(`${COLORS.bright}META:${COLORS.reset}`);

    if (output.meta.assumptions.length > 0) {
      lines.push(`  ${COLORS.dim}Assumptions:${COLORS.reset}`);
      for (const a of output.meta.assumptions) {
        lines.push(`    • ${a}`);
      }
    }

    if (output.meta.uncertainties.length > 0) {
      lines.push(`  ${COLORS.dim}Uncertainties:${COLORS.reset}`);
      for (const u of output.meta.uncertainties) {
        lines.push(`    • ${u}`);
      }
    }
    lines.push('');
  }

  // Footer
  lines.push(`${COLORS.bright}═══════════════════════════════════════════════════════════════${COLORS.reset}`);

  return lines.join('\n');
}

function formatEvent(event: AuditEvent): string {
  const lines: string[] = [];
  const sevColor = SEVERITY_COLORS[event.payload.severity];

  // Event header
  lines.push(`  ${sevColor}[${event.payload.severity.toUpperCase()}]${COLORS.reset} ${COLORS.bright}${event.event_type}${COLORS.reset}`);
  lines.push(`  ${COLORS.dim}${event.timestamp}${COLORS.reset}`);
  lines.push('');

  // Claim
  lines.push(`  ${COLORS.cyan}CLAIM:${COLORS.reset} ${event.payload.claim}`);
  lines.push(`  ${COLORS.cyan}CONFIDENCE:${COLORS.reset} ${(event.payload.confidence * 100).toFixed(0)}%`);

  // Attack path
  if (event.payload.attack_path.length > 0) {
    lines.push(`  ${COLORS.cyan}ATTACK PATH:${COLORS.reset}`);
    for (let i = 0; i < event.payload.attack_path.length; i++) {
      const prefix = i === event.payload.attack_path.length - 1 ? '└─' : '├─';
      lines.push(`    ${prefix} ${event.payload.attack_path[i]}`);
    }
  }

  // Affected assets
  if (event.payload.affected_assets.length > 0) {
    lines.push(`  ${COLORS.cyan}AFFECTED:${COLORS.reset} ${event.payload.affected_assets.join(', ')}`);
  }

  // Assurance breaks
  if (event.payload.assurance_break.length > 0) {
    lines.push(`  ${COLORS.cyan}ASSURANCE BREAK:${COLORS.reset} ${event.payload.assurance_break.join(', ')}`);
  }

  // Evidence refs
  if (event.payload.evidence_refs.length > 0) {
    lines.push(`  ${COLORS.cyan}EVIDENCE:${COLORS.reset}`);
    for (const ref of event.payload.evidence_refs) {
      lines.push(`    • [${ref.type}] ${ref.pointer}`);
    }
  }

  return lines.join('\n');
}

// Simple ASCII visualization for state
export function visualizeState(state: AgentState): string {
  const frames: Record<AgentState, string[]> = {
    idle: [
      '    ○    ',
      '   ───   ',
      '  │   │  ',
      '  └───┘  '
    ],
    analyzing: [
      '    ◐    ',
      '   ╱─╲   ',
      '  │ ⚙ │  ',
      '  └───┘  '
    ],
    conflict: [
      '   ⚡⚡   ',
      '   ╱─╲   ',
      '  │ ! │  ',
      '  └───┘  '
    ],
    escalated: [
      '    ▲    ',
      '   ╱!╲   ',
      '  │ ▲ │  ',
      '  └───┘  '
    ],
    blocked: [
      '   ███   ',
      '   █■█   ',
      '  █ ✗ █  ',
      '   ███   '
    ]
  };

  const stateColor = STATE_COLORS[state];
  return frames[state].map(line => `${stateColor}${line}${COLORS.reset}`).join('\n');
}

export function visualizeCompact(output: AuditorOutput): string {
  const criticalCount = output.events.filter(e => e.payload.severity === 'critical').length;
  const highCount = output.events.filter(e => e.payload.severity === 'high').length;

  const stateColor = STATE_COLORS[output.agent_state];
  const stateIcon = STATE_ICONS[output.agent_state];

  let statusLine = `${stateColor}${stateIcon}${COLORS.reset} `;
  statusLine += `${output.agent_id} │ `;
  statusLine += `${stateColor}${output.agent_state.toUpperCase()}${COLORS.reset} │ `;

  if (criticalCount > 0) {
    statusLine += `${SEVERITY_COLORS.critical} ${criticalCount} CRIT ${COLORS.reset} `;
  }
  if (highCount > 0) {
    statusLine += `${SEVERITY_COLORS.high} ${highCount} HIGH ${COLORS.reset} `;
  }

  return statusLine;
}
