/**
 * Fixer SLOP Agent
 *
 * SLOP-native agent that generates fixes for security findings.
 * Supports version bumps, code changes, and configuration fixes.
 */

import { execSync } from 'child_process';
import { SLOPAgent } from './base.js';
import {
  SLOPAgentConfig,
  SLOPTool,
  SLOPToolCall,
  SLOPToolResult,
  Finding,
  FixResult,
  FixBatchResult,
  FixStrategy,
  ApplyFixResult,
} from './types.js';

const FIXER_TOOLS: SLOPTool[] = [
  {
    name: 'suggest-fix',
    description: 'Analyze a finding and suggest how to fix it',
    parameters: {
      finding: { type: 'object', description: 'The finding to fix', required: true },
      context: { type: 'object', description: 'Additional context (package.json path, etc.)', required: false },
    },
  },
  {
    name: 'suggest-fixes-batch',
    description: 'Suggest fixes for multiple findings at once',
    parameters: {
      findings: { type: 'array', description: 'Array of findings to fix', required: true },
      context: { type: 'object', description: 'Additional context', required: false },
    },
  },
  {
    name: 'apply-fix',
    description: 'Apply a fix locally (run commands, modify files)',
    parameters: {
      fix: { type: 'object', description: 'The fix result to apply', required: true },
      dryRun: { type: 'boolean', description: 'If true, show what would be done without doing it', required: false },
    },
  },
  {
    name: 'generate-pr-description',
    description: 'Generate a PR description for a set of fixes',
    parameters: {
      fixes: { type: 'array', description: 'Array of fix results', required: true },
    },
  },
  {
    name: 'get-stats',
    description: 'Get fixer statistics',
    parameters: {},
  },
];

// Known version fixes for common CVEs
const KNOWN_FIXES: Record<string, { package: string; minVersion: string }> = {
  'CVE-2021-44906': { package: 'minimist', minVersion: '1.2.6' },
  'CVE-2020-7610': { package: 'bson', minVersion: '1.1.4' },
  'CVE-2019-10746': { package: 'mixin-deep', minVersion: '2.0.1' },
  'CVE-2019-10747': { package: 'set-value', minVersion: '4.0.1' },
  'CVE-2020-8203': { package: 'lodash', minVersion: '4.17.19' },
  'CVE-2021-23337': { package: 'lodash', minVersion: '4.17.21' },
  'CVE-2019-10744': { package: 'lodash', minVersion: '4.17.12' },
  'CVE-2018-16487': { package: 'lodash', minVersion: '4.17.11' },
  'CVE-2020-28500': { package: 'lodash', minVersion: '4.17.21' },
  'CVE-2021-44228': { package: 'log4j-core', minVersion: '2.17.0' },
  'CVE-2022-22965': { package: 'spring-beans', minVersion: '5.3.18' },
};

export class FixerAgent extends SLOPAgent {
  private stats = {
    analyzed: 0,
    fixable: 0,
    unfixable: 0,
    applied: 0,
  };

  constructor(config: Partial<SLOPAgentConfig> = {}) {
    super(
      {
        id: config.id || 'fixer-agent',
        name: config.name || 'Fixer Agent',
        port: config.port || 3012,
        description: 'Security fixer agent - generates and applies fixes for vulnerabilities',
        coordinatorUrl: config.coordinatorUrl,
        peers: config.peers,
      },
      FIXER_TOOLS
    );
  }

  async handleToolCall(call: SLOPToolCall): Promise<SLOPToolResult> {
    console.log(`[Fixer] Tool call: ${call.tool}`, call.arguments);

    try {
      switch (call.tool) {
        case 'suggest-fix':
          return { result: await this.suggestFix(call.arguments.finding as Finding, call.arguments.context as Record<string, unknown>) };
        case 'suggest-fixes-batch':
          return { result: await this.suggestFixesBatch(call.arguments.findings as Finding[], call.arguments.context as Record<string, unknown>) };
        case 'apply-fix':
          return { result: await this.applyFix(call.arguments.fix as FixResult, call.arguments.dryRun as boolean) };
        case 'generate-pr-description':
          return { result: this.generatePRDescription(call.arguments.fixes as FixResult[]) };
        case 'get-stats':
          return { result: this.stats };
        default:
          return { error: `Unknown tool: ${call.tool}` };
      }
    } catch (error) {
      return { error: String(error) };
    }
  }

  private async suggestFix(finding: Finding, context?: Record<string, unknown>): Promise<FixResult> {
    this.stats.analyzed++;

    // Determine fix strategy based on finding type
    if (finding.type === 'vulnerability' && finding.package) {
      return this.suggestPackageFix(finding, context);
    } else if (finding.type === 'secret') {
      return this.suggestSecretFix(finding, context);
    } else if (finding.type === 'code-issue') {
      return this.suggestCodeFix(finding, context);
    } else {
      return this.suggestManualFix(finding);
    }
  }

  private suggestPackageFix(finding: Finding, context?: Record<string, unknown>): FixResult {
    const pkg = finding.package!;
    const currentVersion = finding.version || 'unknown';
    let fixedVersion: string | undefined;
    let confidence = 0.5;

    // Check if we have a known fix for this CVE
    if (finding.cve && KNOWN_FIXES[finding.cve]) {
      const knownFix = KNOWN_FIXES[finding.cve];
      if (knownFix.package.toLowerCase() === pkg.toLowerCase()) {
        fixedVersion = knownFix.minVersion;
        confidence = 0.95;
      }
    }

    // Try to get fix info from metadata
    if (!fixedVersion && finding.metadata?.fixedVersion) {
      fixedVersion = finding.metadata.fixedVersion as string;
      confidence = 0.85;
    }

    // If still no fix, suggest latest
    if (!fixedVersion) {
      fixedVersion = 'latest';
      confidence = 0.6;
    }

    const isNpm = !context?.packageManager || context?.packageManager === 'npm';
    const command = isNpm
      ? `npm install ${pkg}@${fixedVersion}`
      : `yarn add ${pkg}@${fixedVersion}`;

    const diff = `  "${pkg}": "${currentVersion}"
+ "${pkg}": "${fixedVersion}"`;

    this.stats.fixable++;

    return {
      findingId: finding.id,
      finding,
      fixable: true,
      strategy: 'version-bump',
      package: pkg,
      currentVersion,
      fixedVersion,
      description: `Update ${pkg} from ${currentVersion} to ${fixedVersion}`,
      explanation: finding.cve
        ? `This fixes ${finding.cve}. The vulnerability in ${pkg}@${currentVersion} is patched in version ${fixedVersion}.`
        : `Updating to ${fixedVersion} should resolve the security issue.`,
      commands: [command],
      diff,
      confidence,
      breakingChangeRisk: this.assessBreakingChangeRisk(currentVersion, fixedVersion),
      testRequired: true,
      autoFixSafe: confidence >= 0.8 && this.assessBreakingChangeRisk(currentVersion, fixedVersion) === 'low',
    };
  }

  private suggestSecretFix(finding: Finding, context?: Record<string, unknown>): FixResult {
    const file = finding.file || 'unknown';
    const line = finding.line || 0;
    const secretType = String(finding.metadata?.rule || finding.title || 'secret').toLowerCase();

    // Determine the type of secret and suggest appropriate fix
    let envVarName = 'SECRET_KEY';
    let explanation = '';

    if (secretType.includes('aws') || secretType.includes('akia')) {
      envVarName = 'AWS_ACCESS_KEY_ID';
      explanation = 'AWS credentials should never be hardcoded. Use environment variables or AWS IAM roles.';
    } else if (secretType.includes('private-key') || secretType.includes('rsa')) {
      envVarName = 'PRIVATE_KEY_PATH';
      explanation = 'Private keys should be stored in secure locations and referenced via path, not embedded in code.';
    } else if (secretType.includes('api-key') || secretType.includes('api_key')) {
      envVarName = 'API_KEY';
      explanation = 'API keys should be stored in environment variables or a secrets manager.';
    } else if (secretType.includes('password')) {
      envVarName = 'DB_PASSWORD';
      explanation = 'Passwords should never be hardcoded. Use environment variables or a secrets manager.';
    } else if (secretType.includes('token')) {
      envVarName = 'AUTH_TOKEN';
      explanation = 'Tokens should be stored in environment variables or a secrets manager.';
    }

    this.stats.fixable++;

    return {
      findingId: finding.id,
      finding,
      fixable: true,
      strategy: 'env-var',
      description: `Replace hardcoded secret with environment variable ${envVarName}`,
      explanation: `${explanation}\n\nReplace the hardcoded value at ${file}:${line} with process.env.${envVarName} and set the actual value in your environment or .env file (which should be in .gitignore).`,
      commands: [
        `# Add to .env (do NOT commit this file):`,
        `echo "${envVarName}=your-secret-here" >> .env`,
        `# Make sure .env is in .gitignore:`,
        `echo ".env" >> .gitignore`,
      ],
      diff: `- const secret = "hardcoded-value";
+ const secret = process.env.${envVarName};`,
      confidence: 0.9,
      breakingChangeRisk: 'low',
      testRequired: true,
      autoFixSafe: false, // Secrets require manual review
    };
  }

  private suggestCodeFix(finding: Finding, context?: Record<string, unknown>): FixResult {
    const cwe = finding.cwe || '';
    let description = 'Review and fix the code issue';
    let explanation = finding.description;
    let diff = '';

    // Common code issue fixes
    if (cwe.includes('CWE-89') || finding.title.toLowerCase().includes('sql injection')) {
      description = 'Use parameterized queries instead of string concatenation';
      explanation = 'SQL injection can be prevented by using parameterized queries or prepared statements.';
      diff = `- db.query("SELECT * FROM users WHERE id = " + userId);
+ db.query("SELECT * FROM users WHERE id = ?", [userId]);`;
    } else if (cwe.includes('CWE-79') || finding.title.toLowerCase().includes('xss')) {
      description = 'Sanitize user input before rendering';
      explanation = 'XSS can be prevented by escaping HTML entities in user-provided content.';
      diff = `- element.innerHTML = userInput;
+ element.textContent = userInput; // Or use a sanitization library`;
    } else if (cwe.includes('CWE-22') || finding.title.toLowerCase().includes('path traversal')) {
      description = 'Validate and sanitize file paths';
      explanation = 'Path traversal can be prevented by validating that resolved paths stay within expected directories.';
      diff = `- const filePath = basePath + userInput;
+ const filePath = path.join(basePath, path.basename(userInput));`;
    }

    this.stats.fixable++;

    return {
      findingId: finding.id,
      finding,
      fixable: true,
      strategy: 'code-change',
      description,
      explanation,
      commands: [],
      diff,
      confidence: 0.7,
      breakingChangeRisk: 'medium',
      testRequired: true,
      autoFixSafe: false,
    };
  }

  private suggestManualFix(finding: Finding): FixResult {
    this.stats.unfixable++;

    return {
      findingId: finding.id,
      finding,
      fixable: false,
      strategy: 'manual',
      description: 'This issue requires manual review and fixing',
      explanation: `Unable to automatically generate a fix for this ${finding.type} issue. Please review the finding details and apply an appropriate fix manually.`,
      commands: [],
      confidence: 0,
      breakingChangeRisk: 'medium',
      testRequired: true,
      autoFixSafe: false,
    };
  }

  private async suggestFixesBatch(findings: Finding[], context?: Record<string, unknown>): Promise<FixBatchResult> {
    const fixes: FixResult[] = [];
    const allCommands: string[] = [];
    const npmUpdates: Map<string, string> = new Map();

    for (const finding of findings) {
      const fix = await this.suggestFix(finding, context);
      fixes.push(fix);

      // Collect npm updates for batch command
      if (fix.strategy === 'version-bump' && fix.package && fix.fixedVersion) {
        // Keep the highest version if same package appears multiple times
        const existing = npmUpdates.get(fix.package);
        if (!existing || this.compareVersions(fix.fixedVersion, existing) > 0) {
          npmUpdates.set(fix.package, fix.fixedVersion);
        }
      }
    }

    // Generate combined npm install command
    if (npmUpdates.size > 0) {
      const packages = Array.from(npmUpdates.entries())
        .map(([pkg, version]) => `${pkg}@${version}`)
        .join(' ');
      allCommands.push(`npm install ${packages}`);
    }

    // Add non-npm commands
    for (const fix of fixes) {
      if (fix.strategy !== 'version-bump' && fix.commands.length > 0) {
        allCommands.push(...fix.commands);
      }
    }

    const summary = {
      versionBumps: fixes.filter((f) => f.strategy === 'version-bump').length,
      codeChanges: fixes.filter((f) => f.strategy === 'code-change').length,
      configChanges: fixes.filter((f) => f.strategy === 'config-change' || f.strategy === 'env-var').length,
      manual: fixes.filter((f) => f.strategy === 'manual').length,
    };

    return {
      total: fixes.length,
      fixable: fixes.filter((f) => f.fixable).length,
      unfixable: fixes.filter((f) => !f.fixable).length,
      fixes,
      summary,
      allCommands,
    };
  }

  private async applyFix(fix: FixResult, dryRun = false): Promise<ApplyFixResult> {
    if (!fix.fixable || fix.commands.length === 0) {
      return {
        findingId: fix.findingId,
        success: false,
        applied: false,
        error: 'No applicable commands for this fix',
      };
    }

    if (dryRun) {
      return {
        findingId: fix.findingId,
        success: true,
        applied: false,
        output: `[DRY RUN] Would execute:\n${fix.commands.join('\n')}`,
      };
    }

    // Only apply version bumps automatically
    if (fix.strategy !== 'version-bump') {
      return {
        findingId: fix.findingId,
        success: false,
        applied: false,
        error: `Strategy '${fix.strategy}' requires manual application`,
      };
    }

    try {
      const command = fix.commands[0];
      console.log(`[Fixer] Applying fix: ${command}`);
      const output = execSync(command, { encoding: 'utf-8', timeout: 60000 });
      this.stats.applied++;

      return {
        findingId: fix.findingId,
        success: true,
        applied: true,
        output,
      };
    } catch (error) {
      return {
        findingId: fix.findingId,
        success: false,
        applied: false,
        error: String(error),
      };
    }
  }

  private generatePRDescription(fixes: FixResult[]): string {
    const fixable = fixes.filter((f) => f.fixable);
    const versionBumps = fixable.filter((f) => f.strategy === 'version-bump');

    let description = `## Security Fixes\n\n`;
    description += `This PR addresses **${fixable.length}** security ${fixable.length === 1 ? 'issue' : 'issues'}.\n\n`;

    if (versionBumps.length > 0) {
      description += `### Dependency Updates\n\n`;
      description += `| Package | From | To | CVE |\n`;
      description += `|---------|------|-----|-----|\n`;

      for (const fix of versionBumps) {
        const cve = fix.finding.cve || 'N/A';
        description += `| ${fix.package} | ${fix.currentVersion} | ${fix.fixedVersion} | ${cve} |\n`;
      }
      description += `\n`;
    }

    const otherFixes = fixable.filter((f) => f.strategy !== 'version-bump');
    if (otherFixes.length > 0) {
      description += `### Other Fixes\n\n`;
      for (const fix of otherFixes) {
        description += `- **${fix.finding.title}**: ${fix.description}\n`;
      }
      description += `\n`;
    }

    description += `---\n`;
    description += `*Generated by [Aura Security](https://aurasecurity.io)*\n`;

    return description;
  }

  private assessBreakingChangeRisk(current: string, fixed: string): 'none' | 'low' | 'medium' | 'high' {
    if (fixed === 'latest') return 'high';

    // Parse semver (basic)
    const currentParts = current.replace(/[^\d.]/g, '').split('.').map(Number);
    const fixedParts = fixed.replace(/[^\d.]/g, '').split('.').map(Number);

    if (currentParts.length < 1 || fixedParts.length < 1) return 'medium';

    // Major version bump = high risk
    if (fixedParts[0] > currentParts[0]) return 'high';

    // Minor version bump = medium risk
    if (fixedParts[1] > (currentParts[1] || 0)) return 'medium';

    // Patch version bump = low risk
    return 'low';
  }

  private compareVersions(a: string, b: string): number {
    const aParts = a.replace(/[^\d.]/g, '').split('.').map(Number);
    const bParts = b.replace(/[^\d.]/g, '').split('.').map(Number);

    for (let i = 0; i < Math.max(aParts.length, bParts.length); i++) {
      const aVal = aParts[i] || 0;
      const bVal = bParts[i] || 0;
      if (aVal > bVal) return 1;
      if (aVal < bVal) return -1;
    }
    return 0;
  }
}

// Allow running as standalone
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = parseInt(process.env.PORT || '3012', 10);
  const agent = new FixerAgent({ port });
  agent.start();
}
