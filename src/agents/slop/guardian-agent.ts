/**
 * PR Guardian Agent - SLOP Native
 *
 * Real-time PR protection. Watches pull requests, blocks merging if
 * critical issues are found, and adds security comments.
 *
 * Tools:
 * - check-pr: Analyze a PR for security issues
 * - block-pr: Block a PR from merging
 * - approve-pr: Approve a PR after security review
 * - add-comment: Add security findings as PR comment
 * - create-check: Create GitHub/GitLab check run
 * - get-pr-status: Get security status of a PR
 */

import { SLOPAgent } from './base.js';
import {
  SLOPAgentConfig,
  SLOPTool,
  SLOPToolCall,
  SLOPToolResult,
  Finding,
} from './types.js';

// Guardian Types
export interface PRCheckResult {
  prId: string;
  repo: string;
  status: 'passed' | 'failed' | 'warning' | 'pending';
  blocked: boolean;
  blockReason?: string;
  findings: Finding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    secretsFound: number;
    newVulnerabilities: number;
  };
  recommendation: 'approve' | 'request-changes' | 'block';
  comment: string;
  checksCreated: string[];
  reviewedAt: string;
}

export interface PRPolicy {
  blockOnCritical: boolean;
  blockOnHigh: boolean;
  blockOnSecrets: boolean;
  requireApproval: boolean;
  autoComment: boolean;
  autoCreateChecks: boolean;
  exemptPaths: string[];
  exemptAuthors: string[];
}

export interface CheckRun {
  id: string;
  name: string;
  status: 'queued' | 'in_progress' | 'completed';
  conclusion?: 'success' | 'failure' | 'neutral' | 'cancelled' | 'skipped' | 'timed_out' | 'action_required';
  output: {
    title: string;
    summary: string;
    annotations: CheckAnnotation[];
  };
  url?: string;
}

export interface CheckAnnotation {
  path: string;
  start_line: number;
  end_line: number;
  annotation_level: 'notice' | 'warning' | 'failure';
  message: string;
  title: string;
}

const DEFAULT_POLICY: PRPolicy = {
  blockOnCritical: true,
  blockOnHigh: false,
  blockOnSecrets: true,
  requireApproval: true,
  autoComment: true,
  autoCreateChecks: true,
  exemptPaths: ['docs/', 'README.md', '.github/'],
  exemptAuthors: [],
};

const GUARDIAN_TOOLS: SLOPTool[] = [
  {
    name: 'check-pr',
    description: 'Analyze a pull request for security issues',
    parameters: {
      repo: {
        type: 'string',
        description: 'Repository (owner/repo)',
        required: true,
      },
      prNumber: {
        type: 'number',
        description: 'Pull request number',
        required: true,
      },
      policy: {
        type: 'object',
        description: 'Security policy overrides',
        required: false,
      },
    },
  },
  {
    name: 'block-pr',
    description: 'Block a PR from merging due to security issues',
    parameters: {
      repo: {
        type: 'string',
        description: 'Repository (owner/repo)',
        required: true,
      },
      prNumber: {
        type: 'number',
        description: 'Pull request number',
        required: true,
      },
      reason: {
        type: 'string',
        description: 'Reason for blocking',
        required: true,
      },
    },
  },
  {
    name: 'approve-pr',
    description: 'Approve a PR after security review',
    parameters: {
      repo: {
        type: 'string',
        description: 'Repository (owner/repo)',
        required: true,
      },
      prNumber: {
        type: 'number',
        description: 'Pull request number',
        required: true,
      },
      comment: {
        type: 'string',
        description: 'Approval comment',
        required: false,
      },
    },
  },
  {
    name: 'add-comment',
    description: 'Add security findings as a PR comment',
    parameters: {
      repo: {
        type: 'string',
        description: 'Repository (owner/repo)',
        required: true,
      },
      prNumber: {
        type: 'number',
        description: 'Pull request number',
        required: true,
      },
      findings: {
        type: 'array',
        description: 'Security findings to report',
        required: true,
      },
    },
  },
  {
    name: 'create-check',
    description: 'Create a GitHub check run for PR',
    parameters: {
      repo: {
        type: 'string',
        description: 'Repository (owner/repo)',
        required: true,
      },
      sha: {
        type: 'string',
        description: 'Commit SHA',
        required: true,
      },
      findings: {
        type: 'array',
        description: 'Security findings',
        required: true,
      },
    },
  },
  {
    name: 'get-pr-status',
    description: 'Get the security status of a PR',
    parameters: {
      repo: {
        type: 'string',
        description: 'Repository (owner/repo)',
        required: true,
      },
      prNumber: {
        type: 'number',
        description: 'Pull request number',
        required: true,
      },
    },
  },
  {
    name: 'set-policy',
    description: 'Set security policy for a repository',
    parameters: {
      repo: {
        type: 'string',
        description: 'Repository (owner/repo)',
        required: true,
      },
      policy: {
        type: 'object',
        description: 'Security policy settings',
        required: true,
      },
    },
  },
  {
    name: 'watch-prs',
    description: 'Start watching PRs for a repository',
    parameters: {
      repo: {
        type: 'string',
        description: 'Repository (owner/repo)',
        required: true,
      },
      webhookUrl: {
        type: 'string',
        description: 'Webhook URL for PR events',
        required: false,
      },
    },
  },
];

export class GuardianAgent extends SLOPAgent {
  private prResults: Map<string, PRCheckResult> = new Map();
  private policies: Map<string, PRPolicy> = new Map();
  private watchedRepos: Set<string> = new Set();
  private githubToken?: string;
  private scannerUrl?: string;
  private graderUrl?: string;

  constructor(config: SLOPAgentConfig) {
    super(config, GUARDIAN_TOOLS);
    this.githubToken = process.env.GITHUB_TOKEN;
    this.scannerUrl = process.env.SCANNER_URL || 'http://localhost:4001';
    this.graderUrl = process.env.GRADER_URL || 'http://localhost:4002';
  }

  async handleToolCall(call: SLOPToolCall): Promise<SLOPToolResult> {
    const { tool, arguments: args } = call;

    try {
      switch (tool) {
        case 'check-pr':
          return { result: await this.checkPR(
            args.repo as string,
            args.prNumber as number,
            args.policy as Partial<PRPolicy> | undefined
          )};

        case 'block-pr':
          return { result: await this.blockPR(
            args.repo as string,
            args.prNumber as number,
            args.reason as string
          )};

        case 'approve-pr':
          return { result: await this.approvePR(
            args.repo as string,
            args.prNumber as number,
            args.comment as string | undefined
          )};

        case 'add-comment':
          return { result: await this.addComment(
            args.repo as string,
            args.prNumber as number,
            args.findings as Finding[]
          )};

        case 'create-check':
          return { result: await this.createCheck(
            args.repo as string,
            args.sha as string,
            args.findings as Finding[]
          )};

        case 'get-pr-status':
          return { result: await this.getPRStatus(
            args.repo as string,
            args.prNumber as number
          )};

        case 'set-policy':
          return { result: await this.setPolicy(
            args.repo as string,
            args.policy as Partial<PRPolicy>
          )};

        case 'watch-prs':
          return { result: await this.watchPRs(
            args.repo as string,
            args.webhookUrl as string | undefined
          )};

        default:
          return { error: `Unknown tool: ${tool}` };
      }
    } catch (error) {
      return { error: String(error) };
    }
  }

  /**
   * Check a PR for security issues
   */
  private async checkPR(
    repo: string,
    prNumber: number,
    policyOverrides?: Partial<PRPolicy>
  ): Promise<PRCheckResult> {
    const prId = `${repo}#${prNumber}`;
    const policy = { ...DEFAULT_POLICY, ...this.policies.get(repo), ...policyOverrides };

    console.log(`[Guardian] Checking PR ${prId}...`);

    // Fetch PR details
    const prDetails = await this.fetchPRDetails(repo, prNumber);
    if (!prDetails) {
      throw new Error(`Could not fetch PR ${prId}`);
    }

    // Check if author is exempt
    if (policy.exemptAuthors.includes(prDetails.author)) {
      return this.createPassedResult(prId, repo, 'Author is exempt from security checks');
    }

    // Check if all files are in exempt paths
    const nonExemptFiles = prDetails.files.filter(f =>
      !policy.exemptPaths.some(p => f.startsWith(p))
    );

    if (nonExemptFiles.length === 0) {
      return this.createPassedResult(prId, repo, 'All changed files are in exempt paths');
    }

    // Scan the PR diff for security issues
    let findings: Finding[] = [];
    try {
      // Call scanner agent
      const scanResult = await this.callAgent(this.scannerUrl!, 'scan-diff', {
        repo,
        prNumber,
        diff: prDetails.diff,
        files: nonExemptFiles,
      }) as { findings?: Finding[] };

      findings = scanResult?.findings || [];
    } catch (error) {
      console.log(`[Guardian] Scanner not available, using basic analysis`);
      findings = this.basicDiffAnalysis(prDetails.diff);
    }

    // Grade findings if we have them
    if (findings.length > 0) {
      try {
        const gradeResult = await this.callAgent(this.graderUrl!, 'grade-batch', {
          findings,
        }) as { graded?: Array<{ finding: Finding; priority: number }> };

        if (gradeResult?.graded) {
          // Sort by priority
          findings = gradeResult.graded
            .sort((a, b) => b.priority - a.priority)
            .map(g => g.finding);
        }
      } catch {
        // Continue without grading
      }
    }

    // Calculate summary
    const summary = {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
      secretsFound: findings.filter(f => f.type === 'secret').length,
      newVulnerabilities: findings.filter(f => f.type === 'vulnerability').length,
    };

    // Determine if we should block
    let blocked = false;
    let blockReason: string | undefined;

    if (policy.blockOnCritical && summary.critical > 0) {
      blocked = true;
      blockReason = `${summary.critical} critical security issue(s) found`;
    } else if (policy.blockOnHigh && summary.high > 0) {
      blocked = true;
      blockReason = `${summary.high} high severity issue(s) found`;
    } else if (policy.blockOnSecrets && summary.secretsFound > 0) {
      blocked = true;
      blockReason = `${summary.secretsFound} secret(s) detected in code`;
    }

    // Determine status and recommendation
    let status: PRCheckResult['status'];
    let recommendation: PRCheckResult['recommendation'];

    if (blocked) {
      status = 'failed';
      recommendation = 'block';
    } else if (summary.critical > 0 || summary.high > 0) {
      status = 'warning';
      recommendation = 'request-changes';
    } else if (findings.length > 0) {
      status = 'warning';
      recommendation = policy.requireApproval ? 'request-changes' : 'approve';
    } else {
      status = 'passed';
      recommendation = 'approve';
    }

    // Generate comment
    const comment = this.generateComment(findings, summary, status, blocked, blockReason);

    // Create check run if configured
    const checksCreated: string[] = [];
    if (policy.autoCreateChecks && prDetails.sha) {
      try {
        const check = await this.createCheck(repo, prDetails.sha, findings);
        if (check.id) checksCreated.push(check.id);
      } catch {
        // Check creation failed, continue
      }
    }

    // Add comment if configured
    if (policy.autoComment && findings.length > 0) {
      try {
        await this.addComment(repo, prNumber, findings);
      } catch {
        // Comment failed, continue
      }
    }

    const result: PRCheckResult = {
      prId,
      repo,
      status,
      blocked,
      blockReason,
      findings,
      summary,
      recommendation,
      comment,
      checksCreated,
      reviewedAt: new Date().toISOString(),
    };

    // Cache result
    this.prResults.set(prId, result);

    // Write to memory
    await this.writeMemory(`guardian:pr:${prId}`, {
      status,
      blocked,
      findingsCount: findings.length,
      reviewedAt: result.reviewedAt,
    });

    return result;
  }

  /**
   * Block a PR from merging
   */
  private async blockPR(repo: string, prNumber: number, reason: string): Promise<{
    success: boolean;
    prId: string;
    message: string;
  }> {
    const prId = `${repo}#${prNumber}`;

    if (!this.githubToken) {
      return {
        success: false,
        prId,
        message: 'GitHub token not configured - cannot block PR',
      };
    }

    try {
      // Create a review requesting changes
      const response = await fetch(
        `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews`,
        {
          method: 'POST',
          headers: {
            'Authorization': `token ${this.githubToken}`,
            'Accept': 'application/vnd.github.v3+json',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            body: `## Security Review: BLOCKED\n\n${reason}\n\n_This PR has been blocked by Aura Security Guardian._`,
            event: 'REQUEST_CHANGES',
          }),
        }
      );

      if (response.ok) {
        await this.writeMemory(`guardian:blocked:${prId}`, {
          reason,
          blockedAt: Date.now(),
        });

        return {
          success: true,
          prId,
          message: `PR ${prId} blocked: ${reason}`,
        };
      } else {
        const error = await response.text();
        return {
          success: false,
          prId,
          message: `Failed to block PR: ${error}`,
        };
      }
    } catch (error) {
      return {
        success: false,
        prId,
        message: `Error blocking PR: ${error}`,
      };
    }
  }

  /**
   * Approve a PR after security review
   */
  private async approvePR(repo: string, prNumber: number, comment?: string): Promise<{
    success: boolean;
    prId: string;
    message: string;
  }> {
    const prId = `${repo}#${prNumber}`;

    if (!this.githubToken) {
      return {
        success: false,
        prId,
        message: 'GitHub token not configured',
      };
    }

    try {
      const response = await fetch(
        `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews`,
        {
          method: 'POST',
          headers: {
            'Authorization': `token ${this.githubToken}`,
            'Accept': 'application/vnd.github.v3+json',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            body: comment || '## Security Review: APPROVED\n\n_This PR has passed Aura Security Guardian checks._',
            event: 'APPROVE',
          }),
        }
      );

      if (response.ok) {
        return {
          success: true,
          prId,
          message: `PR ${prId} approved`,
        };
      } else {
        return {
          success: false,
          prId,
          message: `Failed to approve PR`,
        };
      }
    } catch (error) {
      return {
        success: false,
        prId,
        message: `Error approving PR: ${error}`,
      };
    }
  }

  /**
   * Add security findings as PR comment
   */
  private async addComment(repo: string, prNumber: number, findings: Finding[]): Promise<{
    success: boolean;
    commentUrl?: string;
  }> {
    if (!this.githubToken) {
      return { success: false };
    }

    const summary = {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
    };

    const comment = this.generateComment(findings, { ...summary, secretsFound: 0, newVulnerabilities: 0 }, 'warning', false);

    try {
      const response = await fetch(
        `https://api.github.com/repos/${repo}/issues/${prNumber}/comments`,
        {
          method: 'POST',
          headers: {
            'Authorization': `token ${this.githubToken}`,
            'Accept': 'application/vnd.github.v3+json',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ body: comment }),
        }
      );

      if (response.ok) {
        const data = await response.json() as { html_url: string };
        return { success: true, commentUrl: data.html_url };
      }
    } catch {
      // Comment failed
    }

    return { success: false };
  }

  /**
   * Create a GitHub check run
   */
  private async createCheck(repo: string, sha: string, findings: Finding[]): Promise<CheckRun> {
    const annotations: CheckAnnotation[] = findings
      .filter(f => f.file && f.line)
      .slice(0, 50) // GitHub limits to 50 annotations
      .map(f => ({
        path: f.file!,
        start_line: f.line!,
        end_line: f.line!,
        annotation_level: f.severity === 'critical' || f.severity === 'high' ? 'failure' : 'warning',
        message: f.description,
        title: f.title,
      }));

    const hasCritical = findings.some(f => f.severity === 'critical');
    const hasHigh = findings.some(f => f.severity === 'high');

    const checkRun: CheckRun = {
      id: `check-${Date.now()}`,
      name: 'Aura Security Guardian',
      status: 'completed',
      conclusion: hasCritical ? 'failure' : hasHigh ? 'action_required' : findings.length > 0 ? 'neutral' : 'success',
      output: {
        title: hasCritical ? 'Critical Security Issues Found' : hasHigh ? 'Security Review Required' : 'Security Check Passed',
        summary: `Found ${findings.length} security issue(s)`,
        annotations,
      },
    };

    if (this.githubToken) {
      try {
        const response = await fetch(
          `https://api.github.com/repos/${repo}/check-runs`,
          {
            method: 'POST',
            headers: {
              'Authorization': `token ${this.githubToken}`,
              'Accept': 'application/vnd.github.v3+json',
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              name: checkRun.name,
              head_sha: sha,
              status: checkRun.status,
              conclusion: checkRun.conclusion,
              output: checkRun.output,
            }),
          }
        );

        if (response.ok) {
          const data = await response.json() as { id: number; html_url: string };
          checkRun.id = String(data.id);
          checkRun.url = data.html_url;
        }
      } catch {
        // Check creation failed
      }
    }

    return checkRun;
  }

  /**
   * Get PR security status
   */
  private async getPRStatus(repo: string, prNumber: number): Promise<PRCheckResult | null> {
    const prId = `${repo}#${prNumber}`;
    return this.prResults.get(prId) || null;
  }

  /**
   * Set security policy for a repo
   */
  private async setPolicy(repo: string, policy: Partial<PRPolicy>): Promise<{
    success: boolean;
    policy: PRPolicy;
  }> {
    const currentPolicy = this.policies.get(repo) || DEFAULT_POLICY;
    const newPolicy = { ...currentPolicy, ...policy };
    this.policies.set(repo, newPolicy);

    await this.writeMemory(`guardian:policy:${repo}`, newPolicy);

    return { success: true, policy: newPolicy };
  }

  /**
   * Start watching PRs for a repo
   */
  private async watchPRs(repo: string, webhookUrl?: string): Promise<{
    success: boolean;
    repo: string;
    message: string;
  }> {
    this.watchedRepos.add(repo);

    await this.writeMemory(`guardian:watching:${repo}`, {
      since: Date.now(),
      webhookUrl,
    });

    return {
      success: true,
      repo,
      message: `Now watching PRs for ${repo}`,
    };
  }

  // ===== Helper Methods =====

  private async fetchPRDetails(repo: string, prNumber: number): Promise<{
    sha: string;
    author: string;
    files: string[];
    diff: string;
  } | null> {
    const headers: Record<string, string> = {
      'Accept': 'application/vnd.github.v3+json',
      'User-Agent': 'Aura-Guardian',
    };

    if (this.githubToken) {
      headers['Authorization'] = `token ${this.githubToken}`;
    }

    try {
      // Get PR details
      const prResponse = await fetch(
        `https://api.github.com/repos/${repo}/pulls/${prNumber}`,
        { headers }
      );

      if (!prResponse.ok) return null;

      const prData = await prResponse.json() as {
        head: { sha: string };
        user: { login: string };
      };

      // Get changed files
      const filesResponse = await fetch(
        `https://api.github.com/repos/${repo}/pulls/${prNumber}/files`,
        { headers }
      );

      const filesData = await filesResponse.json() as Array<{
        filename: string;
        patch?: string;
      }>;

      const files = filesData.map(f => f.filename);
      const diff = filesData.map(f => f.patch || '').join('\n');

      return {
        sha: prData.head.sha,
        author: prData.user.login,
        files,
        diff,
      };
    } catch {
      return null;
    }
  }

  private basicDiffAnalysis(diff: string): Finding[] {
    const findings: Finding[] = [];

    // Check for secrets
    const secretPatterns = [
      { pattern: /AKIA[0-9A-Z]{16}/, name: 'AWS Access Key' },
      { pattern: /ghp_[A-Za-z0-9_]{36}/, name: 'GitHub Token' },
      { pattern: /sk_live_[A-Za-z0-9]{24}/, name: 'Stripe Secret Key' },
      { pattern: /-----BEGIN.*PRIVATE KEY-----/, name: 'Private Key' },
      { pattern: /password\s*[:=]\s*['"][^'"]+['"]/, name: 'Hardcoded Password' },
    ];

    for (const { pattern, name } of secretPatterns) {
      if (pattern.test(diff)) {
        findings.push({
          id: `secret-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
          type: 'secret',
          severity: 'critical',
          title: `${name} Detected`,
          description: `Found ${name.toLowerCase()} in the diff`,
        });
      }
    }

    // Check for dangerous patterns
    if (/eval\s*\(/.test(diff)) {
      findings.push({
        id: `code-${Date.now()}`,
        type: 'code-issue',
        severity: 'high',
        title: 'Dangerous eval() Usage',
        description: 'eval() can execute arbitrary code and should be avoided',
      });
    }

    return findings;
  }

  private createPassedResult(prId: string, repo: string, reason: string): PRCheckResult {
    return {
      prId,
      repo,
      status: 'passed',
      blocked: false,
      findings: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0, secretsFound: 0, newVulnerabilities: 0 },
      recommendation: 'approve',
      comment: `## Security Review: PASSED\n\n${reason}`,
      checksCreated: [],
      reviewedAt: new Date().toISOString(),
    };
  }

  private generateComment(
    findings: Finding[],
    summary: PRCheckResult['summary'],
    status: PRCheckResult['status'],
    blocked: boolean,
    blockReason?: string
  ): string {
    const statusEmoji = status === 'passed' ? '✅' : status === 'failed' ? '❌' : '⚠️';
    const statusText = status === 'passed' ? 'PASSED' : status === 'failed' ? 'FAILED' : 'WARNING';

    let comment = `## ${statusEmoji} Security Review: ${statusText}\n\n`;

    if (blocked) {
      comment += `> **BLOCKED**: ${blockReason}\n\n`;
    }

    comment += `| Severity | Count |\n|----------|-------|\n`;
    comment += `| Critical | ${summary.critical} |\n`;
    comment += `| High | ${summary.high} |\n`;
    comment += `| Medium | ${summary.medium} |\n`;
    comment += `| Low | ${summary.low} |\n\n`;

    if (findings.length > 0) {
      comment += `### Findings\n\n`;
      for (const finding of findings.slice(0, 10)) {
        const icon = finding.severity === 'critical' ? '🔴' : finding.severity === 'high' ? '🟠' : '🟡';
        comment += `${icon} **${finding.title}**`;
        if (finding.file) comment += ` (${finding.file}${finding.line ? `:${finding.line}` : ''})`;
        comment += `\n`;
      }
      if (findings.length > 10) {
        comment += `\n_...and ${findings.length - 10} more findings_\n`;
      }
    }

    comment += `\n---\n_Powered by [Aura Security Guardian](https://aurasecurity.io)_`;

    return comment;
  }
}

// Export factory function
export function createGuardianAgent(port = 4007, coordinatorUrl?: string): GuardianAgent {
  return new GuardianAgent({
    id: 'guardian',
    name: 'PR Guardian Agent',
    port,
    description: 'Real-time PR protection - blocks dangerous code before merge',
    coordinatorUrl,
  });
}
