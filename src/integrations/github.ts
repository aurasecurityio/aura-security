// GitHub Integration - Fetch PR details, diffs, and create check runs
// Requires: GITHUB_TOKEN environment variable

import type { AuditorInput, AuditorOutput } from '../types/events.js';

export interface GitHubConfig {
  token: string;
  apiUrl?: string;  // For GitHub Enterprise
}

export interface PullRequest {
  number: number;
  title: string;
  body: string;
  head: { sha: string; ref: string };
  base: { ref: string };
  user: { login: string };
  changed_files: number;
  additions: number;
  deletions: number;
}

export interface ChangedFile {
  filename: string;
  status: string;
  additions: number;
  deletions: number;
  patch?: string;
}

export class GitHubIntegration {
  private token: string;
  private apiUrl: string;

  constructor(config: GitHubConfig) {
    this.token = config.token;
    this.apiUrl = config.apiUrl || 'https://api.github.com';
  }

  private async fetch<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const res = await fetch(`${this.apiUrl}${endpoint}`, {
      ...options,
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'Accept': 'application/vnd.github.v3+json',
        'X-GitHub-Api-Version': '2022-11-28',
        ...options.headers
      }
    });

    if (!res.ok) {
      throw new Error(`GitHub API error: ${res.status} ${res.statusText}`);
    }

    return res.json() as Promise<T>;
  }

  // Get pull request details
  async getPullRequest(owner: string, repo: string, prNumber: number): Promise<PullRequest> {
    return this.fetch(`/repos/${owner}/${repo}/pulls/${prNumber}`);
  }

  // Get files changed in PR
  async getPullRequestFiles(owner: string, repo: string, prNumber: number): Promise<ChangedFile[]> {
    return this.fetch(`/repos/${owner}/${repo}/pulls/${prNumber}/files`);
  }

  // Get full diff
  async getPullRequestDiff(owner: string, repo: string, prNumber: number): Promise<string> {
    const res = await fetch(`${this.apiUrl}/repos/${owner}/${repo}/pulls/${prNumber}`, {
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'Accept': 'application/vnd.github.v3.diff'
      }
    });

    if (!res.ok) {
      throw new Error(`GitHub API error: ${res.status}`);
    }

    return res.text();
  }

  // Create audit input from PR
  async createAuditInput(
    owner: string,
    repo: string,
    prNumber: number,
    criticalAssets: string[] = ['auth', 'billing', 'database', 'secrets', 'infra']
  ): Promise<AuditorInput> {
    const [pr, files, diff] = await Promise.all([
      this.getPullRequest(owner, repo, prNumber),
      this.getPullRequestFiles(owner, repo, prNumber),
      this.getPullRequestDiff(owner, repo, prNumber)
    ]);

    const isProd = pr.base.ref === 'main' || pr.base.ref === 'master';

    return {
      change_event: {
        id: `github-${owner}-${repo}-pr-${prNumber}`,
        type: 'pull_request',
        environment: isProd ? 'prod' : 'staging',
        repo: `${owner}/${repo}`,
        commit: pr.head.sha,
        files_changed: files.map(f => f.filename),
        diff: diff
      },
      evidence_bundle: {
        // Can be populated by scanner integrations
      },
      policy_context: {
        critical_assets: criticalAssets,
        risk_tolerance: isProd ? 'low' : 'medium'
      }
    };
  }

  // Create a check run for the PR
  async createCheckRun(
    owner: string,
    repo: string,
    headSha: string,
    output: AuditorOutput
  ): Promise<void> {
    const criticalCount = output.events.filter(e => e.payload.severity === 'critical').length;
    const highCount = output.events.filter(e => e.payload.severity === 'high').length;

    const conclusion = criticalCount > 0 ? 'failure' :
                       highCount > 0 ? 'neutral' : 'success';

    const summary = this.formatCheckSummary(output);
    const annotations = this.formatAnnotations(output);

    await this.fetch(`/repos/${owner}/${repo}/check-runs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'SLOP Security Audit',
        head_sha: headSha,
        status: 'completed',
        conclusion,
        output: {
          title: `Security Audit: ${output.agent_state.toUpperCase()}`,
          summary,
          annotations: annotations.slice(0, 50) // GitHub limit
        }
      })
    });
  }

  // Create a PR comment with audit results
  async createPRComment(
    owner: string,
    repo: string,
    prNumber: number,
    output: AuditorOutput
  ): Promise<void> {
    const body = this.formatCommentBody(output);

    await this.fetch(`/repos/${owner}/${repo}/issues/${prNumber}/comments`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ body })
    });
  }

  private formatCheckSummary(output: AuditorOutput): string {
    const counts = {
      critical: output.events.filter(e => e.payload.severity === 'critical').length,
      high: output.events.filter(e => e.payload.severity === 'high').length,
      medium: output.events.filter(e => e.payload.severity === 'medium').length,
      low: output.events.filter(e => e.payload.severity === 'low').length
    };

    return `## Security Audit Results

**Agent State:** ${output.agent_state.toUpperCase()}

### Findings Summary
| Severity | Count |
|----------|-------|
| Critical | ${counts.critical} |
| High | ${counts.high} |
| Medium | ${counts.medium} |
| Low | ${counts.low} |

### Details
${output.events.filter(e => e.event_type !== 'analysis_started').map(e => `
#### ${e.payload.severity.toUpperCase()}: ${e.payload.claim}
- **Confidence:** ${(e.payload.confidence * 100).toFixed(0)}%
- **Affected:** ${e.payload.affected_assets.join(', ') || 'N/A'}
- **Attack Path:**
${e.payload.attack_path.map(p => `  1. ${p}`).join('\n')}
`).join('\n')}
`;
  }

  private formatAnnotations(output: AuditorOutput): Array<{
    path: string;
    start_line: number;
    end_line: number;
    annotation_level: 'failure' | 'warning' | 'notice';
    message: string;
    title: string;
  }> {
    const annotations: Array<{
      path: string;
      start_line: number;
      end_line: number;
      annotation_level: 'failure' | 'warning' | 'notice';
      message: string;
      title: string;
    }> = [];

    for (const event of output.events) {
      if (event.event_type === 'analysis_started') continue;

      for (const ref of event.payload.evidence_refs) {
        if (ref.type === 'diff') {
          const level = event.payload.severity === 'critical' ? 'failure' :
                        event.payload.severity === 'high' ? 'warning' : 'notice';

          annotations.push({
            path: ref.pointer.includes('/') ? ref.pointer : 'unknown',
            start_line: 1,
            end_line: 1,
            annotation_level: level,
            message: event.payload.claim,
            title: `${event.payload.severity.toUpperCase()}: Security Finding`
          });
        }
      }
    }

    return annotations;
  }

  private formatCommentBody(output: AuditorOutput): string {
    const emoji = output.agent_state === 'blocked' ? '🚨' :
                  output.agent_state === 'escalated' ? '⚠️' :
                  output.agent_state === 'conflict' ? '⚡' : '✅';

    const counts = {
      critical: output.events.filter(e => e.payload.severity === 'critical').length,
      high: output.events.filter(e => e.payload.severity === 'high').length,
      medium: output.events.filter(e => e.payload.severity === 'medium').length,
      low: output.events.filter(e => e.payload.severity === 'low').length
    };

    let body = `## ${emoji} SLOP Security Audit

**Status:** ${output.agent_state.toUpperCase()}

| Critical | High | Medium | Low |
|:--------:|:----:|:------:|:---:|
| ${counts.critical} | ${counts.high} | ${counts.medium} | ${counts.low} |

`;

    if (output.events.length > 1) {
      body += `### Findings\n\n`;

      for (const event of output.events) {
        if (event.event_type === 'analysis_started') continue;

        const sevEmoji = event.payload.severity === 'critical' ? '🔴' :
                         event.payload.severity === 'high' ? '🟠' :
                         event.payload.severity === 'medium' ? '🟡' : '🟢';

        body += `<details>
<summary>${sevEmoji} <strong>${event.payload.severity.toUpperCase()}</strong>: ${event.payload.claim}</summary>

**Confidence:** ${(event.payload.confidence * 100).toFixed(0)}%
**Affected:** ${event.payload.affected_assets.join(', ') || 'N/A'}

**Attack Path:**
${event.payload.attack_path.map((p, i) => `${i + 1}. ${p}`).join('\n')}

</details>

`;
      }
    }

    body += `\n---\n*Powered by SLOP Auditor*`;

    return body;
  }
}
