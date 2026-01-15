// GitLab Integration - Fetch MR details and create pipeline comments
// Requires: GITLAB_TOKEN environment variable

import type { AuditorInput, AuditorOutput } from '../types/events.js';

export interface GitLabConfig {
  token: string;
  apiUrl?: string;  // For self-hosted GitLab
}

export interface MergeRequest {
  iid: number;
  title: string;
  description: string;
  source_branch: string;
  target_branch: string;
  sha: string;
  author: { username: string };
  changes_count: string;
}

export interface MergeRequestChange {
  old_path: string;
  new_path: string;
  diff: string;
}

export class GitLabIntegration {
  private token: string;
  private apiUrl: string;

  constructor(config: GitLabConfig) {
    this.token = config.token;
    this.apiUrl = config.apiUrl || 'https://gitlab.com/api/v4';
  }

  private async fetch<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const res = await fetch(`${this.apiUrl}${endpoint}`, {
      ...options,
      headers: {
        'PRIVATE-TOKEN': this.token,
        'Content-Type': 'application/json',
        ...options.headers
      }
    });

    if (!res.ok) {
      throw new Error(`GitLab API error: ${res.status} ${res.statusText}`);
    }

    return res.json() as Promise<T>;
  }

  // Get merge request details
  async getMergeRequest(projectId: string | number, mrIid: number): Promise<MergeRequest> {
    return this.fetch(`/projects/${encodeURIComponent(projectId)}/merge_requests/${mrIid}`);
  }

  // Get MR changes/diff
  async getMergeRequestChanges(projectId: string | number, mrIid: number): Promise<{ changes: MergeRequestChange[] }> {
    return this.fetch(`/projects/${encodeURIComponent(projectId)}/merge_requests/${mrIid}/changes`);
  }

  // Create audit input from MR
  async createAuditInput(
    projectId: string | number,
    mrIid: number,
    criticalAssets: string[] = ['auth', 'billing', 'database', 'secrets', 'infra']
  ): Promise<AuditorInput> {
    const [mr, changes] = await Promise.all([
      this.getMergeRequest(projectId, mrIid),
      this.getMergeRequestChanges(projectId, mrIid)
    ]);

    const isProd = mr.target_branch === 'main' || mr.target_branch === 'master';
    const diff = changes.changes.map(c => c.diff).join('\n');

    return {
      change_event: {
        id: `gitlab-${projectId}-mr-${mrIid}`,
        type: 'pull_request',
        environment: isProd ? 'prod' : 'staging',
        repo: String(projectId),
        commit: mr.sha,
        files_changed: changes.changes.map(c => c.new_path),
        diff
      },
      evidence_bundle: {},
      policy_context: {
        critical_assets: criticalAssets,
        risk_tolerance: isProd ? 'low' : 'medium'
      }
    };
  }

  // Create MR comment with audit results
  async createMRComment(
    projectId: string | number,
    mrIid: number,
    output: AuditorOutput
  ): Promise<void> {
    const body = this.formatCommentBody(output);

    await this.fetch(`/projects/${encodeURIComponent(projectId)}/merge_requests/${mrIid}/notes`, {
      method: 'POST',
      body: JSON.stringify({ body })
    });
  }

  // Update pipeline status
  async updateCommitStatus(
    projectId: string | number,
    sha: string,
    output: AuditorOutput
  ): Promise<void> {
    const criticalCount = output.events.filter(e => e.payload.severity === 'critical').length;
    const highCount = output.events.filter(e => e.payload.severity === 'high').length;

    const state = criticalCount > 0 ? 'failed' :
                  highCount > 0 ? 'failed' : 'success';

    await this.fetch(`/projects/${encodeURIComponent(projectId)}/statuses/${sha}`, {
      method: 'POST',
      body: JSON.stringify({
        state,
        name: 'SLOP Security Audit',
        description: `${output.agent_state.toUpperCase()} - ${criticalCount} critical, ${highCount} high`,
        context: 'security/slop-audit'
      })
    });
  }

  private formatCommentBody(output: AuditorOutput): string {
    const emoji = output.agent_state === 'blocked' ? '🚨' :
                  output.agent_state === 'escalated' ? '⚠️' : '✅';

    const counts = {
      critical: output.events.filter(e => e.payload.severity === 'critical').length,
      high: output.events.filter(e => e.payload.severity === 'high').length,
      medium: output.events.filter(e => e.payload.severity === 'medium').length,
      low: output.events.filter(e => e.payload.severity === 'low').length
    };

    let body = `## ${emoji} SLOP Security Audit

**Status:** \`${output.agent_state.toUpperCase()}\`

| Critical | High | Medium | Low |
|:--------:|:----:|:------:|:---:|
| ${counts.critical} | ${counts.high} | ${counts.medium} | ${counts.low} |

`;

    for (const event of output.events) {
      if (event.event_type === 'analysis_started') continue;

      body += `### ${event.payload.severity.toUpperCase()}: ${event.payload.claim}
- Confidence: ${(event.payload.confidence * 100).toFixed(0)}%
- Affected: ${event.payload.affected_assets.join(', ') || 'N/A'}

`;
    }

    return body;
  }
}
