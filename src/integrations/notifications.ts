/**
 * Notification Integrations for SLOP Auditor
 *
 * Supports:
 * - Slack (webhooks + bot API)
 * - Discord (webhooks)
 * - Email (SMTP)
 * - Custom webhooks
 */

import { getDatabase } from '../database/index.js';

export interface NotificationConfig {
  slack?: {
    webhookUrl?: string;
    botToken?: string;
    channel?: string;
    enabled: boolean;
  };
  discord?: {
    webhookUrl?: string;
    enabled: boolean;
  };
  email?: {
    smtp: {
      host: string;
      port: number;
      secure: boolean;
      user: string;
      pass: string;
    };
    from: string;
    to: string[];
    enabled: boolean;
  };
  webhook?: {
    url: string;
    headers?: Record<string, string>;
    enabled: boolean;
  };
}

export interface NotificationPayload {
  title: string;
  message: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  auditId?: string;
  target?: string;
  findings?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  link?: string;
}

export class NotificationService {
  private config: NotificationConfig;
  private dbPath?: string;

  constructor(config: NotificationConfig = {}, dbPath?: string) {
    this.config = config;
    this.dbPath = dbPath;
  }

  /**
   * Load configuration from database settings
   */
  loadFromDatabase(): void {
    if (!this.dbPath) return;

    const db = getDatabase(this.dbPath);
    const settings = db.getSettings('notifications.');

    // Parse Slack settings
    if (settings['notifications.slack.enabled'] === 'true') {
      this.config.slack = {
        enabled: true,
        webhookUrl: settings['notifications.slack.webhookUrl'],
        botToken: settings['notifications.slack.botToken'],
        channel: settings['notifications.slack.channel']
      };
    }

    // Parse Discord settings
    if (settings['notifications.discord.enabled'] === 'true') {
      this.config.discord = {
        enabled: true,
        webhookUrl: settings['notifications.discord.webhookUrl']
      };
    }

    // Parse webhook settings
    if (settings['notifications.webhook.enabled'] === 'true') {
      this.config.webhook = {
        enabled: true,
        url: settings['notifications.webhook.url'],
        headers: settings['notifications.webhook.headers']
          ? JSON.parse(settings['notifications.webhook.headers'])
          : undefined
      };
    }
  }

  /**
   * Send notification to all configured channels
   */
  async notify(payload: NotificationPayload): Promise<{ sent: string[]; failed: string[] }> {
    const results = { sent: [] as string[], failed: [] as string[] };

    // Try each enabled channel
    const promises: Promise<void>[] = [];

    if (this.config.slack?.enabled && this.config.slack.webhookUrl) {
      promises.push(
        this.sendSlack(payload)
          .then(() => { results.sent.push('slack'); })
          .catch((err) => {
            console.error('[NOTIFY] Slack failed:', err.message);
            results.failed.push('slack');
          })
      );
    }

    if (this.config.discord?.enabled && this.config.discord.webhookUrl) {
      promises.push(
        this.sendDiscord(payload)
          .then(() => { results.sent.push('discord'); })
          .catch((err) => {
            console.error('[NOTIFY] Discord failed:', err.message);
            results.failed.push('discord');
          })
      );
    }

    if (this.config.webhook?.enabled && this.config.webhook.url) {
      promises.push(
        this.sendWebhook(payload)
          .then(() => { results.sent.push('webhook'); })
          .catch((err) => {
            console.error('[NOTIFY] Webhook failed:', err.message);
            results.failed.push('webhook');
          })
      );
    }

    await Promise.all(promises);

    // Record in database
    if (this.dbPath) {
      try {
        const db = getDatabase(this.dbPath);
        db.recordNotification(
          payload.auditId || 'manual',
          results.sent.join(','),
          results.failed.length === 0
        );
      } catch (err) {
        console.error('[NOTIFY] Failed to record notification:', err);
      }
    }

    return results;
  }

  /**
   * Send to Slack webhook
   */
  private async sendSlack(payload: NotificationPayload): Promise<void> {
    const webhookUrl = this.config.slack?.webhookUrl;
    if (!webhookUrl) throw new Error('Slack webhook URL not configured');

    const color = this.getSeverityColor(payload.severity);
    const emoji = this.getSeverityEmoji(payload.severity);

    const slackPayload = {
      attachments: [{
        color,
        blocks: [
          {
            type: 'header',
            text: {
              type: 'plain_text',
              text: `${emoji} ${payload.title}`,
              emoji: true
            }
          },
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: payload.message
            }
          },
          ...(payload.findings ? [{
            type: 'section',
            fields: [
              { type: 'mrkdwn', text: `*Critical:* ${payload.findings.critical}` },
              { type: 'mrkdwn', text: `*High:* ${payload.findings.high}` },
              { type: 'mrkdwn', text: `*Medium:* ${payload.findings.medium}` },
              { type: 'mrkdwn', text: `*Low:* ${payload.findings.low}` }
            ]
          }] : []),
          ...(payload.target ? [{
            type: 'context',
            elements: [{
              type: 'mrkdwn',
              text: `📁 Target: \`${payload.target}\``
            }]
          }] : []),
          ...(payload.link ? [{
            type: 'actions',
            elements: [{
              type: 'button',
              text: { type: 'plain_text', text: 'View Details' },
              url: payload.link,
              action_id: 'view_audit'
            }]
          }] : [])
        ]
      }]
    };

    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(slackPayload)
    });

    if (!response.ok) {
      throw new Error(`Slack returned ${response.status}: ${await response.text()}`);
    }

    console.log('[NOTIFY] Slack notification sent');
  }

  /**
   * Send to Discord webhook
   */
  private async sendDiscord(payload: NotificationPayload): Promise<void> {
    const webhookUrl = this.config.discord?.webhookUrl;
    if (!webhookUrl) throw new Error('Discord webhook URL not configured');

    const color = this.getSeverityColorInt(payload.severity);
    const emoji = this.getSeverityEmoji(payload.severity);

    const discordPayload = {
      embeds: [{
        title: `${emoji} ${payload.title}`,
        description: payload.message,
        color,
        fields: payload.findings ? [
          { name: '🔴 Critical', value: String(payload.findings.critical), inline: true },
          { name: '🟠 High', value: String(payload.findings.high), inline: true },
          { name: '🟡 Medium', value: String(payload.findings.medium), inline: true },
          { name: '🟢 Low', value: String(payload.findings.low), inline: true }
        ] : [],
        footer: payload.target ? { text: `Target: ${payload.target}` } : undefined,
        timestamp: new Date().toISOString()
      }]
    };

    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(discordPayload)
    });

    if (!response.ok) {
      throw new Error(`Discord returned ${response.status}: ${await response.text()}`);
    }

    console.log('[NOTIFY] Discord notification sent');
  }

  /**
   * Send to custom webhook
   */
  private async sendWebhook(payload: NotificationPayload): Promise<void> {
    const webhookConfig = this.config.webhook;
    if (!webhookConfig?.url) throw new Error('Webhook URL not configured');

    const response = await fetch(webhookConfig.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...webhookConfig.headers
      },
      body: JSON.stringify({
        event: 'audit_complete',
        timestamp: new Date().toISOString(),
        ...payload
      })
    });

    if (!response.ok) {
      throw new Error(`Webhook returned ${response.status}: ${await response.text()}`);
    }

    console.log('[NOTIFY] Custom webhook notification sent');
  }

  /**
   * Test a specific notification channel
   */
  async testChannel(channel: 'slack' | 'discord' | 'webhook'): Promise<{ success: boolean; error?: string }> {
    const testPayload: NotificationPayload = {
      title: 'SLOP Auditor Test',
      message: 'This is a test notification from SLOP Auditor.',
      severity: 'low',
      findings: { critical: 0, high: 0, medium: 1, low: 2 },
      target: 'test'
    };

    try {
      switch (channel) {
        case 'slack':
          await this.sendSlack(testPayload);
          break;
        case 'discord':
          await this.sendDiscord(testPayload);
          break;
        case 'webhook':
          await this.sendWebhook(testPayload);
          break;
      }
      return { success: true };
    } catch (err) {
      return { success: false, error: err instanceof Error ? err.message : String(err) };
    }
  }

  private getSeverityColor(severity: string): string {
    switch (severity) {
      case 'critical': return '#ff0000';
      case 'high': return '#ff6600';
      case 'medium': return '#ffcc00';
      case 'low': return '#00cc00';
      default: return '#666666';
    }
  }

  private getSeverityColorInt(severity: string): number {
    switch (severity) {
      case 'critical': return 0xff0000;
      case 'high': return 0xff6600;
      case 'medium': return 0xffcc00;
      case 'low': return 0x00cc00;
      default: return 0x666666;
    }
  }

  private getSeverityEmoji(severity: string): string {
    switch (severity) {
      case 'critical': return '🚨';
      case 'high': return '⚠️';
      case 'medium': return '⚡';
      case 'low': return 'ℹ️';
      default: return '🔍';
    }
  }
}

/**
 * Create notification from scan result
 */
export function createNotificationFromAudit(
  auditId: string,
  type: string,
  target: string,
  summary: { critical: number; high: number; medium: number; low: number },
  baseUrl?: string
): NotificationPayload {
  const total = summary.critical + summary.high + summary.medium + summary.low;

  let severity: 'critical' | 'high' | 'medium' | 'low' = 'low';
  if (summary.critical > 0) severity = 'critical';
  else if (summary.high > 0) severity = 'high';
  else if (summary.medium > 0) severity = 'medium';

  const title = total > 0
    ? `Security Scan Found ${total} Issue${total > 1 ? 's' : ''}`
    : 'Security Scan Complete';

  const message = total > 0
    ? `A ${type} scan of \`${target}\` found security issues that require attention.`
    : `A ${type} scan of \`${target}\` completed with no findings.`;

  return {
    title,
    message,
    severity,
    auditId,
    target,
    findings: summary,
    link: baseUrl ? `${baseUrl}/#audit/${auditId}` : undefined
  };
}
