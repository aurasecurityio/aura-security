/**
 * Aura Protocol - Base Agent
 *
 * Abstract base class for all agents.
 */

import { execSync, spawn } from 'child_process';
import {
  Agent,
  AgentConfig,
  AgentCapabilities,
  AgentStatus,
  AgentResult,
} from './types.js';
import { ZoneContext, ZoneFinding } from '../zones/types.js';

export abstract class BaseAgent implements Agent {
  protected status: AgentStatus = 'idle';

  constructor(
    public readonly config: AgentConfig,
    public readonly capabilities: AgentCapabilities
  ) {}

  /**
   * Check if external tool is installed
   */
  protected async checkToolAvailable(toolName: string): Promise<boolean> {
    try {
      execSync(`which ${toolName}`, { stdio: 'ignore' });
      return true;
    } catch {
      // Try Windows-style check
      try {
        execSync(`where ${toolName}`, { stdio: 'ignore' });
        return true;
      } catch {
        return false;
      }
    }
  }

  /**
   * Execute a command and return output
   */
  protected async executeCommand(
    command: string,
    args: string[],
    options: { cwd?: string; timeout?: number } = {}
  ): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    return new Promise((resolve) => {
      const proc = spawn(command, args, {
        cwd: options.cwd,
        shell: true,
        timeout: options.timeout || 300000, // 5 minute default
      });

      let stdout = '';
      let stderr = '';

      proc.stdout?.on('data', (data) => {
        stdout += data.toString();
      });

      proc.stderr?.on('data', (data) => {
        stderr += data.toString();
      });

      proc.on('close', (code) => {
        resolve({
          stdout,
          stderr,
          exitCode: code || 0,
        });
      });

      proc.on('error', (err) => {
        resolve({
          stdout,
          stderr: err.message,
          exitCode: 1,
        });
      });
    });
  }

  /**
   * Check if agent is available
   */
  async isAvailable(): Promise<boolean> {
    if (!this.config.enabled) return false;

    if (this.config.externalTool) {
      return this.checkToolAvailable(this.config.externalTool);
    }

    return true;
  }

  /**
   * Get current status
   */
  getStatus(): AgentStatus {
    return this.status;
  }

  /**
   * Execute the agent
   */
  abstract execute(context: ZoneContext): Promise<AgentResult>;

  /**
   * Helper to create a finding
   */
  protected createFinding(
    agentId: string,
    partial: Omit<ZoneFinding, 'id' | 'agentId' | 'timestamp'>
  ): ZoneFinding {
    return {
      ...partial,
      id: `${agentId}-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
      agentId,
      timestamp: Date.now(),
    };
  }
}
