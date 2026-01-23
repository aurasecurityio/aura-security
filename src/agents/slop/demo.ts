#!/usr/bin/env npx tsx
/**
 * SLOP Multi-Agent Demo
 *
 * Demonstrates SLOP-native agent-to-agent communication:
 * 1. Starts Coordinator, Scanner, and Analyst agents
 * 2. Registers agents with coordinator
 * 3. Runs a full security pipeline with inter-agent communication
 *
 * Usage:
 *   npx tsx src/agents/slop/demo.ts [target-path]
 *
 * Example:
 *   npx tsx src/agents/slop/demo.ts ./
 *   npx tsx src/agents/slop/demo.ts /path/to/project
 */

import { CoordinatorAgent } from './coordinator-agent.js';
import { ScannerAgent } from './scanner-agent.js';
import { AnalystAgent } from './analyst-agent.js';
import { FixerAgent } from './fixer-agent.js';

const COORDINATOR_PORT = 3009;
const SCANNER_PORT = 3010;
const ANALYST_PORT = 3011;
const FIXER_PORT = 3012;

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
  const target = process.argv[2] || './';

  console.log(`
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║     █████╗ ██╗   ██╗██████╗  █████╗     ███████╗██╗      ██████╗ ██████╗     ║
║    ██╔══██╗██║   ██║██╔══██╗██╔══██╗    ██╔════╝██║     ██╔═══██╗██╔══██╗    ║
║    ███████║██║   ██║██████╔╝███████║    ███████╗██║     ██║   ██║██████╔╝    ║
║    ██╔══██║██║   ██║██╔══██╗██╔══██║    ╚════██║██║     ██║   ██║██╔═══╝     ║
║    ██║  ██║╚██████╔╝██║  ██║██║  ██║    ███████║███████╗╚██████╔╝██║         ║
║    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝    ╚══════╝╚══════╝ ╚═════╝ ╚═╝         ║
║                                                                               ║
║                    Multi-Agent Security Pipeline Demo                         ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
`);

  console.log(`Target: ${target}\n`);

  // Create agents
  const coordinator = new CoordinatorAgent({ port: COORDINATOR_PORT });
  const scanner = new ScannerAgent({
    port: SCANNER_PORT,
    coordinatorUrl: `http://localhost:${COORDINATOR_PORT}`,
  });
  const analyst = new AnalystAgent({
    port: ANALYST_PORT,
    coordinatorUrl: `http://localhost:${COORDINATOR_PORT}`,
  });
  const fixer = new FixerAgent({
    port: FIXER_PORT,
    coordinatorUrl: `http://localhost:${COORDINATOR_PORT}`,
  });

  try {
    // Start all agents
    console.log('Starting SLOP agents...\n');

    await Promise.all([coordinator.start(), scanner.start(), analyst.start(), fixer.start()]);

    await sleep(500); // Let agents fully initialize

    // Register agents with coordinator
    console.log('\nRegistering agents with coordinator...\n');

    await fetch(`http://localhost:${COORDINATOR_PORT}/tools`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool: 'register-agent',
        arguments: {
          id: 'scanner-agent',
          name: 'Scanner Agent',
          url: `http://localhost:${SCANNER_PORT}`,
        },
      }),
    });

    await fetch(`http://localhost:${COORDINATOR_PORT}/tools`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool: 'register-agent',
        arguments: {
          id: 'analyst-agent',
          name: 'Analyst Agent',
          url: `http://localhost:${ANALYST_PORT}`,
        },
      }),
    });

    await fetch(`http://localhost:${COORDINATOR_PORT}/tools`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool: 'register-agent',
        arguments: {
          id: 'fixer-agent',
          name: 'Fixer Agent',
          url: `http://localhost:${FIXER_PORT}`,
        },
      }),
    });

    // List agents
    const listResponse = await fetch(`http://localhost:${COORDINATOR_PORT}/tools`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tool: 'list-agents', arguments: {} }),
    });
    const listResult = await listResponse.json();
    console.log(`Registered agents: ${listResult.result.online} online\n`);

    for (const agent of listResult.result.agents) {
      console.log(`  ✓ ${agent.name} (${agent.url}) - ${agent.tools.length} tools`);
    }

    // Run the pipeline
    console.log('\n');
    console.log('Starting security pipeline...\n');

    const pipelineResponse = await fetch(`http://localhost:${COORDINATOR_PORT}/tools`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool: 'run-pipeline',
        arguments: { target },
      }),
    });

    const pipelineResult = await pipelineResponse.json();

    if (pipelineResult.result.success) {
      console.log(`\n✓ Pipeline completed successfully in ${pipelineResult.result.totalDuration}ms`);

      // Show final results
      const stages = pipelineResult.result.stages;
      console.log(`\nPipeline stages:`);
      for (const stage of stages) {
        console.log(`  ${stage.agent}/${stage.tool}: ${stage.duration}ms`);
      }

      // Show scan summary if available
      const scanStage = stages.find((s: { tool: string }) => s.tool === 'scan');
      if (scanStage && scanStage.result) {
        console.log(`\nScan summary:`);
        console.log(`  Total findings: ${scanStage.result.summary.total}`);
        console.log(`  Critical: ${scanStage.result.summary.critical}`);
        console.log(`  High: ${scanStage.result.summary.high}`);
        console.log(`  Medium: ${scanStage.result.summary.medium}`);
        console.log(`  Low: ${scanStage.result.summary.low}`);
      }

      // Show triage summary if available
      const triageStage = stages.find((s: { tool: string }) => s.tool === 'triage-batch');
      if (triageStage && triageStage.result) {
        console.log(`\nTriage summary:`);
        console.log(`  Validated: ${triageStage.result.summary.validated}`);
        console.log(`  False positives removed: ${triageStage.result.summary.falsePositives}`);
        console.log(`  Recommended for fix: ${triageStage.result.summary.recommendedForFix}`);
      }

      // Show fix summary if available
      const fixStage = stages.find((s: { tool: string }) => s.tool === 'suggest-fixes-batch');
      if (fixStage && fixStage.result) {
        console.log(`\nFix summary:`);
        console.log(`  Fixable: ${fixStage.result.fixable}`);
        console.log(`  Unfixable: ${fixStage.result.unfixable}`);
        console.log(`  Version bumps: ${fixStage.result.summary.versionBumps}`);
        console.log(`  Code changes: ${fixStage.result.summary.codeChanges}`);
        if (fixStage.result.allCommands && fixStage.result.allCommands.length > 0) {
          console.log(`\nQuick fix command:`);
          console.log(`  ${fixStage.result.allCommands[0]}`);
        }
      }
    } else {
      console.log(`\n✗ Pipeline failed: ${pipelineResult.result.error}`);
    }

    // Show agent communication log
    console.log(`\n\nAgent Communication Log (last 10 messages):`);
    console.log(`─────────────────────────────────────────────`);

    const messagesResponse = await fetch(`http://localhost:${COORDINATOR_PORT}/messages`);
    const messages = await messagesResponse.json();

    for (const msg of messages.messages.slice(-10)) {
      const time = new Date(msg.timestamp).toISOString().split('T')[1].split('.')[0];
      const direction = msg.type === 'request' ? '→' : '←';
      console.log(`  [${time}] ${msg.from} ${direction} ${msg.to}: ${msg.tool || 'response'}`);
    }

    // Show shared memory
    console.log(`\n\nShared Memory (recent entries):`);
    console.log(`─────────────────────────────────────────────`);

    const memoryResponse = await fetch(`http://localhost:${COORDINATOR_PORT}/memory`);
    const memory = await memoryResponse.json();

    for (const entry of memory.entries.slice(-5)) {
      console.log(`  ${entry.key}: ${JSON.stringify(entry.value).substring(0, 80)}...`);
    }

    console.log(`
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   Demo complete! The agents communicated via SLOP protocol:                   ║
║                                                                               ║
║   1. Coordinator registered Scanner, Analyst, and Fixer agents                ║
║   2. Coordinator called Scanner → Scanner ran security tools                  ║
║   3. Coordinator called Analyst → Analyst triaged findings                    ║
║   4. Analyst deduplicated and prioritized findings                            ║
║   5. Coordinator called Fixer → Fixer generated fix suggestions               ║
║   6. All results stored in shared memory                                      ║
║                                                                               ║
║   Each agent runs as a standalone SLOP server that can be:                    ║
║   - Deployed independently                                                    ║
║   - Swapped for different implementations                                     ║
║   - Mixed with agents from other providers                                    ║
║                                                                               ║
║   This is the power of SLOP: universal agent communication.                   ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
`);

    // Cleanup
    console.log('Shutting down agents...');
    await Promise.all([coordinator.stop(), scanner.stop(), analyst.stop(), fixer.stop()]);
    console.log('Done.\n');
  } catch (error) {
    console.error('Demo error:', error);
    // Cleanup on error
    await Promise.all([coordinator.stop(), scanner.stop(), analyst.stop(), fixer.stop()]).catch(() => {});
    process.exit(1);
  }
}

main();
