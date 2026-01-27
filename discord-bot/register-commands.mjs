/**
 * Register Discord Slash Commands
 *
 * Run this once to register commands with Discord:
 *   node register-commands.mjs
 *
 * Requires BOT_TOKEN and APP_ID environment variables
 */

const APP_ID = process.env.APP_ID || '1465522800180858906';
const BOT_TOKEN = process.env.BOT_TOKEN;

if (!BOT_TOKEN) {
  console.error('ERROR: BOT_TOKEN environment variable required');
  console.log('Run: export BOT_TOKEN="your_bot_token"');
  process.exit(1);
}

const commands = [
  {
    name: 'rugcheck',
    description: 'Quick security scan for red flags and common issues',
    options: [
      {
        name: 'repo',
        description: 'GitHub repository URL (e.g., https://github.com/owner/repo)',
        type: 3, // STRING
        required: true
      }
    ]
  },
  {
    name: 'scan',
    description: 'Full security audit - deep analysis of code and dependencies',
    options: [
      {
        name: 'repo',
        description: 'GitHub repository URL (e.g., https://github.com/owner/repo)',
        type: 3,
        required: true
      }
    ]
  },
  {
    name: 'devcheck',
    description: 'Developer trust analysis - check account age and reputation',
    options: [
      {
        name: 'repo',
        description: 'GitHub repository URL (e.g., https://github.com/owner/repo)',
        type: 3,
        required: true
      }
    ]
  },
  {
    name: 'xcheck',
    description: 'Analyze X/Twitter profile for legitimacy and bot followers',
    options: [
      {
        name: 'username',
        description: 'X/Twitter username (e.g., @elonmusk or elonmusk)',
        type: 3,
        required: true
      }
    ]
  },
  {
    name: 'aicheck',
    description: 'Verify if a repo is a real AI project or just hype',
    options: [
      {
        name: 'repo',
        description: 'GitHub repository URL (e.g., https://github.com/owner/repo)',
        type: 3,
        required: true
      }
    ]
  },
  {
    name: 'scamcheck',
    description: 'Detect known scam patterns, rug pull templates, and honeypot code',
    options: [
      {
        name: 'repo',
        description: 'GitHub repository URL (e.g., https://github.com/owner/repo)',
        type: 3,
        required: true
      }
    ]
  },
  {
    name: 'compare',
    description: 'Compare two repos side-by-side - which one to ape?',
    options: [
      {
        name: 'repo1',
        description: 'First GitHub repository URL',
        type: 3,
        required: true
      },
      {
        name: 'repo2',
        description: 'Second GitHub repository URL',
        type: 3,
        required: true
      }
    ]
  },
  {
    name: 'help',
    description: 'Show available commands and how to use them'
  }
];

async function registerCommands() {
  const url = `https://discord.com/api/v10/applications/${APP_ID}/commands`;

  console.log('Registering commands with Discord...');
  console.log(`App ID: ${APP_ID}`);
  console.log(`Commands: ${commands.map(c => c.name).join(', ')}`);

  try {
    const response = await fetch(url, {
      method: 'PUT',
      headers: {
        'Authorization': `Bot ${BOT_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(commands)
    });

    if (!response.ok) {
      const error = await response.text();
      console.error(`Failed to register commands: ${response.status}`);
      console.error(error);
      process.exit(1);
    }

    const data = await response.json();
    console.log('\nCommands registered successfully!');
    console.log(`Registered ${data.length} commands:`);
    data.forEach(cmd => {
      console.log(`  /${cmd.name} - ${cmd.description}`);
    });

  } catch (error) {
    console.error('Error registering commands:', error);
    process.exit(1);
  }
}

registerCommands();
