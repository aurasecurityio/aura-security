/**
 * AI Project Verifier - Detect Real vs Fake AI Projects
 *
 * Checks if a GitHub repo actually has AI/ML code or is just hype.
 * Looks for real libraries, model files, training code, etc.
 */

// Real AI/ML libraries and frameworks
const AI_LIBRARIES = {
  python: [
    'transformers', 'torch', 'pytorch', 'tensorflow', 'keras', 'jax',
    'langchain', 'openai', 'anthropic', 'huggingface', 'diffusers',
    'scikit-learn', 'sklearn', 'pandas', 'numpy', 'scipy',
    'llama-index', 'llamaindex', 'autogen', 'crewai', 'guidance'
  ],
  javascript: [
    'openai', '@anthropic-ai/sdk', 'langchain', '@langchain',
    'transformers.js', '@xenova/transformers', 'tensorflow',
    '@tensorflow/tfjs', 'brain.js', 'ml5', 'onnxruntime'
  ],
  rust: [
    'candle', 'burn', 'tch', 'ort', 'tract', 'linfa'
  ]
};

// Model file extensions
const MODEL_EXTENSIONS = ['.pt', '.pth', '.onnx', '.safetensors', '.bin', '.gguf', '.ggml', '.h5', '.keras', '.pkl'];

// AI-related file patterns
const AI_FILE_PATTERNS = [
  /model/i, /train/i, /inference/i, /predict/i, /embed/i,
  /llm/i, /gpt/i, /bert/i, /transformer/i, /neural/i,
  /agent/i, /chat/i, /completion/i, /prompt/i
];

// Buzzword-only README patterns (hype without substance)
const HYPE_ONLY_PATTERNS = [
  /revolutionary.*ai/i, /next.*gen.*ai/i, /ai.*powered.*future/i,
  /cutting.*edge.*ml/i, /state.*of.*the.*art/i
];

export interface AIVerifyResult {
  url: string;
  repoName: string;
  isRealAI: boolean;
  aiScore: number;  // 0-100
  verdict: 'REAL AI' | 'LIKELY REAL' | 'UNCERTAIN' | 'HYPE ONLY' | 'NOT AI';
  verdictEmoji: string;
  evidence: {
    aiLibraries: string[];
    modelFiles: string[];
    aiCodeFiles: string[];
    trainingScripts: boolean;
    inferenceCode: boolean;
    hasNotebook: boolean;
  };
  redFlags: string[];
  greenFlags: string[];
  summary: string;
  scannedAt: string;
}

/**
 * Parse GitHub URL
 */
function parseGitHubUrl(url: string): { owner: string; repo: string } | null {
  const patterns = [
    /github\.com\/([^\/]+)\/([^\/\?\#]+)/,
    /^([^\/]+)\/([^\/]+)$/
  ];

  for (const pattern of patterns) {
    const match = url.match(pattern);
    if (match) {
      return {
        owner: match[1],
        repo: match[2].replace(/\.git$/, '')
      };
    }
  }
  return null;
}

/**
 * Main AI verification function
 */
export async function performAIVerification(gitUrl: string): Promise<AIVerifyResult> {
  const parsed = parseGitHubUrl(gitUrl);
  if (!parsed) {
    throw new Error('Invalid GitHub URL');
  }

  const { owner, repo } = parsed;

  const headers: Record<string, string> = {
    'User-Agent': 'AuraSecurityBot/1.0',
    'Accept': 'application/vnd.github.v3+json'
  };
  if (process.env.GITHUB_TOKEN) {
    headers['Authorization'] = `token ${process.env.GITHUB_TOKEN}`;
  }

  // Fetch repo info
  const repoRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers });
  if (!repoRes.ok) {
    if (repoRes.status === 404) throw new Error('Repository not found');
    throw new Error(`GitHub API error: ${repoRes.status}`);
  }
  const repoData = await repoRes.json();

  // Fetch file tree
  const treeRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/git/trees/${repoData.default_branch}?recursive=1`, { headers });
  let files: Array<{ path: string; type: string }> = [];
  if (treeRes.ok) {
    const treeData = await treeRes.json();
    files = treeData.tree?.filter((f: { type: string }) => f.type === 'blob') || [];
  }

  // Initialize evidence
  const evidence: AIVerifyResult['evidence'] = {
    aiLibraries: [],
    modelFiles: [],
    aiCodeFiles: [],
    trainingScripts: false,
    inferenceCode: false,
    hasNotebook: false
  };
  const redFlags: string[] = [];
  const greenFlags: string[] = [];
  let aiScore = 0;

  // Check for dependency files
  const depFiles = ['requirements.txt', 'pyproject.toml', 'setup.py', 'package.json', 'Cargo.toml'];
  const foundDepFiles = files.filter(f => depFiles.includes(f.path.split('/').pop() || ''));

  // Scan dependency files for AI libraries
  for (const depFile of foundDepFiles.slice(0, 3)) {
    try {
      const fileRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/contents/${depFile.path}`, { headers });
      if (fileRes.ok) {
        const fileData = await fileRes.json();
        if (fileData.content) {
          const content = Buffer.from(fileData.content, 'base64').toString('utf-8').toLowerCase();

          // Check Python deps
          for (const lib of AI_LIBRARIES.python) {
            if (content.includes(lib.toLowerCase())) {
              if (!evidence.aiLibraries.includes(lib)) {
                evidence.aiLibraries.push(lib);
              }
            }
          }

          // Check JS deps
          for (const lib of AI_LIBRARIES.javascript) {
            if (content.includes(lib.toLowerCase())) {
              if (!evidence.aiLibraries.includes(lib)) {
                evidence.aiLibraries.push(lib);
              }
            }
          }

          // Check Rust deps
          for (const lib of AI_LIBRARIES.rust) {
            if (content.includes(lib.toLowerCase())) {
              if (!evidence.aiLibraries.includes(lib)) {
                evidence.aiLibraries.push(lib);
              }
            }
          }
        }
      }
    } catch {
      // Skip files we can't read
    }
  }

  // Check for model files
  for (const file of files) {
    const ext = '.' + (file.path.split('.').pop() || '').toLowerCase();
    if (MODEL_EXTENSIONS.includes(ext)) {
      evidence.modelFiles.push(file.path);
    }
  }

  // Check for AI-related code files
  const codeFiles = files.filter(f =>
    f.path.endsWith('.py') || f.path.endsWith('.ts') || f.path.endsWith('.js') || f.path.endsWith('.rs')
  );

  for (const file of codeFiles) {
    if (AI_FILE_PATTERNS.some(p => p.test(file.path))) {
      evidence.aiCodeFiles.push(file.path);
    }
    if (/train/i.test(file.path)) {
      evidence.trainingScripts = true;
    }
    if (/infer|predict|generate|complet/i.test(file.path)) {
      evidence.inferenceCode = true;
    }
  }

  // Check for Jupyter notebooks
  evidence.hasNotebook = files.some(f => f.path.endsWith('.ipynb'));

  // Check README for hype vs substance
  const readmeFile = files.find(f => f.path.toLowerCase().includes('readme'));
  let readmeContent = '';
  if (readmeFile) {
    try {
      const readmeRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/contents/${readmeFile.path}`, { headers });
      if (readmeRes.ok) {
        const readmeData = await readmeRes.json();
        if (readmeData.content) {
          readmeContent = Buffer.from(readmeData.content, 'base64').toString('utf-8');
        }
      }
    } catch {
      // Skip
    }
  }

  // Score calculation
  // AI Libraries (high weight)
  if (evidence.aiLibraries.length >= 3) {
    aiScore += 35;
    greenFlags.push(`Uses ${evidence.aiLibraries.length} AI libraries: ${evidence.aiLibraries.slice(0, 3).join(', ')}`);
  } else if (evidence.aiLibraries.length >= 1) {
    aiScore += 20;
    greenFlags.push(`Uses AI library: ${evidence.aiLibraries.join(', ')}`);
  }

  // Model files (strong signal)
  if (evidence.modelFiles.length > 0) {
    aiScore += 25;
    greenFlags.push(`Contains ${evidence.modelFiles.length} model file(s)`);
  }

  // AI code files
  if (evidence.aiCodeFiles.length >= 5) {
    aiScore += 20;
    greenFlags.push(`${evidence.aiCodeFiles.length} AI-related code files`);
  } else if (evidence.aiCodeFiles.length >= 1) {
    aiScore += 10;
    greenFlags.push('Has AI-related code files');
  }

  // Training/inference code
  if (evidence.trainingScripts) {
    aiScore += 10;
    greenFlags.push('Has training scripts');
  }
  if (evidence.inferenceCode) {
    aiScore += 10;
    greenFlags.push('Has inference/prediction code');
  }

  // Notebooks (common in ML projects)
  if (evidence.hasNotebook) {
    aiScore += 5;
    greenFlags.push('Contains Jupyter notebooks');
  }

  // Red flags
  const hasAIInName = /\bai\b|artificial.*intelligence|machine.*learning|ml\b|llm\b|gpt/i.test(repoData.name + ' ' + (repoData.description || ''));
  const hasHypeOnly = HYPE_ONLY_PATTERNS.some(p => p.test(readmeContent));

  if (hasAIInName && evidence.aiLibraries.length === 0 && evidence.aiCodeFiles.length === 0) {
    aiScore -= 20;
    redFlags.push('AI in name but no AI libraries or code found');
  }

  if (hasHypeOnly && evidence.aiLibraries.length === 0) {
    aiScore -= 15;
    redFlags.push('Hype language in README but no real AI code');
  }

  if (files.length < 5) {
    aiScore -= 10;
    redFlags.push('Very few files - might be placeholder');
  }

  // No code at all
  if (codeFiles.length === 0) {
    aiScore -= 30;
    redFlags.push('No code files found');
  }

  // Clamp score
  aiScore = Math.max(0, Math.min(100, aiScore));

  // Determine verdict
  let verdict: AIVerifyResult['verdict'];
  let verdictEmoji: string;
  let isRealAI = false;

  if (aiScore >= 70) {
    verdict = 'REAL AI';
    verdictEmoji = '🤖';
    isRealAI = true;
  } else if (aiScore >= 50) {
    verdict = 'LIKELY REAL';
    verdictEmoji = '🟢';
    isRealAI = true;
  } else if (aiScore >= 30) {
    verdict = 'UNCERTAIN';
    verdictEmoji = '🟡';
  } else if (aiScore >= 10) {
    verdict = 'HYPE ONLY';
    verdictEmoji = '🟠';
  } else {
    verdict = 'NOT AI';
    verdictEmoji = '🔴';
  }

  // Generate summary
  let summary = '';
  if (verdict === 'REAL AI') {
    summary = `Verified AI project using ${evidence.aiLibraries.slice(0, 2).join(', ') || 'ML tools'}. `;
    if (evidence.modelFiles.length > 0) summary += 'Contains trained models. ';
    if (evidence.trainingScripts) summary += 'Has training code. ';
  } else if (verdict === 'LIKELY REAL') {
    summary = 'Shows signs of real AI/ML work. ';
    if (evidence.aiLibraries.length > 0) summary += `Uses ${evidence.aiLibraries[0]}. `;
  } else if (verdict === 'UNCERTAIN') {
    summary = 'Limited AI evidence found. Could be early stage or wrapper project. ';
  } else if (verdict === 'HYPE ONLY') {
    summary = 'Claims to be AI but lacks actual AI libraries or code. ';
    if (redFlags.length > 0) summary += redFlags[0] + '. ';
  } else {
    summary = 'No AI/ML components detected in this repository. ';
  }

  return {
    url: gitUrl,
    repoName: repo,
    isRealAI,
    aiScore,
    verdict,
    verdictEmoji,
    evidence,
    redFlags,
    greenFlags,
    summary,
    scannedAt: new Date().toISOString()
  };
}
