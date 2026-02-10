/**
 * Config Loader - Loads private detection data from config files
 *
 * Config files are stored in the config/ directory and are NOT committed
 * to the repository. They contain proprietary detection signatures,
 * scoring weights, and thresholds that are only available on the server.
 *
 * If config files are missing, minimal defaults are used.
 */

import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Config directory: AURA_CONFIG_DIR env var, or <project-root>/config/
const CONFIG_DIR = process.env.AURA_CONFIG_DIR || join(__dirname, '..', '..', 'config');

const configCache = new Map<string, unknown>();

/**
 * Load a JSON config file. Returns fallback if file not found.
 */
export function loadConfig<T>(filename: string, fallback: T): T {
  if (configCache.has(filename)) {
    return configCache.get(filename) as T;
  }

  const filePath = join(CONFIG_DIR, filename);
  if (!existsSync(filePath)) {
    console.warn(`[CONFIG] ${filename} not found at ${filePath}, using built-in defaults`);
    configCache.set(filename, fallback);
    return fallback;
  }

  try {
    const content = readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(content) as T;
    configCache.set(filename, parsed);
    console.log(`[CONFIG] Loaded ${filename}`);
    return parsed;
  } catch (err) {
    console.error(`[CONFIG] Failed to parse ${filename}:`, err);
    configCache.set(filename, fallback);
    return fallback;
  }
}

/**
 * Convert a [source, flags] tuple from config to a RegExp
 */
export function toRegExp(pattern: [string, string?]): RegExp {
  return new RegExp(pattern[0], pattern[1] || '');
}

/**
 * Clear config cache (for hot reload or testing)
 */
export function clearConfigCache(): void {
  configCache.clear();
}
