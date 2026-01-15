// License Compliance Checker
// Checks dependencies for license compliance with configurable policies

import { spawnSync } from 'child_process';
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';

// ============ License Types ============

export interface LicenseInfo {
  package: string;
  version: string;
  license: string;
  licenseFile?: string;
  repository?: string;
}

export interface LicensePolicy {
  name: string;
  description: string;
  allowed: string[];      // SPDX identifiers that are allowed
  denied: string[];       // SPDX identifiers that are denied
  unknown: 'allow' | 'warn' | 'deny';  // How to handle unknown licenses
}

export interface LicenseViolation {
  package: string;
  version: string;
  license: string;
  violation: string;
  severity: 'high' | 'medium' | 'low';
}

export interface LicenseCheckResult {
  policy: string;
  licenses: LicenseInfo[];
  violations: LicenseViolation[];
  summary: {
    total: number;
    compliant: number;
    violations: number;
    unknown: number;
  };
}

// ============ Built-in Policies ============

export const POLICIES: Record<string, LicensePolicy> = {
  permissive: {
    name: 'Permissive',
    description: 'Only allow permissive open source licenses',
    allowed: [
      'MIT', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0',
      'Unlicense', '0BSD', 'CC0-1.0', 'WTFPL', 'Zlib', 'BlueOak-1.0.0'
    ],
    denied: [
      'GPL-2.0', 'GPL-3.0', 'AGPL-3.0', 'LGPL-2.1', 'LGPL-3.0',
      'GPL-2.0-only', 'GPL-3.0-only', 'AGPL-3.0-only',
      'GPL-2.0-or-later', 'GPL-3.0-or-later', 'AGPL-3.0-or-later'
    ],
    unknown: 'warn'
  },
  strict: {
    name: 'Strict',
    description: 'Strict policy - only well-known permissive licenses',
    allowed: ['MIT', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0'],
    denied: [
      'GPL-2.0', 'GPL-3.0', 'AGPL-3.0', 'LGPL-2.1', 'LGPL-3.0',
      'GPL-2.0-only', 'GPL-3.0-only', 'AGPL-3.0-only',
      'SSPL-1.0', 'BSL-1.1', 'Elastic-2.0'
    ],
    unknown: 'deny'
  },
  copyleft: {
    name: 'Copyleft Allowed',
    description: 'Allow copyleft licenses (for open source projects)',
    allowed: [
      'MIT', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0',
      'GPL-2.0', 'GPL-3.0', 'LGPL-2.1', 'LGPL-3.0', 'MPL-2.0',
      'GPL-2.0-only', 'GPL-3.0-only', 'LGPL-2.1-only', 'LGPL-3.0-only'
    ],
    denied: ['AGPL-3.0', 'AGPL-3.0-only', 'SSPL-1.0'],
    unknown: 'warn'
  }
};

// ============ License Detection ============

function isToolAvailable(tool: string): boolean {
  try {
    const result = spawnSync(tool, ['--version'], { encoding: 'utf-8', timeout: 5000 });
    return result.status === 0;
  } catch {
    return false;
  }
}

// Run license-checker for Node.js projects
function runLicenseChecker(targetPath: string): LicenseInfo[] {
  const licenses: LicenseInfo[] = [];

  if (!existsSync(join(targetPath, 'package.json'))) {
    return licenses;
  }

  // Try license-checker (npm package)
  if (isToolAvailable('npx')) {
    try {
      const result = spawnSync('npx', ['license-checker', '--json', '--production'], {
        cwd: targetPath,
        encoding: 'utf-8',
        timeout: 60000,
        maxBuffer: 10 * 1024 * 1024
      });

      if (result.stdout) {
        try {
          const data = JSON.parse(result.stdout) as Record<string, {
            licenses?: string;
            repository?: string;
            licenseFile?: string;
          }>;

          for (const [pkgKey, info] of Object.entries(data)) {
            const match = pkgKey.match(/^(.+)@([^@]+)$/);
            if (match) {
              licenses.push({
                package: match[1],
                version: match[2],
                license: info.licenses || 'UNKNOWN',
                repository: info.repository,
                licenseFile: info.licenseFile
              });
            }
          }
        } catch {}
      }
    } catch {}
  }

  // Fallback: read from package-lock.json
  if (licenses.length === 0) {
    const lockPath = join(targetPath, 'package-lock.json');
    if (existsSync(lockPath)) {
      try {
        const lock = JSON.parse(readFileSync(lockPath, 'utf-8'));
        const packages = lock.packages || {};

        for (const [path, info] of Object.entries(packages)) {
          if (path === '' || !path.includes('node_modules/')) continue;
          const pkgInfo = info as { version?: string; license?: string };
          const name = path.replace(/^node_modules\//, '').replace(/.*node_modules\//, '');

          if (name && pkgInfo.version) {
            licenses.push({
              package: name,
              version: pkgInfo.version,
              license: pkgInfo.license || 'UNKNOWN'
            });
          }
        }
      } catch {}
    }
  }

  return licenses;
}

// Run pip-licenses for Python projects
function runPipLicenses(targetPath: string): LicenseInfo[] {
  const licenses: LicenseInfo[] = [];

  if (!existsSync(join(targetPath, 'requirements.txt')) &&
      !existsSync(join(targetPath, 'pyproject.toml'))) {
    return licenses;
  }

  if (isToolAvailable('pip-licenses')) {
    try {
      const result = spawnSync('pip-licenses', ['--format=json'], {
        cwd: targetPath,
        encoding: 'utf-8',
        timeout: 60000
      });

      if (result.stdout) {
        try {
          const data = JSON.parse(result.stdout) as Array<{
            Name: string;
            Version: string;
            License: string;
          }>;

          for (const pkg of data) {
            licenses.push({
              package: pkg.Name,
              version: pkg.Version,
              license: pkg.License || 'UNKNOWN'
            });
          }
        } catch {}
      }
    } catch {}
  }

  return licenses;
}

// Normalize license identifier to SPDX format
function normalizeLicense(license: string): string {
  const normalized = license.trim().toUpperCase();

  // Common mappings
  const mappings: Record<string, string> = {
    'MIT LICENSE': 'MIT',
    'APACHE LICENSE 2.0': 'Apache-2.0',
    'APACHE-2.0': 'Apache-2.0',
    'APACHE 2.0': 'Apache-2.0',
    'BSD': 'BSD-3-Clause',
    'BSD LICENSE': 'BSD-3-Clause',
    'BSD-2': 'BSD-2-Clause',
    'BSD-3': 'BSD-3-Clause',
    'ISC LICENSE': 'ISC',
    'GPL': 'GPL-3.0',
    'GPL V2': 'GPL-2.0',
    'GPL V3': 'GPL-3.0',
    'LGPL': 'LGPL-3.0',
    'MPL': 'MPL-2.0',
    'UNLICENSED': 'UNLICENSED',
    'UNKNOWN': 'UNKNOWN',
    '(MIT OR APACHE-2.0)': 'MIT',  // Take first option for OR
    'MIT AND CC-BY-3.0': 'MIT'     // Take first option for AND
  };

  return mappings[normalized] || license;
}

// Check if a license matches the policy
function checkLicense(license: string, policy: LicensePolicy): {
  compliant: boolean;
  reason?: string;
  severity?: 'high' | 'medium' | 'low';
} {
  const normalized = normalizeLicense(license);

  // Check denied list first
  for (const denied of policy.denied) {
    if (normalized.includes(denied.toUpperCase()) || denied.toUpperCase().includes(normalized)) {
      return {
        compliant: false,
        reason: `License "${license}" is explicitly denied`,
        severity: 'high'
      };
    }
  }

  // Check allowed list
  for (const allowed of policy.allowed) {
    if (normalized.includes(allowed.toUpperCase()) || allowed.toUpperCase().includes(normalized)) {
      return { compliant: true };
    }
  }

  // Handle unknown licenses
  if (normalized === 'UNKNOWN' || normalized === 'UNLICENSED') {
    switch (policy.unknown) {
      case 'allow':
        return { compliant: true };
      case 'deny':
        return {
          compliant: false,
          reason: `Unknown license not allowed by policy`,
          severity: 'high'
        };
      case 'warn':
      default:
        return {
          compliant: false,
          reason: `Unknown license requires manual review`,
          severity: 'low'
        };
    }
  }

  // License not in allowed list
  switch (policy.unknown) {
    case 'allow':
      return { compliant: true };
    case 'deny':
      return {
        compliant: false,
        reason: `License "${license}" is not in the allowed list`,
        severity: 'medium'
      };
    case 'warn':
    default:
      return {
        compliant: false,
        reason: `License "${license}" requires review (not in allowed list)`,
        severity: 'low'
      };
  }
}

// ============ Main License Check Function ============

export interface LicenseCheckOptions {
  policy?: string | LicensePolicy;
  allowedLicenses?: string[];
  deniedLicenses?: string[];
}

export function checkLicenses(
  targetPath: string,
  options: LicenseCheckOptions = {}
): LicenseCheckResult {
  // Determine policy
  let policy: LicensePolicy;

  if (typeof options.policy === 'string') {
    policy = POLICIES[options.policy] || POLICIES.permissive;
  } else if (options.policy) {
    policy = options.policy;
  } else {
    policy = { ...POLICIES.permissive };
  }

  // Apply custom allowed/denied overrides
  if (options.allowedLicenses) {
    policy = { ...policy, allowed: [...policy.allowed, ...options.allowedLicenses] };
  }
  if (options.deniedLicenses) {
    policy = { ...policy, denied: [...policy.denied, ...options.deniedLicenses] };
  }

  // Collect licenses from all sources
  const licenses: LicenseInfo[] = [
    ...runLicenseChecker(targetPath),
    ...runPipLicenses(targetPath)
  ];

  // Check each license
  const violations: LicenseViolation[] = [];
  let compliant = 0;
  let unknown = 0;

  for (const info of licenses) {
    const result = checkLicense(info.license, policy);

    if (result.compliant) {
      compliant++;
    } else {
      if (info.license === 'UNKNOWN') {
        unknown++;
      }
      violations.push({
        package: info.package,
        version: info.version,
        license: info.license,
        violation: result.reason || 'License not compliant',
        severity: result.severity || 'medium'
      });
    }
  }

  return {
    policy: policy.name,
    licenses,
    violations,
    summary: {
      total: licenses.length,
      compliant,
      violations: violations.length,
      unknown
    }
  };
}

// Export policy names for CLI
export const POLICY_NAMES = Object.keys(POLICIES);
