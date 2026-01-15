// SBOM (Software Bill of Materials) Generator
// Supports CycloneDX 1.5 and SPDX 2.3 formats

import { spawnSync } from 'child_process';
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import type { LocalScanResult, PackageFinding } from '../integrations/local-scanner.js';

// ============ CycloneDX 1.5 Format ============

export interface CycloneDXComponent {
  type: 'library' | 'application' | 'framework' | 'file' | 'container' | 'operating-system';
  name: string;
  version: string;
  purl?: string;
  licenses?: Array<{
    license: {
      id?: string;
      name?: string;
    };
  }>;
  hashes?: Array<{
    alg: string;
    content: string;
  }>;
}

export interface CycloneDXVulnerability {
  id: string;
  source?: {
    name: string;
    url?: string;
  };
  ratings?: Array<{
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'none' | 'unknown';
    method?: string;
    score?: number;
  }>;
  description?: string;
  recommendation?: string;
  affects?: Array<{
    ref: string;
  }>;
}

export interface CycloneDXDocument {
  bomFormat: 'CycloneDX';
  specVersion: '1.5';
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools?: Array<{
      vendor: string;
      name: string;
      version: string;
    }>;
    component?: CycloneDXComponent;
  };
  components: CycloneDXComponent[];
  vulnerabilities?: CycloneDXVulnerability[];
}

// ============ SPDX 2.3 Format ============

export interface SPDXPackage {
  SPDXID: string;
  name: string;
  versionInfo: string;
  downloadLocation: string;
  filesAnalyzed: boolean;
  licenseConcluded?: string;
  licenseDeclared?: string;
  copyrightText?: string;
  externalRefs?: Array<{
    referenceCategory: string;
    referenceType: string;
    referenceLocator: string;
  }>;
}

export interface SPDXDocument {
  spdxVersion: 'SPDX-2.3';
  dataLicense: 'CC0-1.0';
  SPDXID: 'SPDXRef-DOCUMENT';
  name: string;
  documentNamespace: string;
  creationInfo: {
    created: string;
    creators: string[];
    licenseListVersion?: string;
  };
  packages: SPDXPackage[];
  relationships: Array<{
    spdxElementId: string;
    relationshipType: string;
    relatedSpdxElement: string;
  }>;
}

// ============ SBOM Generator ============

export interface SBOMOptions {
  format: 'cyclonedx' | 'spdx';
  includeVulnerabilities?: boolean;
  includeLicenses?: boolean;
  projectName?: string;
  projectVersion?: string;
}

function isToolAvailable(tool: string): boolean {
  try {
    const result = spawnSync(tool, ['--version'], { encoding: 'utf-8', timeout: 5000 });
    return result.status === 0;
  } catch {
    return false;
  }
}

// Try to use Syft for better SBOM generation
function runSyft(targetPath: string, format: 'cyclonedx-json' | 'spdx-json'): string | null {
  if (!isToolAvailable('syft')) {
    return null;
  }

  try {
    const result = spawnSync('syft', [targetPath, '-o', format], {
      encoding: 'utf-8',
      timeout: 120000,
      maxBuffer: 50 * 1024 * 1024
    });

    if (result.status === 0 && result.stdout) {
      return result.stdout;
    }
  } catch {}

  return null;
}

// Generate package URL (purl)
function generatePurl(name: string, version: string, type: string): string {
  const typeMap: Record<string, string> = {
    npm: 'npm',
    pip: 'pypi',
    go: 'golang',
    cargo: 'cargo',
    gem: 'gem',
    composer: 'composer',
    maven: 'maven'
  };

  const purlType = typeMap[type] || 'generic';
  return `pkg:${purlType}/${encodeURIComponent(name)}@${encodeURIComponent(version)}`;
}

// Read package.json dependencies
function readNpmDependencies(targetPath: string): Array<{ name: string; version: string }> {
  const deps: Array<{ name: string; version: string }> = [];
  const pkgPath = join(targetPath, 'package.json');
  const lockPath = join(targetPath, 'package-lock.json');

  if (existsSync(lockPath)) {
    try {
      const lock = JSON.parse(readFileSync(lockPath, 'utf-8'));
      const packages = lock.packages || {};

      for (const [path, info] of Object.entries(packages)) {
        if (path === '' || !path.includes('node_modules/')) continue;
        const pkgInfo = info as { version?: string };
        const name = path.replace(/^node_modules\//, '').replace(/.*node_modules\//, '');
        if (name && pkgInfo.version) {
          deps.push({ name, version: pkgInfo.version });
        }
      }
    } catch {}
  } else if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };

      for (const [name, version] of Object.entries(allDeps)) {
        deps.push({ name, version: String(version).replace(/^[\^~]/, '') });
      }
    } catch {}
  }

  return deps;
}

// Read Python requirements
function readPythonDependencies(targetPath: string): Array<{ name: string; version: string }> {
  const deps: Array<{ name: string; version: string }> = [];
  const reqPath = join(targetPath, 'requirements.txt');

  if (existsSync(reqPath)) {
    try {
      const content = readFileSync(reqPath, 'utf-8');
      const lines = content.split('\n');

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;

        const match = trimmed.match(/^([a-zA-Z0-9_-]+)[=<>~!]*=*([0-9.]+)?/);
        if (match) {
          deps.push({
            name: match[1],
            version: match[2] || 'unknown'
          });
        }
      }
    } catch {}
  }

  return deps;
}

// Generate CycloneDX SBOM
export function generateCycloneDX(
  targetPath: string,
  scanResult?: LocalScanResult,
  options: SBOMOptions = { format: 'cyclonedx' }
): CycloneDXDocument {
  // Try Syft first
  const syftOutput = runSyft(targetPath, 'cyclonedx-json');
  if (syftOutput) {
    try {
      const sbom = JSON.parse(syftOutput) as CycloneDXDocument;

      // Add vulnerabilities if we have scan results
      if (options.includeVulnerabilities && scanResult) {
        sbom.vulnerabilities = scanResult.packages
          .filter(p => p.vulnId)
          .map(p => ({
            id: p.vulnId!,
            ratings: [{
              severity: p.severity,
              method: 'other'
            }],
            description: p.title,
            affects: [{
              ref: `pkg:npm/${p.name}@${p.version}`
            }]
          }));
      }

      return sbom;
    } catch {}
  }

  // Manual generation
  const components: CycloneDXComponent[] = [];

  // Read NPM dependencies
  const npmDeps = readNpmDependencies(targetPath);
  for (const dep of npmDeps) {
    components.push({
      type: 'library',
      name: dep.name,
      version: dep.version,
      purl: generatePurl(dep.name, dep.version, 'npm')
    });
  }

  // Read Python dependencies
  const pyDeps = readPythonDependencies(targetPath);
  for (const dep of pyDeps) {
    components.push({
      type: 'library',
      name: dep.name,
      version: dep.version,
      purl: generatePurl(dep.name, dep.version, 'pip')
    });
  }

  // Create vulnerabilities from scan results
  const vulnerabilities: CycloneDXVulnerability[] = [];
  if (options.includeVulnerabilities && scanResult) {
    for (const pkg of scanResult.packages) {
      if (pkg.vulnId) {
        vulnerabilities.push({
          id: pkg.vulnId,
          ratings: [{
            severity: pkg.severity,
            method: 'other'
          }],
          description: pkg.title,
          recommendation: pkg.fixedVersion ? `Upgrade to ${pkg.fixedVersion}` : undefined,
          affects: [{
            ref: components.find(c => c.name === pkg.name)?.purl || `pkg:generic/${pkg.name}@${pkg.version}`
          }]
        });
      }
    }
  }

  const serialNumber = `urn:uuid:${crypto.randomUUID()}`;

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{
        vendor: 'SlopAuditor',
        name: 'slop-auditor',
        version: '0.2.0'
      }],
      component: {
        type: 'application',
        name: options.projectName || 'unknown',
        version: options.projectVersion || '0.0.0'
      }
    },
    components,
    vulnerabilities: vulnerabilities.length > 0 ? vulnerabilities : undefined
  };
}

// Generate SPDX SBOM
export function generateSPDX(
  targetPath: string,
  scanResult?: LocalScanResult,
  options: SBOMOptions = { format: 'spdx' }
): SPDXDocument {
  // Try Syft first
  const syftOutput = runSyft(targetPath, 'spdx-json');
  if (syftOutput) {
    try {
      return JSON.parse(syftOutput) as SPDXDocument;
    } catch {}
  }

  // Manual generation
  const packages: SPDXPackage[] = [];
  const relationships: SPDXDocument['relationships'] = [];

  // Root package
  const rootId = 'SPDXRef-Package-root';
  packages.push({
    SPDXID: rootId,
    name: options.projectName || 'unknown',
    versionInfo: options.projectVersion || '0.0.0',
    downloadLocation: 'NOASSERTION',
    filesAnalyzed: false,
    licenseConcluded: 'NOASSERTION',
    copyrightText: 'NOASSERTION'
  });

  relationships.push({
    spdxElementId: 'SPDXRef-DOCUMENT',
    relationshipType: 'DESCRIBES',
    relatedSpdxElement: rootId
  });

  // NPM dependencies
  const npmDeps = readNpmDependencies(targetPath);
  for (let i = 0; i < npmDeps.length; i++) {
    const dep = npmDeps[i];
    const id = `SPDXRef-Package-npm-${i}`;

    packages.push({
      SPDXID: id,
      name: dep.name,
      versionInfo: dep.version,
      downloadLocation: `https://www.npmjs.com/package/${dep.name}`,
      filesAnalyzed: false,
      licenseConcluded: 'NOASSERTION',
      copyrightText: 'NOASSERTION',
      externalRefs: [{
        referenceCategory: 'PACKAGE-MANAGER',
        referenceType: 'purl',
        referenceLocator: generatePurl(dep.name, dep.version, 'npm')
      }]
    });

    relationships.push({
      spdxElementId: rootId,
      relationshipType: 'DEPENDS_ON',
      relatedSpdxElement: id
    });
  }

  // Python dependencies
  const pyDeps = readPythonDependencies(targetPath);
  for (let i = 0; i < pyDeps.length; i++) {
    const dep = pyDeps[i];
    const id = `SPDXRef-Package-pip-${i}`;

    packages.push({
      SPDXID: id,
      name: dep.name,
      versionInfo: dep.version,
      downloadLocation: `https://pypi.org/project/${dep.name}/`,
      filesAnalyzed: false,
      licenseConcluded: 'NOASSERTION',
      copyrightText: 'NOASSERTION',
      externalRefs: [{
        referenceCategory: 'PACKAGE-MANAGER',
        referenceType: 'purl',
        referenceLocator: generatePurl(dep.name, dep.version, 'pip')
      }]
    });

    relationships.push({
      spdxElementId: rootId,
      relationshipType: 'DEPENDS_ON',
      relatedSpdxElement: id
    });
  }

  const namespace = `https://spdx.org/spdxdocs/${options.projectName || 'project'}-${Date.now()}`;

  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: options.projectName || 'unknown',
    documentNamespace: namespace,
    creationInfo: {
      created: new Date().toISOString(),
      creators: ['Tool: slop-auditor-0.2.0'],
      licenseListVersion: '3.19'
    },
    packages,
    relationships
  };
}

// Main SBOM generation function
export function generateSBOM(
  targetPath: string,
  scanResult?: LocalScanResult,
  options: SBOMOptions = { format: 'cyclonedx' }
): CycloneDXDocument | SPDXDocument {
  if (options.format === 'spdx') {
    return generateSPDX(targetPath, scanResult, options);
  }
  return generateCycloneDX(targetPath, scanResult, options);
}
