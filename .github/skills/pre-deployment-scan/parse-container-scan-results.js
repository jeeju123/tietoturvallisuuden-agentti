#!/usr/bin/env node

/**
 * parse-container-scan-results.js
 *
 * Supported workflows:
 *   - Unified single-report consolidation (recommended):
 *      node .github/skills/pre-deployment-scan/parse-container-scan-results.js
 *      -> Produces artefacts/container-security-report.json
 *
 *   - In-place reduction of existing bloated files:
 *      node .github/skills/pre-deployment-scan/parse-container-scan-results.js --in-place
 *      -> Strips artefacts/misconfig-results.json and artefacts/container-scan-base-results.json
 *
 *   - Direct Trivy pipeline streaming:
 *      trivy config --format json . | node .github/skills/pre-deployment-scan/parse-container-scan-results.js --type misconfig
 *      trivy image --format json node:14.17.0-alpine | node .github/skills/pre-deployment-scan/parse-container-scan-results.js --type container
 *
 *   - Output formatting:
 *      node .github/skills/pre-deployment-scan/parse-container-scan-results.js --markdown
 *      node .github/skills/pre-deployment-scan/parse-container-scan-results.js --summary
 *      node .github/skills/pre-deployment-scan/parse-container-scan-results.js --table
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const SEVERITY_ORDER = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  UNKNOWN: 0
};

const DEFAULT_MISCONFIG_FILE = 'artefacts/misconfig-results.json';
const DEFAULT_CONTAINER_FILE = 'artefacts/container-scan-base-results.json';
const DEFAULT_REMOTE_FILE = 'artefacts/container-scan-remote-results.json';
const DEFAULT_UNIFIED_REPORT = 'artefacts/container-security-report.json';

// ANSI color escape code stripper
const ANSI_REGEX = /\u001b\[[0-9;]*[a-zA-Z]/g;

function stripAnsi(str) {
  if (typeof str !== 'string') return '';
  return str.replace(ANSI_REGEX, '');
}

function parseArgs(args) {
  const options = {
    misconfigFile: null,
    containerFile: null,
    outputFile: null,
    format: 'json',
    explicitFormat: false,
    minSeverity: null,
    fixedOnly: false,
    inPlace: false,
    keepTemp: false,
    scan: false,
    parseOnly: false,
    image: null,
    type: 'auto' // 'auto' | 'misconfig' | 'container'
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '-h' || arg === '--help') {
      printHelp();
      process.exit(0);
    } else if (arg === '--misconfig') {
      options.misconfigFile = args[++i];
    } else if (arg === '--container') {
      options.containerFile = args[++i];
    } else if (arg === '-o' || arg === '--output') {
      options.outputFile = args[++i];
    } else if (arg === '--format') {
      options.format = args[++i]?.toLowerCase();
      options.explicitFormat = true;
    } else if (arg === '--markdown') {
      options.format = 'markdown';
      options.explicitFormat = true;
    } else if (arg === '--json') {
      options.format = 'json';
      options.explicitFormat = true;
    } else if (arg === '--table') {
      options.format = 'table';
      options.explicitFormat = true;
    } else if (arg === '--summary') {
      options.format = 'summary';
      options.explicitFormat = true;
    } else if (arg === '--min-severity') {
      options.minSeverity = args[++i]?.toUpperCase();
    } else if (arg === '--fixed-only') {
      options.fixedOnly = true;
    } else if (arg === '--in-place') {
      options.inPlace = true;
    } else if (arg === '--keep-temp') {
      options.keepTemp = true;
    } else if (arg === '--scan') {
      options.scan = true;
    } else if (arg === '--parse-only') {
      options.parseOnly = true;
    } else if (arg === '--image') {
      options.image = args[++i];
    } else if (arg === '--type') {
      options.type = args[++i]?.toLowerCase();
    } else if (!arg.startsWith('-')) {
      if (!options.misconfigFile && !options.containerFile) {
        options.containerFile = arg;
      }
    }
  }

  return options;
}

function printHelp() {
  console.log(`
    parse-container-scan-results.js: pre-deployment container security runner & aggregator

    Executes or parses Trivy misconfiguration and container image scans, strips scanner bloat,
    evaluates SSDLC security gates, cleans up intermediate artifacts, and outputs a single combined report.

    Usage:
      End-to-end execution: scan Dockerfile & image directly, cleans temp files, outputs combined report:
        node .github/skills/pre-deployment-scan/parse-container-scan-results.js [options]

      Ingest existing raw/legacy files and clean them up from artefacts/:
        node .github/skills/pre-deployment-scan/parse-container-scan-results.js --parse-only

      Direct pipeline streaming:
        trivy config --format json . | node .github/skills/pre-deployment-scan/parse-container-scan-results.js --type misconfig
        trivy image --format json <image> | node .github/skills/pre-deployment-scan/parse-container-scan-results.js --type container

    Options:
      --scan                   Force fresh Trivy scan execution (default if no inputs piped/specified)
      --image <name>           Base image name to scan (defaults to auto-detecting FROM in Dockerfile)
      --keep-temp              Do NOT delete intermediate files (misconfig-results.json, etc.)
      --parse-only             Only parse and combine existing files without running Trivy
      --misconfig <path>       Path to Trivy misconfiguration JSON (default: artefacts/misconfig-results.json)
      --container <path>       Path to Trivy container scan JSON (default: artefacts/container-scan-base-results.json)
      -o, --output <path>      Output file path (default: artefacts/container-security-report.json)
      --in-place               Rewrite intermediate files in-place instead of deleting them
      --format <fmt>           json | markdown | table | summary (default: json)
      --json                   Shortcut for --format json
      --markdown               Shortcut for --format markdown
      --table                  Shortcut for --format table
      --summary                Shortcut for --format summary
      --min-severity <level>   Filter by minimum severity: CRITICAL, HIGH, MEDIUM, LOW
      --fixed-only             Only include vulnerabilities with an available patch
      --type <type>            auto | misconfig | container (for piped STDIN)
      -h, --help               Show this help message
`);
}

function detectBaseImages(dockerfilePath = 'Dockerfile') {
  const absPath = path.resolve(process.cwd(), dockerfilePath);
  if (!fs.existsSync(absPath)) return [];
  const content = fs.readFileSync(absPath, 'utf8');
  const images = [];
  const regex = /^\s*FROM\s+(?:--[a-z0-9_-]+=\S+\s+)*([^\s#]+)/gim;
  let match;
  while ((match = regex.exec(content)) !== null) {
    const img = match[1];
    if (img && img.toLowerCase() !== 'scratch' && !images.includes(img)) {
      images.push(img);
    }
  }
  return images;
}

function runTrivy(args) {
  try {
    const result = spawnSync('trivy', args, {
      encoding: 'utf8',
      windowsHide: true,
      maxBuffer: 100 * 1024 * 1024 // 100MB buffer for large image vulnerability dumps
    });

    if (result.error) {
      if (result.error.code === 'ENOENT') {
        console.error("Error: 'trivy' executable not found in PATH.");
        console.error("Please install Trivy per .github/skills/pre-deployment-scan/SKILL.md prerequisites.");
        return null;
      }
      throw result.error;
    }

    if (result.status !== 0 && result.status !== null) {
      const errOut = (result.stderr || '').trim();
      if (errOut) {
        console.warn(`Trivy warning/stderr: ${errOut.slice(0, 300)}`);
      }
    }

    if (!result.stdout || !result.stdout.trim()) {
      return null;
    }

    return JSON.parse(result.stdout);
  } catch (err) {
    console.error(`Failed executing Trivy (${args.join(' ')}):`, err.message);
    return null;
  }
}

/**
 * Normalizes Risk Classification per references/risk-classification.md:
 * - KEV: Emergency
 * - CVSS >= 7.0 and EPSS >= 10%: Critical
 * - CVSS >= 7.0 and EPSS < 10% (or unknown EPSS): Elevated
 * - CVSS < 7.0 and EPSS >= 10%: High
 * - CVSS 4.0 - 6.9 and EPSS < 10%: Moderate
 * - CVSS < 4.0: Minor
 *
 * For misconfigurations without CVSS:
 * - CRITICAL (e.g. Secrets in ENV): Emergency/Critical
 * - HIGH (e.g. USER root): Elevated
 * - MEDIUM (e.g. EXPOSE 22): Moderate
 * - LOW (e.g. No HEALTHCHECK): Minor
 */
function resolveRiskClassification(severity, cvssScore = null, epssPercent = null, isKev = false) {
  if (isKev) return 'Emergency';

  const sevUpper = (severity || 'UNKNOWN').toUpperCase();

  if (cvssScore !== null) {
    const hasHighEpss = epssPercent !== null && epssPercent >= 10.0;
    if (cvssScore >= 7.0) {
      return hasHighEpss ? 'Critical' : 'Elevated';
    } else if (cvssScore >= 4.0) {
      return hasHighEpss ? 'High' : 'Moderate';
    } else {
      return 'Minor';
    }
  }

  // Fallback heuristic based on native severity
  switch (sevUpper) {
    case 'CRITICAL':
      return 'Critical';
    case 'HIGH':
      return 'Elevated';
    case 'MEDIUM':
      return 'Moderate';
    case 'LOW':
      return 'Minor';
    default:
      return 'Moderate';
  }
}

function extractCvss(vuln) {
  if (!vuln.CVSS || typeof vuln.CVSS !== 'object') {
    return { score: null, vector: null, source: null };
  }

  const preferredSources = ['ghsa', 'nvd', 'redhat'];
  const availableSources = Object.keys(vuln.CVSS);
  const source = preferredSources.find(s => availableSources.includes(s)) || availableSources[0];

  if (!source || !vuln.CVSS[source]) {
    return { score: null, vector: null, source: null };
  }

  const data = vuln.CVSS[source];
  const score = data.V3Score ?? data.V40Score ?? data.V2Score ?? null;
  const vector = data.V3Vector ?? data.V40Vector ?? data.V2Vector ?? null;

  return { score, vector, source };
}

function extractSnippet(causeMetadata) {
  if (!causeMetadata || !causeMetadata.Code || !Array.isArray(causeMetadata.Code.Lines)) {
    return null;
  }
  const lines = causeMetadata.Code.Lines.map(l => stripAnsi(l.Content || '')).filter(Boolean);
  return lines.join('\n') || null;
}

function generateRemediation(pkgName, installedVersion, fixedVersion, primaryUrl) {
  if (fixedVersion) {
    return `Upgrade ${pkgName} to version ${fixedVersion} or newer (via base image upgrade or package update).`;
  }
  return `No official fix available for ${pkgName} in current OS release. Consider updating base image to a modern/supported distribution.`;
}

function parseMisconfigurations(data, options = {}) {
  const findings = [];
  const stats = {
    total: 0,
    bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 },
    byRiskClass: { Emergency: 0, Critical: 0, Elevated: 0, High: 0, Moderate: 0, Minor: 0 }
  };

  const minSeverityVal = options.minSeverity ? (SEVERITY_ORDER[options.minSeverity] ?? 0) : 0;

  // Handle already-parsed lean format
  if (Array.isArray(data.findings)) {
    for (const m of data.findings) {
      const severity = (m.severity || 'UNKNOWN').toUpperCase();
      const severityVal = SEVERITY_ORDER[severity] ?? 0;
      if (severityVal < minSeverityVal) continue;

      stats.total++;
      stats.bySeverity[severity] = (stats.bySeverity[severity] || 0) + 1;
      const riskClass = m.riskClassification || resolveRiskClassification(severity);
      stats.byRiskClass[riskClass] = (stats.byRiskClass[riskClass] || 0) + 1;
      findings.push(m);
    }
    return { findings, stats };
  }

  const results = data.Results || [];

  for (const targetResult of results) {
    const targetFile = targetResult.Target || 'Dockerfile';
    const misconfigurations = targetResult.Misconfigurations || [];

    for (const m of misconfigurations) {
      const severity = (m.Severity || 'UNKNOWN').toUpperCase();
      const severityVal = SEVERITY_ORDER[severity] ?? 0;

      if (severityVal < minSeverityVal) continue;

      // Special case: Secrets in Dockerfile ENV are categorized as Critical/Emergency
      const isSecretRule = m.ID === 'DS-0031' || /secret|credential|password|key/i.test(m.Title || '');
      const riskClass = isSecretRule && severity === 'CRITICAL' ? 'Critical' : resolveRiskClassification(severity);

      stats.total++;
      stats.bySeverity[severity] = (stats.bySeverity[severity] || 0) + 1;
      stats.byRiskClass[riskClass] = (stats.byRiskClass[riskClass] || 0) + 1;

      const cause = m.CauseMetadata || {};
      const snippet = extractSnippet(cause);

      findings.push({
        id: m.ID || 'Unknown',
        title: (m.Title || 'Security check failed').trim(),
        severity: severity,
        riskClassification: riskClass,
        target: targetFile,
        startLine: cause.StartLine ?? null,
        endLine: cause.EndLine ?? null,
        codeSnippet: snippet,
        message: (m.Message || m.Description || '').trim().replace(/[\r\n]+/g, ' '),
        resolution: (m.Resolution || 'Review security guideline').trim().replace(/[\r\n]+/g, ' '),
        primaryUrl: m.PrimaryURL || (m.References && m.References[0]) || ''
      });
    }
  }

  // Sort misconfigurations: Critical -> High -> Medium -> Low
  findings.sort((a, b) => {
    return (SEVERITY_ORDER[b.severity] ?? 0) - (SEVERITY_ORDER[a.severity] ?? 0);
  });

  return { findings, stats };
}

function parseContainerVulnerabilities(data, options = {}) {
  const findings = [];
  const stats = {
    total: 0,
    fixable: 0,
    bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 },
    byRiskClass: { Emergency: 0, Critical: 0, Elevated: 0, High: 0, Moderate: 0, Minor: 0 },
    packagesAffected: new Set()
  };

  const minSeverityVal = options.minSeverity ? (SEVERITY_ORDER[options.minSeverity] ?? 0) : 0;

  // Handle already-parsed lean format
  if (Array.isArray(data.findings)) {
    for (const v of data.findings) {
      const severity = (v.severity || 'UNKNOWN').toUpperCase();
      const severityVal = SEVERITY_ORDER[severity] ?? 0;
      if (severityVal < minSeverityVal) continue;
      if (options.fixedOnly && (!v.fixedVersion || v.fixedVersion === 'None available')) continue;

      const pkgName = v.package || 'unknown';
      stats.total++;
      if (v.fixedVersion && v.fixedVersion !== 'None available') stats.fixable++;
      stats.bySeverity[severity] = (stats.bySeverity[severity] || 0) + 1;
      const riskClass = v.riskClassification || resolveRiskClassification(severity, v.cvss?.score);
      stats.byRiskClass[riskClass] = (stats.byRiskClass[riskClass] || 0) + 1;
      stats.packagesAffected.add(pkgName);
      findings.push(v);
    }
    return {
      findings,
      stats: {
        ...stats,
        packagesAffectedCount: stats.packagesAffected.size,
        packagesAffected: Array.from(stats.packagesAffected)
      }
    };
  }

  const results = data.Results || [];

  for (const targetResult of results) {
    const targetName = targetResult.Target || 'container';
    const targetClass = targetResult.Class || 'os-pkgs';
    const vulnerabilities = targetResult.Vulnerabilities || [];

    for (const v of vulnerabilities) {
      const severity = (v.Severity || 'UNKNOWN').toUpperCase();
      const severityVal = SEVERITY_ORDER[severity] ?? 0;

      if (severityVal < minSeverityVal) continue;
      if (options.fixedOnly && !v.FixedVersion) continue;

      const pkgName = v.PkgName || 'unknown';
      const cvss = extractCvss(v);
      const riskClass = resolveRiskClassification(severity, cvss.score);
      const fixedVersion = v.FixedVersion || null;
      const remediation = generateRemediation(pkgName, v.InstalledVersion, fixedVersion, v.PrimaryURL);

      stats.total++;
      if (fixedVersion) stats.fixable++;
      stats.bySeverity[severity] = (stats.bySeverity[severity] || 0) + 1;
      stats.byRiskClass[riskClass] = (stats.byRiskClass[riskClass] || 0) + 1;
      stats.packagesAffected.add(pkgName);

      findings.push({
        target: targetName,
        class: targetClass,
        package: pkgName,
        vulnerabilityId: v.VulnerabilityID || 'Unknown',
        severity: severity,
        riskClassification: riskClass,
        cvss: {
          score: cvss.score,
          vector: cvss.vector,
          source: cvss.source
        },
        installedVersion: v.InstalledVersion || 'unknown',
        fixedVersion: fixedVersion || 'None available',
        status: v.Status || (fixedVersion ? 'fixed' : 'affected'),
        title: (v.Title || v.VulnerabilityID || 'No title').trim().replace(/[\r\n]+/g, ' '),
        remediation: remediation,
        primaryUrl: v.PrimaryURL || ''
      });
    }
  }

  // Sort findings: Critical -> High -> Medium -> Low
  findings.sort((a, b) => {
    const sevDiff = (SEVERITY_ORDER[b.severity] ?? 0) - (SEVERITY_ORDER[a.severity] ?? 0);

    if (sevDiff !== 0) return sevDiff;
    
    return (b.cvss?.score || 0) - (a.cvss?.score || 0);
  });

  return {
    findings,
    stats: {
      ...stats,
      packagesAffectedCount: stats.packagesAffected.size,
      packagesAffected: Array.from(stats.packagesAffected)
    }
  };
}

/**
 * Extracts key image metadata (OS, EOL status, tags)
 */
function extractImageMetadata(data) {
  if (!data || typeof data !== 'object') return null;
  if (data.imageMetadata) return data.imageMetadata;

  const meta = data.Metadata || {};
  const os = meta.OS || {};
  return {
    artifactName: data.ArtifactName || 'unknown',
    osFamily: os.Family || 'unknown',
    osVersion: os.Name || 'unknown',
    isEndOfLife: Boolean(os.EOSL),
    architecture: meta.ImageConfig?.architecture || 'unknown',
    created: meta.ImageConfig?.created || null
  };
}

/**
 * Evaluates pre-deployment SSDLC Security Gate
 */
function evaluateGate(summary) {
  const criticalMisconfigs = summary.misconfigurations.bySeverity.CRITICAL;
  const criticalVulns = summary.vulnerabilities.bySeverity.CRITICAL;
  const isEol = summary.imageMetadata?.isEndOfLife;

  const failureReasons = [];
  if (criticalMisconfigs > 0) failureReasons.push(`${criticalMisconfigs} CRITICAL misconfiguration(s) detected (e.g. exposed secrets).`);
  if (criticalVulns > 0) failureReasons.push(`${criticalVulns} CRITICAL container package vulnerability(ies) detected.`);
  if (isEol) failureReasons.push(`Base image OS is End-Of-Life (${summary.imageMetadata?.osFamily} ${summary.imageMetadata?.osVersion}).`);

  return {
    status: failureReasons.length === 0 ? 'PASSED' : 'FAILED',
    reasons: failureReasons,
    blockingIssuesCount: criticalMisconfigs + criticalVulns + (isEol ? 1 : 0)
  };
}

/**
 * Creates unified consolidated report
 */
function createUnifiedReport(misconfigData, containerData, options) {
  const misconfig = misconfigData ? parseMisconfigurations(misconfigData, options) : { findings: [], stats: { total: 0, bySeverity: {}, byRiskClass: {} } };
  const container = containerData ? parseContainerVulnerabilities(containerData, options) : { findings: [], stats: { total: 0, fixable: 0, bySeverity: {}, byRiskClass: {} } };
  const imageMetadata = containerData ? extractImageMetadata(containerData) : null;

  const totalFindings = misconfig.stats.total + container.stats.total;

  // Aggregate combined severities
  const combinedSeverity = {
    CRITICAL: (misconfig.stats.bySeverity.CRITICAL || 0) + (container.stats.bySeverity.CRITICAL || 0),
    HIGH: (misconfig.stats.bySeverity.HIGH || 0) + (container.stats.bySeverity.HIGH || 0),
    MEDIUM: (misconfig.stats.bySeverity.MEDIUM || 0) + (container.stats.bySeverity.MEDIUM || 0),
    LOW: (misconfig.stats.bySeverity.LOW || 0) + (container.stats.bySeverity.LOW || 0)
  };

  const combinedRiskClass = {
    Emergency: (misconfig.stats.byRiskClass.Emergency || 0) + (container.stats.byRiskClass.Emergency || 0),
    Critical: (misconfig.stats.byRiskClass.Critical || 0) + (container.stats.byRiskClass.Critical || 0),
    Elevated: (misconfig.stats.byRiskClass.Elevated || 0) + (container.stats.byRiskClass.Elevated || 0),
    High: (misconfig.stats.byRiskClass.High || 0) + (container.stats.byRiskClass.High || 0),
    Moderate: (misconfig.stats.byRiskClass.Moderate || 0) + (container.stats.byRiskClass.Moderate || 0),
    Minor: (misconfig.stats.byRiskClass.Minor || 0) + (container.stats.byRiskClass.Minor || 0)
  };

  const summary = {
    totalFindings,
    gate: null,
    imageMetadata,
    combinedSeverity,
    combinedRiskClass,
    misconfigurations: misconfig.stats,
    vulnerabilities: container.stats
  };

  summary.gate = evaluateGate(summary);

  return {
    summary,
    misconfigurations: misconfig.findings,
    vulnerabilities: container.findings
  };
}

function formatMarkdown(report) {
  const { summary, misconfigurations, vulnerabilities } = report;
  const lines = [];

  lines.push('# Container & Pre-Deployment Security Report\n');
  lines.push(`**Gate Status**: ${summary.gate.status === 'PASSED' ? ' **PASSED**' : ' **FAILED (BLOCKED)**'}`);
  if (summary.gate.reasons.length > 0) {
    summary.gate.reasons.forEach(r => lines.push(`- WARNING: ${r}`));
  }
  lines.push('');

  if (summary.imageMetadata) {
    lines.push('## Base Image Overview');
    lines.push(`- **Image**: \`${summary.imageMetadata.artifactName}\``);
    lines.push(`- **OS**: ${summary.imageMetadata.osFamily} ${summary.imageMetadata.osVersion} ${summary.imageMetadata.isEndOfLife ? 'NOT SUPPORTED **(END-OF-LIFE)**' : 'SUPPORTED'}`);
    lines.push(`- **Architecture**: ${summary.imageMetadata.architecture}\n`);
  }

  lines.push('## Executive Summary');
  lines.push(`- **Total Findings**: ${summary.totalFindings}`);
  lines.push(`- **Misconfigurations**: ${summary.misconfigurations.total}`);
  lines.push(`- **Container Vulnerabilities**: ${summary.vulnerabilities.total} (${summary.vulnerabilities.fixable} fixable) across ${summary.vulnerabilities.packagesAffectedCount || 0} packages`);
  lines.push(`- **Severity Breakdown**: CRITICAL: ${summary.combinedSeverity.CRITICAL}, HIGH: ${summary.combinedSeverity.HIGH}, MEDIUM: ${summary.combinedSeverity.MEDIUM}, LOW: ${summary.combinedSeverity.LOW}`);
  lines.push(`- **Risk Classification Breakdown** (per risk-classification.md):`);
  lines.push(`  - Emergency: ${summary.combinedRiskClass.Emergency}`);
  lines.push(`  - Critical: ${summary.combinedRiskClass.Critical}`);
  lines.push(`  - Elevated: ${summary.combinedRiskClass.Elevated}`);
  lines.push(`  - High: ${summary.combinedRiskClass.High}`);
  lines.push(`  - Moderate: ${summary.combinedRiskClass.Moderate}`);
  lines.push(`  - Minor: ${summary.combinedRiskClass.Minor}\n`);

  // Misconfigurations Section
  if (misconfigurations.length > 0) {
    lines.push('## Dockerfile & IaC Misconfigurations\n');
    lines.push('| # | Check ID | Severity | Line | Title | Resolution |');
    lines.push('|---|---|---|---|---|---|');

    misconfigurations.forEach((m, idx) => {
      const loc = m.startLine ? `L${m.startLine}` : 'N/A';
      lines.push(`| ${idx + 1} | [${m.id}](${m.primaryUrl || '#'}) | **${m.severity}** | ${loc} | ${m.title} | ${m.resolution} |`);
    });
    lines.push('');
  }

  // Container Vulnerabilities Section
  if (vulnerabilities.length > 0) {
    lines.push('## Top Container Image Vulnerabilities\n');
    lines.push('| # | Package | CVE ID | Severity | Risk Class | Installed | Fixed In | Status | Remediation |');
    lines.push('|---|---|---|---|---|---|---|---|---|');

    vulnerabilities.slice(0, 30).forEach((v, idx) => {
      const link = v.primaryUrl ? `[${v.vulnerabilityId}](${v.primaryUrl})` : v.vulnerabilityId;
      lines.push(`| ${idx + 1} | \`${v.package}\` | ${link} | **${v.severity}** | ${v.riskClassification} | \`${v.installedVersion}\` | \`${v.fixedVersion}\` | ${v.status} | ${v.remediation} |`);
    });
    if (vulnerabilities.length > 30) {
      lines.push(`\n*(Showing top 30 of ${vulnerabilities.length} container vulnerabilities. See full JSON for complete list.)*`);
    }
  }

  return lines.join('\n');
}

function formatSummary(report) {
  const { summary } = report;
  const lines = [
    'Container & Pre-Deployment Security Summary',
    `Gate Status: ${summary.gate.status} (${summary.gate.blockingIssuesCount} blocking issues)`,
    summary.imageMetadata ? `Base Image: ${summary.imageMetadata.artifactName} (${summary.imageMetadata.osFamily} ${summary.imageMetadata.osVersion}${summary.imageMetadata.isEndOfLife ? ' - EOL!' : ''})` : null,
    `Total Findings: ${summary.totalFindings} (Misconfigs: ${summary.misconfigurations.total}, Vulnerabilities: ${summary.vulnerabilities.total})`,
    '',
    'Severities:',
    `  CRITICAL: ${summary.combinedSeverity.CRITICAL}`,
    `  HIGH:     ${summary.combinedSeverity.HIGH}`,
    `  MEDIUM:   ${summary.combinedSeverity.MEDIUM}`,
    `  LOW:      ${summary.combinedSeverity.LOW}`,
    '',
    'Risk Classifications:',
    `  Emergency: ${summary.combinedRiskClass.Emergency}`,
    `  Critical:  ${summary.combinedRiskClass.Critical}`,
    `  Elevated:  ${summary.combinedRiskClass.Elevated}`,
    `  High:      ${summary.combinedRiskClass.High}`,
    `  Moderate:  ${summary.combinedRiskClass.Moderate}`,
    `  Minor:     ${summary.combinedRiskClass.Minor}`
  ].filter(Boolean);

  return lines.join('\n');
}

function formatTable(report) {
  console.log(`\nContainer Security Summary: ${report.summary.totalFindings} findings (Gate: ${report.summary.gate.status})\n`);

  if (report.misconfigurations.length > 0) {
    console.log('--- Misconfigurations ---');
    console.table(report.misconfigurations.map((m, idx) => ({
      '#': idx + 1,
      ID: m.id,
      Severity: m.severity,
      Line: m.startLine || 'N/A',
      Title: m.title.length > 40 ? m.title.substring(0, 37) + '...' : m.title,
      Resolution: m.resolution.length > 40 ? m.resolution.substring(0, 37) + '...' : m.resolution
    })));
  }

  if (report.vulnerabilities.length > 0) {
    console.log('\n--- Container Vulnerabilities (Top 25) ---');
    console.table(report.vulnerabilities.slice(0, 25).map((v, idx) => ({
      '#': idx + 1,
      Package: v.package,
      CVE: v.vulnerabilityId,
      Severity: v.severity,
      Risk: v.riskClassification,
      Installed: v.installedVersion,
      'Fixed In': v.fixedVersion
    })));
  }
}

function readJsonFile(filePath) {
  if (!filePath) return null;

  const absPath = path.resolve(process.cwd(), filePath);

  if (!fs.existsSync(absPath)) return null;
  try {
    const raw = fs.readFileSync(absPath, 'utf8');

    return JSON.parse(raw);
  } catch (err) {
    console.error(`Warning: Failed to read or parse JSON file at ${absPath}: ${err.message}`);

    return null;
  }
}

function readStdin() {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) return resolve(null);

    let buffer = '';

    process.stdin.setEncoding('utf8');
    process.stdin.on('data', chunk => { buffer += chunk; });
    process.stdin.on('end', () => {
      if (buffer.trim()) {
        try {
          resolve(JSON.parse(buffer));
        } catch (err) {
          console.error('Error parsing STDIN as JSON:', err.message);
          resolve(null);
        }
      } else {
        resolve(null);
      }
    });
    process.stdin.on('error', () => resolve(null));
  });
}

async function main() {
  const options = parseArgs(process.argv.slice(2));

  // Check STDIN first
  const stdinData = await readStdin();

  let misconfigData = null;
  let containerData = null;

  if (stdinData) {
    // Autodetect or use --type
    const isImage = options.type === 'container' || stdinData.ArtifactType === 'container_image' || (stdinData.Results && stdinData.Results.some(r => r.Class === 'os-pkgs'));
    if (isImage) {
      containerData = stdinData;
    } else {
      misconfigData = stdinData;
    }
  }

  // Load or execute Misconfiguration Scan
  if (!misconfigData) {
    if (options.misconfigFile) {
      misconfigData = readJsonFile(options.misconfigFile);
    } else if (options.parseOnly) {
      if (fs.existsSync(DEFAULT_MISCONFIG_FILE)) {
        misconfigData = readJsonFile(DEFAULT_MISCONFIG_FILE);
      }
    } else {
      // Execute live Trivy config scan in-memory
      console.error('› Running Trivy IaC / Dockerfile misconfiguration scan in-memory...');
      misconfigData = runTrivy(['config', '--format=json', '.']);
      if (!misconfigData && fs.existsSync(DEFAULT_MISCONFIG_FILE)) {
        misconfigData = readJsonFile(DEFAULT_MISCONFIG_FILE);
      }
    }
  }

  // Load or execute Container Vulnerability Scan
  if (!containerData) {
    if (options.containerFile) {
      containerData = readJsonFile(options.containerFile);
    } else if (options.parseOnly) {
      if (fs.existsSync(DEFAULT_CONTAINER_FILE)) {
        containerData = readJsonFile(DEFAULT_CONTAINER_FILE);
      } else if (fs.existsSync(DEFAULT_REMOTE_FILE)) {
        containerData = readJsonFile(DEFAULT_REMOTE_FILE);
      }
    } else {
      // Determine image to scan
      const detectedImages = detectBaseImages();
      const targetImage = options.image || detectedImages[0];

      if (targetImage) {
        console.error(`› Running Trivy container scan in-memory for base image: ${targetImage}...`);

        containerData = runTrivy(['image', '--format=json', targetImage]);
      }

      if (!containerData && fs.existsSync(DEFAULT_CONTAINER_FILE)) {
        containerData = readJsonFile(DEFAULT_CONTAINER_FILE);
      } else if (!containerData && fs.existsSync(DEFAULT_REMOTE_FILE)) {
        containerData = readJsonFile(DEFAULT_REMOTE_FILE);
      }
    }
  }

  if (!misconfigData && !containerData) {
    console.error('Error: No input data found. Neither STDIN, live Trivy execution, nor default artefact files were available.');
    process.exit(1);
  }

  // Generate unified report
  const unifiedReport = createUnifiedReport(misconfigData, containerData, options);

  // If --in-place was requested, rewrite the input files with lean stripped versions
  if (options.inPlace) {
    if (misconfigData && fs.existsSync(DEFAULT_MISCONFIG_FILE)) {
      const leanMisconfig = {
        summary: unifiedReport.summary.misconfigurations,
        findings: unifiedReport.misconfigurations
      };

      fs.writeFileSync(path.resolve(process.cwd(), DEFAULT_MISCONFIG_FILE), JSON.stringify(leanMisconfig, null, 2), 'utf8');

      console.error(`[in-place] Updated ${DEFAULT_MISCONFIG_FILE} (${unifiedReport.misconfigurations.length} findings)`);
    }

    if (containerData && fs.existsSync(DEFAULT_CONTAINER_FILE)) {
      const leanContainer = {
        imageMetadata: unifiedReport.summary.imageMetadata,
        summary: unifiedReport.summary.vulnerabilities,
        findings: unifiedReport.vulnerabilities
      };

      fs.writeFileSync(path.resolve(process.cwd(), DEFAULT_CONTAINER_FILE), JSON.stringify(leanContainer, null, 2), 'utf8');

      console.error(`[in-place] Updated ${DEFAULT_CONTAINER_FILE} (${unifiedReport.vulnerabilities.length} findings)`);
    }
  } else if (!options.keepTemp) {
    const intermediateFiles = [
      DEFAULT_MISCONFIG_FILE,
      DEFAULT_CONTAINER_FILE,
      DEFAULT_REMOTE_FILE
    ];
    for (const relPath of intermediateFiles) {
      const absPath = path.resolve(process.cwd(), relPath);

      if (fs.existsSync(absPath)) {
        try {
          fs.unlinkSync(absPath);
          console.error(`Cleaned up intermediate artifact: ${relPath}`);
        } catch (e) {
          // ignore cleanup failures
        }
      }
    }
  }

  // If explicit formatting was requested (summary, table, markdown) without -o, print directly to stdout
  if (options.explicitFormat && !options.outputFile) {
    if (options.format === 'markdown') {
      process.stdout.write(formatMarkdown(unifiedReport) + '\n');
    } else if (options.format === 'summary') {
      process.stdout.write(formatSummary(unifiedReport) + '\n');
    } else if (options.format === 'table') {
      formatTable(unifiedReport);
    } else {
      process.stdout.write(JSON.stringify(unifiedReport, null, 2) + '\n');
    }
    return;
  }

  const jsonOutput = JSON.stringify(unifiedReport, null, 2);

  // Target file resolution
  if (options.outputFile) {
    let contentToWrite = jsonOutput;
    if (options.format === 'markdown') contentToWrite = formatMarkdown(unifiedReport);
    else if (options.format === 'summary') contentToWrite = formatSummary(unifiedReport);

    const resolvedOut = path.resolve(process.cwd(), options.outputFile);
    
    fs.mkdirSync(path.dirname(resolvedOut), { recursive: true });
    fs.writeFileSync(resolvedOut, contentToWrite, 'utf8');

    console.error(`Generated report at: ${options.outputFile}`);
  } else if (!process.stdout.isTTY) {
    process.stdout.write(jsonOutput + '\n');
  } else {
    // Default interactive run: write canonical unified report JSON to disk and display summary
    const resolvedOut = path.resolve(process.cwd(), DEFAULT_UNIFIED_REPORT);

    fs.mkdirSync(path.dirname(resolvedOut), { recursive: true });
    fs.writeFileSync(resolvedOut, jsonOutput, 'utf8');

    console.error(`Consolidated container security report written to: ${DEFAULT_UNIFIED_REPORT}`);
    console.log('\n' + formatSummary(unifiedReport));
  }
}

if (require.main === module) {
  main().catch(err => {
    console.error('Execution error:', err);
    process.exit(1);
  });
}

module.exports = {
  createUnifiedReport,
  parseMisconfigurations,
  parseContainerVulnerabilities,
  extractImageMetadata,
  evaluateGate
};
