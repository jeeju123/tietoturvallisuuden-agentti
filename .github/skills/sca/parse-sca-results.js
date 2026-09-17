/**
 * parse-sca-results.js
 *
 * Bundled helper script for the `sca` skill (.github/skills/sca/).
 * Reads Trivy SCA JSON output (from STDIN, file argument, or default artefacts/sca-results.json),
 * strips thousands of lines of raw SBOM packages/metadata, and emits structured findings conforming to
 * .github/skills/sca/SKILL.md and .github/references/risk-classification.md.
 *
 * Saves compact, relevant findings directly to `artefacts/sca-results.json` (or specified --output),
 * replacing the bloated raw output to minimize token consumption while preserving complete vulnerability data.
 *
 * Direct pipe:
 *   trivy sbom ./artefacts/sbom-results.json --format json | node .github/skills/sca/parse-sca-results.js
 *
 * File input:
 *   node .github/skills/sca/parse-sca-results.js ./artefacts/sca-results.json
 */

const fs = require('fs');
const path = require('path');

const SEVERITY_ORDER = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  UNKNOWN: 0
};

const DEFAULT_OUTPUT_FILE = 'artefacts/sca-results.json';

function parseArgs(args) {
  const options = {
    input: null,
    output: DEFAULT_OUTPUT_FILE,
    stdout: false,
    format: 'json', // Defaults to structured JSON for agents & skills
    minSeverity: null,
    fixedOnly: false,
    pkg: null
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '-h' || arg === '--help') {
      printHelp();
      process.exit(0);
    } else if (arg === '-i' || arg === '--input') {
      options.input = args[++i];
    } else if (arg === '-o' || arg === '--output') {
      options.output = args[++i];
    } else if (arg === '--stdout') {
      options.stdout = true;
    } else if (arg === '--no-save') {
      options.output = null;
    } else if (arg === '--format') {
      options.format = args[++i]?.toLowerCase();
    } else if (arg === '--markdown') {
      options.format = 'markdown';
    } else if (arg === '--json') {
      options.format = 'json';
    } else if (arg === '--table') {
      options.format = 'table';
    } else if (arg === '--summary') {
      options.format = 'summary';
    } else if (arg === '--min-severity') {
      options.minSeverity = args[++i]?.toUpperCase();
    } else if (arg === '--fixed-only') {
      options.fixedOnly = true;
    } else if (arg === '--pkg') {
      options.pkg = args[++i]?.toLowerCase();
    } else if (!arg.startsWith('-')) {
      options.input = arg;
    }
  }

  return options;
}

function printHelp() {
  console.log(`
    parse-sca-results.js: Parse Trivy SCA output into structured SSDLC findings

    Usage:
      Piped directly from Trivy (saves compact findings to artefacts/sca-results.json):
        trivy sbom ./artefacts/sbom-results.json --format json | node .github/skills/sca/parse-sca-results.js

      File input (replaces raw artefacts/sca-results.json in-place with parsed output):
        node .github/skills/sca/parse-sca-results.js ./artefacts/sca-results.json

    Options:
      -i, --input <file>        Input JSON path (reads STDIN if piped, defaults to artefacts/sca-results.json)
      -o, --output <file>       Output file destination (default: artefacts/sca-results.json)
      --stdout                  Also print full output to stdout in addition to saving to file
      --no-save                 Do not write to file, only print to stdout
      --format <fmt>            json | markdown | table | summary (default: json)
      --json                    Shortcut for --format json
      --markdown                Shortcut for --format markdown
      --table                   Shortcut for --format table
      --summary                 Shortcut for --format summary
      --min-severity <level>    Minimum severity: CRITICAL, HIGH, MEDIUM, LOW
      --fixed-only              Only list vulnerabilities with available fixes
      --pkg <name>              Filter by package name
      -h, --help                Show this help message
`);
}

function resolveRiskClassification(severity, cvssScore, epssPercent = null, isKev = false) {
  if (isKev) {
    return 'Emergency';
  }

  const score = cvssScore !== null ? cvssScore : (
    severity === 'CRITICAL' ? 9.5 :
    severity === 'HIGH' ? 7.5 :
    severity === 'MEDIUM' ? 5.5 :
    severity === 'LOW' ? 2.5 : 5.0
  );

  const hasHighEpss = epssPercent !== null && epssPercent >= 10.0;

  if (score >= 7.0) {
    return hasHighEpss ? 'Critical' : 'Elevated';
  } else if (score >= 4.0) {
    return hasHighEpss ? 'High' : 'Moderate';
  } else {
    return 'Minor';
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

function generateRemediation(pkgName, installedVersion, fixedVersion, primaryUrl) {
  if (fixedVersion) {
    return `Upgrade ${pkgName} to version ${fixedVersion} or newer (e.g. npm update ${pkgName} or update package.json).`;
  }
  return `No official fix currently available. Review advisory (${primaryUrl || 'N/A'}) for mitigations, evaluate dependency necessity, or replace package.`;
}

function processScaResults(data, options) {
  if (data && Array.isArray(data.findings) && data.summary) {
    let filteredFindings = data.findings;
    const minSeverityVal = options.minSeverity ? (SEVERITY_ORDER[options.minSeverity] ?? 0) : 0;
    if (minSeverityVal > 0) {
      filteredFindings = filteredFindings.filter(f => (SEVERITY_ORDER[f.severity] ?? 0) >= minSeverityVal);
    }
    if (options.fixedOnly) {
      filteredFindings = filteredFindings.filter(f => f.fixedVersion && f.fixedVersion !== 'None available');
    }
    if (options.pkg) {
      filteredFindings = filteredFindings.filter(f => f.library.toLowerCase().includes(options.pkg));
    }
    return {
      summary: data.summary,
      findings: filteredFindings
    };
  }

  const results = data.Results || [];
  const findings = [];
  const stats = {
    totalFindings: 0,
    fixableFindings: 0,
    bySeverity: {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      UNKNOWN: 0
    },
    byRiskClass: {
      Emergency: 0,
      Critical: 0,
      Elevated: 0,
      High: 0,
      Moderate: 0,
      Minor: 0
    },
    packagesAffected: new Set()
  };

  const minSeverityVal = options.minSeverity ? (SEVERITY_ORDER[options.minSeverity] ?? 0) : 0;

  for (const targetResult of results) {
    const targetFile = targetResult.Target || 'Unknown Target';
    const vulnerabilities = targetResult.Vulnerabilities || [];

    for (const v of vulnerabilities) {
      const severity = (v.Severity || 'UNKNOWN').toUpperCase();
      const severityVal = SEVERITY_ORDER[severity] ?? 0;

      if (severityVal < minSeverityVal) continue;
      if (options.fixedOnly && !v.FixedVersion) continue;

      const pkgName = v.PkgName || 'unknown';
      if (options.pkg && !pkgName.toLowerCase().includes(options.pkg)) continue;

      const cvss = extractCvss(v);
      const riskClass = resolveRiskClassification(severity, cvss.score);
      const fixedVersion = v.FixedVersion || null;
      const remediation = generateRemediation(pkgName, v.InstalledVersion, fixedVersion, v.PrimaryURL);

      stats.totalFindings++;
      if (fixedVersion) stats.fixableFindings++;
      stats.bySeverity[severity] = (stats.bySeverity[severity] || 0) + 1;
      stats.byRiskClass[riskClass] = (stats.byRiskClass[riskClass] || 0) + 1;
      stats.packagesAffected.add(pkgName);

      findings.push({
        target: targetFile,
        library: pkgName,
        vulnerabilityId: v.VulnerabilityID || 'Unknown',
        vendorIds: v.VendorIDs || [],
        severity: severity,
        cvss: {
          score: cvss.score,
          vector: cvss.vector,
          source: cvss.source
        },
        riskClassification: riskClass,
        status: v.Status || (fixedVersion ? 'fixed' : 'affected'),
        installedVersion: v.InstalledVersion || 'unknown',
        fixedVersion: fixedVersion || 'None available',
        description: (v.Title || v.Description || 'No description').trim().replace(/[\r\n]+/g, ' '),
        remediation: remediation,
        url: v.PrimaryURL || ''
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
    summary: {
      totalFindings: stats.totalFindings,
      fixableFindings: stats.fixableFindings,
      packagesAffectedCount: stats.packagesAffected.size,
      packagesAffected: Array.from(stats.packagesAffected),
      bySeverity: stats.bySeverity,
      byRiskClass: stats.byRiskClass
    },
    findings
  };
}

function formatMarkdown({ findings, summary }) {
  const lines = [];

  lines.push('# Software Composition Analysis (SCA) - Relevant Findings Summary\n');
  lines.push('## Overview');
  lines.push(`- **Total Vulnerabilities**: ${summary.totalFindings}`);
  lines.push(`- **Fixable Vulnerabilities**: ${summary.fixableFindings} / ${summary.totalFindings}`);
  lines.push(`- **Distinct Packages Affected**: ${summary.packagesAffectedCount}`);
  lines.push(`- **Severity Breakdown**: CRITICAL: ${summary.bySeverity.CRITICAL}, HIGH: ${summary.bySeverity.HIGH}, MEDIUM: ${summary.bySeverity.MEDIUM}, LOW: ${summary.bySeverity.LOW}`);
  lines.push(`- **Risk Classification Breakdown** (per risk-classification.md):`);
  lines.push(`  - Emergency: ${summary.byRiskClass.Emergency}`);
  lines.push(`  - Critical: ${summary.byRiskClass.Critical}`);
  lines.push(`  - Elevated: ${summary.byRiskClass.Elevated}`);
  lines.push(`  - High: ${summary.byRiskClass.High}`);
  lines.push(`  - Moderate: ${summary.byRiskClass.Moderate}`);
  lines.push(`  - Minor: ${summary.byRiskClass.Minor}\n`);

  if (findings.length === 0) {
    lines.push('No vulnerabilities found matching the specified criteria.');
    return lines.join('\n');
  }

  lines.push('## Vulnerability Findings Table\n');
  lines.push('| # | Library | Vulnerability ID | Severity | Risk Class | Installed | Fixed In | Status | Description |');
  lines.push('|---|---|---|---|---|---|---|---|---|');

  findings.forEach((f, idx) => {
    const titleTrunc = f.description.length > 80 ? f.description.substring(0, 77) + '...' : f.description;
    const safeTitle = titleTrunc.replace(/\|/g, '\\|');
    const vulnLink = f.url ? `[${f.vulnerabilityId}](${f.url})` : f.vulnerabilityId;
    lines.push(`| ${idx + 1} | \`${f.library}\` | ${vulnLink} | **${f.severity}** | ${f.riskClassification} | \`${f.installedVersion}\` | \`${f.fixedVersion}\` | ${f.status} | ${safeTitle} |`);
  });

  lines.push('\n## Actionable Remediations\n');
  findings.forEach((f, idx) => {
    lines.push(`### ${idx + 1}. \`${f.library}\` - ${f.vulnerabilityId} (${f.severity} / ${f.riskClassification})`);
    lines.push(`- **Description**: ${f.description}`);
    lines.push(`- **Current Version**: \`${f.installedVersion}\` | **Fixed Version**: \`${f.fixedVersion}\``);
    lines.push(`- **Remediation**: ${f.remediation}`);
    if (f.url) lines.push(`- **Advisory**: ${f.url}`);
    lines.push('');
  });

  return lines.join('\n');
}

function formatTable({ findings, summary }) {
  console.log(`\nSCA Summary: ${summary.totalFindings} findings (${summary.fixableFindings} fixable) across ${summary.packagesAffectedCount} packages`);
  console.log(`Severities: CRITICAL=${summary.bySeverity.CRITICAL} HIGH=${summary.bySeverity.HIGH} MEDIUM=${summary.bySeverity.MEDIUM} LOW=${summary.bySeverity.LOW}\n`);

  const rows = findings.map((f, idx) => ({
    '#': idx + 1,
    Library: f.library,
    ID: f.vulnerabilityId,
    Severity: f.severity,
    Risk: f.riskClassification,
    Installed: f.installedVersion,
    'Fixed In': f.fixedVersion,
    Remediation: f.fixedVersion !== 'None available' ? `Update to ${f.fixedVersion}` : 'No fix'
  }));

  console.table(rows);
  return '';
}

function formatSummaryOnly({ summary }) {
  const lines = [
    'SCA Vulnerability Summary',
    `Total Findings: ${summary.totalFindings}`,
    `Fixable: ${summary.fixableFindings}`,
    `Packages Affected: ${summary.packagesAffectedCount}`,
    '',
    'By Severity:',
    `  CRITICAL: ${summary.bySeverity.CRITICAL}`,
    `  HIGH:     ${summary.bySeverity.HIGH}`,
    `  MEDIUM:   ${summary.bySeverity.MEDIUM}`,
    `  LOW:      ${summary.bySeverity.LOW}`,
    '',
    'By Risk Classification (risk-classification.md):',
    `  Emergency: ${summary.byRiskClass.Emergency}`,
    `  Critical:  ${summary.byRiskClass.Critical}`,
    `  Elevated:  ${summary.byRiskClass.Elevated}`,
    `  High:      ${summary.byRiskClass.High}`,
    `  Moderate:  ${summary.byRiskClass.Moderate}`,
    `  Minor:     ${summary.byRiskClass.Minor}`
  ];
  return lines.join('\n');
}

function readInput(options) {
  return new Promise((resolve, reject) => {
    // If a specific input file was provided via argument
    if (options.input) {
      const resolvedInputPath = path.resolve(process.cwd(), options.input);
      if (!fs.existsSync(resolvedInputPath)) {
        return reject(new Error(`Input file does not exist: ${resolvedInputPath}`));
      }
      try {
        const content = fs.readFileSync(resolvedInputPath, 'utf8');
        return resolve(content);
      } catch (err) {
        return reject(err);
      }
    }

    // If stdin is piped (e.g. trivy ... | node parse-sca-results.js)
    if (!process.stdin.isTTY) {
      let buffer = '';
      process.stdin.setEncoding('utf8');
      process.stdin.on('data', chunk => {
        buffer += chunk;
      });
      process.stdin.on('end', () => {
        if (buffer.trim()) {
          resolve(buffer);
        } else {
          fallbackFile(resolve, reject);
        }
      });
      process.stdin.on('error', err => reject(err));
    } else {
      fallbackFile(resolve, reject);
    }
  });
}

function fallbackFile(resolve, reject) {
  const defaultPath = path.resolve(process.cwd(), 'artefacts/sca-results.json');
  if (fs.existsSync(defaultPath)) {
    try {
      resolve(fs.readFileSync(defaultPath, 'utf8'));
    } catch (err) {
      reject(err);
    }
  } else {
    reject(new Error(`No piped input provided and default file not found: ${defaultPath}`));
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));

  let rawData;
  try {
    rawData = await readInput(options);
  } catch (err) {
    console.error('Error reading input:', err.message);
    process.exit(1);
  }

  let jsonData;
  try {
    jsonData = JSON.parse(rawData);
  } catch (err) {
    console.error('Error parsing JSON from input. The input was not valid JSON.');
    // Check if rawData looks like an error message from Trivy or shell
    const trimmed = (rawData || '').trim();
    if (trimmed.length > 0) {
      console.error('Captured input preview:');
      console.error(trimmed.substring(0, 300) + (trimmed.length > 300 ? '...' : ''));
    }

    console.error('\nTip: If piping from Trivy, ensure Trivy succeeded without errors:');
    console.error('  trivy sbom ./artefacts/sbom-results.json --format json | node .github/skills/sca/scripts/parse-sca-results.js');

    process.exit(1);
  }

  const processed = processScaResults(jsonData, options);

  let outputText = '';
  if (options.format === 'json') {
    outputText = JSON.stringify(processed, null, 2);
  } else if (options.format === 'summary') {
    outputText = formatSummaryOnly(processed);
  } else if (options.format === 'table') {
    formatTable(processed);
    if (options.output) {
      const resolvedOutputPath = path.resolve(process.cwd(), options.output);
      fs.mkdirSync(path.dirname(resolvedOutputPath), { recursive: true });

      const fileData = resolvedOutputPath.endsWith('.md') ? formatMarkdown(processed) : JSON.stringify(processed, null, 2);
      fs.writeFileSync(resolvedOutputPath, fileData, 'utf8');

      const bytes = Buffer.byteLength(fileData, 'utf8');
      console.error(`Parsed SCA results written to: ${options.output} (${processed.summary.totalFindings} findings, ${(bytes / 1024).toFixed(1)} KB)`);
    }
    return;
  } else if (options.format === 'markdown') {
    outputText = formatMarkdown(processed);
  } else {
    outputText = JSON.stringify(processed, null, 2);
  }

  if (options.output) {
    const resolvedOutputPath = path.resolve(process.cwd(), options.output);
    fs.mkdirSync(path.dirname(resolvedOutputPath), { recursive: true });

    const fileData = resolvedOutputPath.endsWith('.md') ? formatMarkdown(processed) : JSON.stringify(processed, null, 2);
    fs.writeFileSync(resolvedOutputPath, fileData, 'utf8');

    const bytes = Buffer.byteLength(fileData, 'utf8');
    console.error(`Parsed SCA results written to: ${options.output} (${processed.summary.totalFindings} findings, ${(bytes / 1024).toFixed(1)} KB)`);
  }

  if (!options.output || options.stdout || options.format !== 'json') {
    process.stdout.write(outputText + '\n');
  } else {
    console.log(formatSummaryOnly(processed));
  }
}

main();
