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

const fs = require("fs");
const path = require("path");

const SEVERITY_ORDER = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  UNKNOWN: 0,
};

const DEFAULT_OUTPUT_FILE = "artefacts/sca-results.json";

function parseArgs(args) {
  const options = {
    input: null,
    output: DEFAULT_OUTPUT_FILE,
    stdout: false,
    format: "json",
    minSeverity: null,
    fixedOnly: false,
    keepTemp: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "-h" || arg === "--help") {
      printHelp();
      process.exit(0);
    } else if (arg === "-i" || arg === "--input") {
      options.input = args[++i];
    } else if (arg === "-o" || arg === "--output") {
      options.output = args[++i];
    } else if (arg === "--stdout") {
      options.stdout = true;
    } else if (arg === "--format") {
      const fmt = args[++i]?.toLowerCase();
      if (fmt === "json") {
        options.format = fmt;
      }
    } else if (arg === "--json") {
      options.format = "json";
    } else if (arg === "--min-severity") {
      options.minSeverity = args[++i]?.toUpperCase();
    } else if (arg === "--fixed-only") {
      options.fixedOnly = true;
    } else if (arg === "--keep-temp") {
      options.keepTemp = true;
    } else if (!arg.startsWith("-")) {
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

      File input (replaces raw report in-place with parsed output):
        node .github/skills/sca/parse-sca-results.js ./artefacts/sca-results.json

    Options:
      -i, --input <file>        Input JSON path (reads STDIN if piped, defaults to artefacts/sca-results.json)
      -o, --output <file>       Output file destination (default: artefacts/sca-results.json)
      --stdout                  Print output to stdout
      --format <fmt>            json (default: json)
      --json                    Shortcut for --format json
      --min-severity <level>    Minimum severity: CRITICAL, HIGH, MEDIUM, LOW
      --fixed-only              Only list vulnerabilities with available fixes
      --keep-temp               Preserve intermediate scan files for audit trail
      -h, --help                Show this help message
`);
}

function extractCvss(vuln) {
  if (!vuln.CVSS || typeof vuln.CVSS !== "object") {
    return { score: null, vector: null, source: null };
  }

  const preferredSources = ["ghsa", "nvd", "redhat"];
  const availableSources = Object.keys(vuln.CVSS);
  const source =
    preferredSources.find((s) => availableSources.includes(s)) ||
    availableSources[0];

  if (!source || !vuln.CVSS[source]) {
    return { score: null, vector: null, source: null };
  }

  const data = vuln.CVSS[source];
  const score = data.V3Score ?? data.V40Score ?? data.V2Score ?? null;
  const vector = data.V3Vector ?? data.V40Vector ?? data.V2Vector ?? null;

  return { score, vector, source };
}

function extractEpssAndKev(vuln) {
  let isKev = false;
  let epssPercent = null;

  if (
    vuln.CveMetadata?.CISA ||
    vuln.KnownExploitedVulnerabilities ||
    vuln.Kev
  ) {
    isKev = true;
  }
  if (Array.isArray(vuln.References)) {
    if (
      vuln.References.some((r) =>
        /cisa\.gov\/known-exploited-vulnerabilities/i.test(r),
      )
    ) {
      isKev = true;
    }
  }

  if (vuln.EPSS && typeof vuln.EPSS === "object") {
    const rawScore = vuln.EPSS.Score ?? vuln.EPSS.score ?? null;
    if (rawScore !== null && !isNaN(rawScore)) {
      epssPercent =
        parseFloat(rawScore) <= 1.0
          ? parseFloat(rawScore) * 100
          : parseFloat(rawScore);
    }
  }

  return { isKev, epssPercent };
}

function generateRemediation(
  pkgName,
  installedVersion,
  fixedVersion,
  primaryUrl,
) {
  if (fixedVersion) {
    return `Upgrade ${pkgName} to version ${fixedVersion} or newer (e.g. npm update ${pkgName} or update package.json).`;
  }
  return `No official fix currently available. Review advisory (${primaryUrl || "N/A"}) for mitigations, evaluate dependency necessity, or replace package.`;
}

function processScaResults(data, options) {
  if (data && Array.isArray(data.findings) && data.summary) {
    let filteredFindings = data.findings;
    const minSeverityVal = options.minSeverity
      ? (SEVERITY_ORDER[options.minSeverity] ?? 0)
      : 0;
    if (minSeverityVal > 0) {
      filteredFindings = filteredFindings.filter(
        (f) => (SEVERITY_ORDER[f.severity] ?? 0) >= minSeverityVal,
      );
    }
    if (options.fixedOnly) {
      filteredFindings = filteredFindings.filter(
        (f) => f.fixedVersion && f.fixedVersion !== "None available",
      );
    }

    const affectedPkgs = new Set(filteredFindings.map((f) => f.library).filter(Boolean));
    const recomputedSummary = {
      totalFindings: filteredFindings.length,
      fixableFindings: filteredFindings.filter(
        (f) => f.fixedVersion && f.fixedVersion !== "None available",
      ).length,
      packagesAffectedCount: affectedPkgs.size,
      packagesAffected: Array.from(affectedPkgs),
      bySeverity: {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        UNKNOWN: 0,
      },
    };

    for (const f of filteredFindings) {
      const sev = (f.severity || "UNKNOWN").toUpperCase();
      if (recomputedSummary.bySeverity[sev] !== undefined) {
        recomputedSummary.bySeverity[sev]++;
      } else {
        recomputedSummary.bySeverity.UNKNOWN++;
      }
    }

    return {
      summary: recomputedSummary,
      findings: filteredFindings,
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
      UNKNOWN: 0,
    },
    packagesAffected: new Set(),
  };

  const minSeverityVal = options.minSeverity
    ? (SEVERITY_ORDER[options.minSeverity] ?? 0)
    : 0;

  for (const targetResult of results) {
    const targetFile = targetResult.Target || "Unknown Target";
    const vulnerabilities = targetResult.Vulnerabilities || [];

    for (const v of vulnerabilities) {
      const severity = (v.Severity || "UNKNOWN").toUpperCase();
      const severityVal = SEVERITY_ORDER[severity] ?? 0;

      if (severityVal < minSeverityVal) continue;
      if (options.fixedOnly && !v.FixedVersion) continue;

      const pkgName = v.PkgName || "unknown";

      const cvss = extractCvss(v);
      const { isKev, epssPercent } = extractEpssAndKev(v);
      const fixedVersion = v.FixedVersion || null;
      const remediation = generateRemediation(
        pkgName,
        v.InstalledVersion,
        fixedVersion,
        v.PrimaryURL,
      );

      stats.totalFindings++;
      if (fixedVersion) stats.fixableFindings++;
      stats.bySeverity[severity] = (stats.bySeverity[severity] || 0) + 1;
      stats.packagesAffected.add(pkgName);

      findings.push({
        target: targetFile,
        library: pkgName,
        vulnerabilityId: v.VulnerabilityID || "Unknown",
        vendorIds: v.VendorIDs || [],
        severity: severity,
        isKev,
        epssPercent,
        cvss: {
          score: cvss.score,
          vector: cvss.vector,
          source: cvss.source,
        },
        status: v.Status || (fixedVersion ? "fixed" : "affected"),
        installedVersion: v.InstalledVersion || "unknown",
        fixedVersion: fixedVersion || "None available",
        description: (v.Title || v.Description || "No description")
          .trim()
          .replace(/[\r\n]+/g, " "),
        remediation: remediation,
        url: v.PrimaryURL || "",
      });
    }
  }

  // Sort findings: Critical -> High -> Medium -> Low
  findings.sort((a, b) => {
    const sevDiff =
      (SEVERITY_ORDER[b.severity] ?? 0) - (SEVERITY_ORDER[a.severity] ?? 0);
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
    },
    findings,
  };
}

function formatSummaryOnly({ summary }) {
  const lines = [
    "SCA Vulnerability Summary",
    `Total Findings: ${summary.totalFindings}`,
    `Fixable: ${summary.fixableFindings}`,
    `Packages Affected: ${summary.packagesAffectedCount}`,
    "",
    "By Severity:",
    `  CRITICAL: ${summary.bySeverity.CRITICAL}`,
    `  HIGH:     ${summary.bySeverity.HIGH}`,
    `  MEDIUM:   ${summary.bySeverity.MEDIUM}`,
    `  LOW:      ${summary.bySeverity.LOW}`,
  ];
  return lines.join("\n");
}

function readInput(options) {
  return new Promise((resolve, reject) => {
    // If a specific input file was provided via argument
    if (options.input) {
      const resolvedInputPath = path.resolve(process.cwd(), options.input);
      if (!fs.existsSync(resolvedInputPath)) {
        return reject(
          new Error(`Input file does not exist: ${resolvedInputPath}`),
        );
      }
      try {
        const content = fs.readFileSync(resolvedInputPath, "utf8");
        return resolve(content);
      } catch (err) {
        return reject(err);
      }
    }

    // If stdin is piped (e.g. trivy ... | node parse-sca-results.js)
    if (!process.stdin.isTTY) {
      let buffer = "";
      process.stdin.setEncoding("utf8");
      process.stdin.on("data", (chunk) => {
        buffer += chunk;
      });
      process.stdin.on("end", () => {
        if (buffer.trim()) {
          resolve(buffer);
        } else {
          reject(
            new Error(
              "Piped STDIN stream was empty. Ensure upstream command executed successfully without errors.",
            ),
          );
        }
      });
      process.stdin.on("error", (err) => reject(err));
    } else {
      fallbackFile(resolve, reject);
    }
  });
}

function fallbackFile(resolve, reject) {
  const defaultPath = path.resolve(process.cwd(), "artefacts/sca-results.json");
  if (fs.existsSync(defaultPath)) {
    try {
      resolve(fs.readFileSync(defaultPath, "utf8"));
    } catch (err) {
      reject(err);
    }
  } else {
    reject(
      new Error(
        `No piped input provided and default file not found: ${defaultPath}`,
      ),
    );
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));

  let rawData;
  try {
    rawData = await readInput(options);
  } catch (err) {
    console.error("Error reading input:", err.message);
    process.exit(1);
  }

  let jsonData;
  try {
    jsonData = JSON.parse(rawData);
  } catch (err) {
    console.error(
      "Error parsing JSON from input. The input was not valid JSON.",
    );
    // Check if rawData looks like an error message from Trivy or shell
    const trimmed = (rawData || "").trim();
    if (trimmed.length > 0) {
      console.error("Captured input preview:");
      console.error(
        trimmed.substring(0, 300) + (trimmed.length > 300 ? "..." : ""),
      );
    }

    console.error(
      "\nTip: If piping from Trivy, ensure Trivy succeeded without errors:",
    );
    console.error(
      "  trivy sbom ./artefacts/sbom-results.json --format json | node .github/skills/sca/parse-sca-results.js",
    );

    process.exit(1);
  }

  const processed = processScaResults(jsonData, options);

  const outputText = JSON.stringify(processed, null, 2);

  if (options.output) {
    const resolvedOutputPath = path.resolve(process.cwd(), options.output);
    fs.mkdirSync(path.dirname(resolvedOutputPath), { recursive: true });

    const fileData = JSON.stringify(processed, null, 2);
    fs.writeFileSync(resolvedOutputPath, fileData, "utf8");

    const bytes = Buffer.byteLength(fileData, "utf8");
    console.error(
      `Parsed SCA results written to: ${options.output} (${processed.summary.totalFindings} findings, ${(bytes / 1024).toFixed(1)} KB)`,
    );
  }

  // Handle intermediate files cleanup or retention
  const intermediateFiles = [
    "artefacts/raw-sca-results.json",
    "raw-sca-results.json",
  ];

  if (!options.keepTemp) {
    for (const relPath of intermediateFiles) {
      const absPath = path.resolve(process.cwd(), relPath);
      if (options.output && absPath === path.resolve(process.cwd(), options.output)) {
        continue;
      }
      if (fs.existsSync(absPath)) {
        try {
          fs.unlinkSync(absPath);
        } catch {
          // ignore
        }
      }
    }
  } else {
    console.error("Audit trail preserved: intermediate files retained (--keep-temp).");
  }

  if (!options.output || options.stdout) {
    process.stdout.write(outputText + "\n");
  } else {
    console.log(formatSummaryOnly(processed));
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  processScaResults,
  extractCvss,
  extractEpssAndKev,
  generateRemediation,
  formatSummaryOnly,
};
