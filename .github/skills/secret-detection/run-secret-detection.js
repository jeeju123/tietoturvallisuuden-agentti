#!/usr/bin/env node

/**
 * run-secret-detection.js
 *
 * Bundled helper script for the `secret-detection` skill (.github/skills/secret-detection/).
 * Runs Gitleaks across git history, staged changes, and working directory (or parses existing report files),
 * deduplicates findings, extracts only necessary fields per SSDLC guidelines and SKILL.md,
 * safely cleans up temporary intermediate files, and writes structured JSON to artefacts/secret-detection-results.json.
 *
 * Usage:
 *   node .github/skills/secret-detection/run-secret-detection.js [options]
 *
 * Options:
 *   --mode <all|history|staged|dir>  Scan mode (default: all)
 *   --output <path>                  Output file (default: artefacts/secret-detection-results.json)
 *   --parse-only                     Only parse and combine existing intermediate files, do not run gitleaks
 *   --keep-temp                      Do not delete intermediate temp files
 *   --redact                         Redact matched secret strings (default: true)
 *   --summary                        Print concise summary to stdout
 *   -h, --help                       Show help message
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

function parseArgs(args) {
  const options = {
    mode: 'all',
    output: 'artefacts/secret-detection-results.json',
    parseOnly: false,
    keepTemp: false,
    redact: true,
    summary: false
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '-h' || arg === '--help') {
      printHelp();
      process.exit(0);
    } else if (arg === '--mode') {
      options.mode = args[++i]?.toLowerCase() || 'all';
    } else if (arg === '-o' || arg === '--output') {
      options.output = args[++i];
    } else if (arg === '--parse-only') {
      options.parseOnly = true;
    } else if (arg === '--keep-temp') {
      options.keepTemp = true;
    } else if (arg === '--no-redact') {
      options.redact = false;
    } else if (arg === '--summary') {
      options.summary = true;
    }
  }

  return options;
}

function printHelp() {
  console.log(`
    run-secret-detection.js: Execute Gitleaks & aggregate structured secret detection findings

    Usage:
      node .github/skills/secret-detection/run-secret-detection.js [options]

    Options:
      --mode <all|history|staged|dir>  Scan mode: history, staged, dir, or all (default: all)
      -o, --output <file>              Output path (default: artefacts/secret-detection-results.json)
      --parse-only                     Only combine/clean existing temp files without running gitleaks
      --keep-temp                      Keep intermediate files (history-results.json, etc.)
      --summary                        Print concise text summary to stdout
      -h, --help                       Show this help message
`);
}

function hasStagedChanges() {
  try {
    const gitDiff = spawnSync('git', ['diff', '--cached', '--quiet'], {
      encoding: 'utf8',
      windowsHide: true
    });
    // Exit code 1 means staged differences exist; 0 means nothing is staged
    return gitDiff.status === 1;
  } catch {
    return true; // Fallback to running gitleaks protect if git check fails
  }
}

function runGitleaksCommand(args) {
  try {
    const result = spawnSync('gitleaks', args, {
      encoding: 'utf8',
      windowsHide: true
    });

    if (result.error) {
      if (result.error.code === 'ENOENT') {
        console.error("Error: 'gitleaks' executable not found in PATH.");
        console.error("Please ensure Gitleaks is installed (e.g. winget install gitleaks or brew install gitleaks) per prerequisites in SKILL.md.");
        process.exit(1);
      }
      throw result.error;
    }

    // Gitleaks exit codes: 0 = no leaks, 1 = leaks found, >1 = runtime error
    if (result.status > 1) {
      console.error(`Gitleaks execution warning/error (code ${result.status}):`, (result.stderr || result.stdout || '').trim());
    }

    return result;
  } catch (err) {
    console.error("Fatal error invoking Gitleaks:", err.message);

    process.exit(1);
  }
}

function cleanFinding(finding, source) {
  return {
    ruleId: finding.RuleID || finding.ruleId || 'unknown',
    description: (finding.Description || finding.description || '').trim(),
    file: finding.File || finding.file || 'unknown',
    startLine: finding.StartLine ?? finding.startLine ?? null,
    endLine: finding.EndLine ?? finding.endLine ?? null,
    fingerprint: finding.Fingerprint || finding.fingerprint || '',
    commit: (finding.Commit || finding.commit || '') || null,
    date: (finding.Date || finding.date || '') || null,
    author: (finding.Author || finding.author || '') || null,
    scanSource: source // 'history', 'staged', or 'dir'
  };
}

function loadAndParseJsonFile(filePath) {
  if (!fs.existsSync(filePath)) {
    return [];
  }

  try {
    const raw = fs.readFileSync(filePath, 'utf8').trim();
    if (!raw || raw === '[]' || raw === 'null') {
      return [];
    }

    const parsed = JSON.parse(raw);

    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.warn(`Warning: Could not parse ${filePath}:`, err.message);

    return [];
  }
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const cwd = process.cwd();
  const artefactsDir = path.resolve(cwd, 'artefacts');

  if (!fs.existsSync(artefactsDir)) {
    fs.mkdirSync(artefactsDir, { recursive: true });
  }

  const tempFiles = [
    { key: 'history', path: path.resolve(artefactsDir, 'history-results.json') },
    { key: 'staged', path: path.resolve(artefactsDir, 'staged-results.json') },
    { key: 'dir', path: path.resolve(artefactsDir, 'dir-results.json') }
  ];

  if (!options.parseOnly) {
    const redactFlag = options.redact ? ['--redact'] : [];

    if (options.mode === 'all' || options.mode === 'history') {
      const historyFile = tempFiles.find(f => f.key === 'history').path;

      runGitleaksCommand(['git', '-v', '--report-format=json', `--report-path=${historyFile}`, ...redactFlag]);
    }

    if (options.mode === 'all' || options.mode === 'staged') {
      const stagedFile = tempFiles.find(f => f.key === 'staged').path;
      if (hasStagedChanges()) {
        runGitleaksCommand(['protect', '-v', '--staged', '--report-format=json', `--report-path=${stagedFile}`, ...redactFlag]);
      } else {
        fs.writeFileSync(stagedFile, '[]', 'utf8');
      }
    }

    if (options.mode === 'all' || options.mode === 'dir') {
      const dirFile = tempFiles.find(f => f.key === 'dir').path;

      runGitleaksCommand(['dir', '-v', '--report-format=json', `--report-path=${dirFile}`, '.', ...redactFlag]);
    }
  }

  // Combine and deduplicate findings across runs
  const combinedFindings = [];
  const seenFingerprints = new Set();
  const summaryByRule = {};

  for (const { key, path: filePath } of tempFiles) {
    const findings = loadAndParseJsonFile(filePath);
    for (const f of findings) {
      const cleaned = cleanFinding(f, key);
      const uniqueKey = cleaned.fingerprint || `${cleaned.file}:${cleaned.ruleId}:${cleaned.startLine}`;

      if (!seenFingerprints.has(uniqueKey)) {
        seenFingerprints.add(uniqueKey);
        combinedFindings.push(cleaned);
        summaryByRule[cleaned.ruleId] = (summaryByRule[cleaned.ruleId] || 0) + 1;
      }
    }
  }

  // Write standardized output file
  const resolvedOutputPath = path.resolve(cwd, options.output);
  fs.mkdirSync(path.dirname(resolvedOutputPath), { recursive: true });
  fs.writeFileSync(resolvedOutputPath, JSON.stringify(combinedFindings, null, 2), 'utf8');

  // Clean up temporary files unless --keep-temp was specified
  if (!options.keepTemp) {
    for (const { path: filePath } of tempFiles) {
      if (fs.existsSync(filePath)) {
        try {
          fs.unlinkSync(filePath);
        } catch (err) {
          console.warn(`Could not remove temp file ${filePath}:`, err.message);
        }
      }
    }
  }

  // Command's console output
  if (combinedFindings.length === 0) {
    console.log(`Secret scan complete: No secrets detected. Written to ${options.output}`);
  } else {
    console.log(`ERROR:Secret scan complete: ${combinedFindings.length} secret(s) detected`);
    console.log(`Findings written to: ${options.output}`);
    console.log('Detected rules:');

    for (const [rule, count] of Object.entries(summaryByRule)) {
      console.log(`  - ${rule}: ${count}`);
    }
  }
}

main();
