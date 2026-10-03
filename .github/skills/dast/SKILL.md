---
name: dast
description: Perform Dynamic Application Security Testing (DAST) within the SSDLC agent, identifying security vulnerabilities in running applications through automated scanning and analysis.
metadata:
  author: Juho Salomäki
  version: "0.1.0"
---

## When to Use
- Remotely after application is deployed, to ensure that no new vulnerabilities have been introduced in the running application.
- During maintenance check, to ensure no new vulnerabilities have been introduced over time.
- User is new to the codebase/repository and no prior DAST scan results exist in `artefacts/` folder.

## When NOT to use
- User has not introduced any changes to the codebase and a previous DAST scan has already been performed in the `artefacts/` folder.

## Prerequisites
- **Confirm that Docker is installed**, and you have access to the commandline tool. The following command can be used to verify the installation, and should return version information if the tool exists on the machine:
  ```bash
  docker --version
  ```
- If the command returns an error or does not display version information, prompt user to install Docker. If user does not want to install, **stop** the skill execution and instruct user to install Docker before proceeding. The DAST tool OWASP ZAP is run via Docker container.
- **Confirm that Node.js is available** (`node -v`) to run the bundled DAST parsing script `parse-zap-results.js`.

## General execution
When performing a typical DAST scan using OWASP ZAP, without any pre-existing conditions (e.g., need for custom rule sets) use the following steps to execute the scan.

**CRITICAL AGENT RULES:**
- **ONLY execute the DAST scan via the helper script**: `./.github/skills/dast/owasp-zap-scan.sh <target_url>` (or `bash ./.github/skills/dast/owasp-zap-scan.sh <target_url>`).
- **NEVER invoke `docker run` or similar commands directly from the terminal**. The helper script encapsulates target URL validation, scheme verification, allowed host whitelisting, ZAP exit code handling, automatic cleanup of intermediate files (`raw-dast-report.json`, `zap.yaml`), and token-optimized parsing.
- **WAIT PATIENTLY FOR SCAN COMPLETION**: ZAP crawls, spiders, and passively tests endpoints inside a Docker container. This scan typically takes 1 to 3 minutes. The agent **MUST** wait synchronously for the script execution to complete and **MUST NOT** cancel, interrupt, or poll prematurely.
- **ASK FOR CONFIRMATION BEFORE SCAN**: Always confirm with the user that the target URL is correct and that they are ready to proceed with the scan.

1. Navigate to the root directory of the repository - same level as `.github/`.
2. Ask the user for the target URL to scan. **DO NOT proceed without a valid URL or invent any URLs.** Confirm the host is whitelisted (`localhost`, `127.0.0.1`, or `host.docker.internal`).
3. Run the scan using the bundled scan helper script, which executes OWASP ZAP baseline scan, cleans up intermediate files, and automatically parses findings into `./artefacts/dast-results.json`:
   ```bash
   ./.github/skills/dast/owasp-zap-scan.sh <target_url>
   ```
   _Note: Wait synchronously for the script to finish (typically 1–3 minutes). Do NOT interrupt._

## Review the scan results
After JSON output is generated in `./artefacts/dast-results.json`, review the file to check for any detected vulnerabilities/issues. **DO NOT** modify the file yet. After you have reviewed the findings, continue with the steps. **If no findings exist, inform the user accordingly.**

1. Inform the user of any detected vulnerabilities/issues, including the:
   - Alert name (`name`) and plugin ID / alert reference (`pluginId`, `alertRef`)
   - Severity (`severity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`)
   - Risk classification per `references/risk-classification.md` (`riskClassification`: `Elevated`, `Moderate`, `Minor`, `Informational`)
   - Normalized CVSS score and range (`cvss.score`, `cvss.range`)
   - Confidence level (`confidence`)
   - CWE (`cwe.id`, `cwe.url`) and WASC (`wasc.id`), if available
   - Total detected occurrences (`totalInstances`) and affected URLs (`affectedUrls`)
   - Sample representative evidence/parameters (`instances`)
   - Actionable remediation solution (`remediation` / `solution`)
   - _Note_: Operational SLAs are not hardcoded into scan artifacts; they are dynamically enriched during `/triage` based on exposure, environment context, and `.github/references/risk-classification.md`.
2. Prompt user to confirm that they have reviewed and understood the findings before proceeding with any remediation steps.
3. After user confirmation, proceed with any necessary remediation steps to address the detected vulnerabilities/issues (or escalate to `/triage` skill).

## Common Rationalizations

| Rationalization | Reality |
| ---------- | ------------ |
| "I will invoke docker run directly instead of running the script" | Always run `./.github/skills/dast/owasp-zap-scan.sh`. Calling docker directly bypasses URL scheme validation, target whitelisting, ZAP exit code handling, cleanup of intermediate files (`zap.yaml`, `raw-dast-report.json`), and automatic token-optimized JSON parsing. |
| "The scan is taking too long so I will cancel, poll, or timeout" | ZAP baseline scan needs 1 to 3 minutes to spider and passively test all endpoints. Wait synchronously for the script to finish. |
| "DAST is unnecessary because SAST found no issues" | SAST inspects static source code; DAST tests live HTTP responses, runtime headers, cookies, and network boundaries that static analysis cannot observe. |
| "I will read the raw baseline-report.json directly" | Raw reports are large lines with massive instance duplication and raw HTML tags. Always use `parse-zap-results.js` to save tokens. |
| "I can scan any target URL" | DAST is intrusive; only scan verified whitelisted local/test hosts (`localhost`, `127.0.0.1`, `host.docker.internal`). |

## Red Flags
- Calling `docker` commands directly from the terminal instead of executing `./.github/skills/dast/owasp-zap-scan.sh`.
- Terminating, killing, or polling the scan before the 1-3 minute execution completes.
- Leaving intermediate files (`raw-dast-report.json`, `zap.yaml`) in `artefacts/` folder.
- `./artefacts/dast-results.json` is empty, OWASP ZAP should always produce some fields to the JSON even if scan results are empty.
- Docker or Node.js is not installed or not functioning correctly.
- Target application was not running, resulting in connection failure or 0 endpoints scanned.

## Verification
After completing dast scan execution, confirm that:
- [ ] `./artefacts/dast-results.json` exists in `artefacts/` folder and contains the parsed DAST scan results conforming to SSDLC policy.
- [ ] If any vulnerabilities/issues were detected, user has been informed and given guidance on how to remediate them. Similarly, if no vulnerabilities/issues were detected, user has been informed accordingly.
