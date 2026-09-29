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
- **Confirm that docker is installed**, and you have access to the commandline tool. The following command can be used to verify the installation, and should return version information if the tool exists on the machine:
  ```bash
-  docker --version
-  ```
- If the command returns an error or does not display version information, prompt user to install Docker. If user does not want to install, **stop** the skill execution and instruct user to install Docker before proceeding. The DAST tool OWASP ZAP is run via Docker container.

## General execution
When performing a typical DAST scan using OWASP ZAP, without any pre-existing conditions (e.g., need for custom rule sets) use the following steps to execute the scan.
1. Navigate to the root directory of the repository - same level as `.github/`.
2. Ask the user for the target URL to scan. **DO NOT proceed without a valid URL or invent any URLs.**
3. Run the following commands to perform a DAST scan using OWASP ZAP. Output shall be saved to `./artefacts/dast-results.json` file.
    - Run a scan with OWASP ZAP
      ```bash
      ./owasp-zap-scan.sh <target_url>
      ```

## Review the scan results
After JSON output is generated in `./artefacts/dast-results.json`, review the file to check for any detected vulnerabilities/issues. **DO NOT** modify the file yet. After you have reviewed the findings, continue with the steps. **If no findings exist, inform the user accordingly.**
1. Inform the user of any detected vulnerabilities/issues, including the:
    - 
2. Prompt user to confirm that they have reviewed and understood the findings before proceeding with any remediation steps.
3. After user confirmation, proceed with any necessary remediation steps to address the detected vulnerabilities/issues.

## Common Rationalizations
| Rationalization | Reality |
|---|---|
| "" |  |

## Red Flags
- `./artefacts/dast-results.json` is empty, OWASP ZAP should always produce some fields to the JSON even if scan results are empty.
- Docker is not installed or not functioning correctly, which is required to run OWASP ZAP.

## Verification
After completing dast scan execution, confirm that:
- [ ] `./artefacts/dast-results.json` exists and contains the dast scan results (or at least some fields).
- [ ] If any vulnerabilities/issues were detected, user has been informed and given guidance on how to remediate them. Similarly, if no vulnerabilities/issues were detected, user has been informed accordingly.