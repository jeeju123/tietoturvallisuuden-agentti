---
name: sast
description: Perform Static Application Security Testing (SAST) to identify security vulnerabilities in the source code of the software.
compatibility: Requires codebase to be available for static analysis.
metadata:
  author: Juho Salomäki
  version: "0.1.0"
---

## When to Use
- During development, after staging changes to confirm that no potential attack vectors are introduced to the codebase.
- During maintenance check, to ensure no new vulnerabilities have been introduced over time.
- User is new to the codebase/repository and no prior sast scan results exist in `artefacts/` folder.
## When NOT to use
- User has not introduced any changes to the codebase and a previous sast scan has already been performed in the `artefacts/` folder.

## Prerequisites
- **Confirm that a SAST tool - Semgrep is installed**, and you have access to the commandline tool. The following command can be used to verify the installation, and should return version information if the tool exists on the machine:
  ```bash
  semgrep --version
  ```
- If the command returns an error or does not display version information, prompt user to install the SAST tool - Semgrep (with available package manager e.g., `pip install semgrep`). If user does not want to install, **stop** the skill execution and instruct user to install semgrep before proceeding.
## General execution
When performing a typical SAST scan using Semgrep, without any pre-existing conditions (e.g., need for custom rule sets) use the following steps to execute the scan. **Note that auto --config=auto is used to automatically select the appropriate rules based on the codebase. This will result in non-deteministic and non-comparable scans. Always let user know that this is the case and results may vary. Use this only if no need for specific rule sets exist.**
1. Navigate to the root directory of the repository - same level as `.github/`.
2. Run the following commands to perform a SAST scan using Semgrep - If you are unsure whether user is new to the repository, it is recommended to run a full scan. Output shall be saved to `./artefacts/sast-results.json` file.
    - Run a scan with automatic rule selection:
      ```bash
      semgrep --config=auto --json-output=./artefacts/sast-results.json
      ```

## Special execution scenarios
When you have specific requirements or user is performing a task (e.g., audit) that requires custom rule sets with deterministic and comparable scans, use the following steps to execute the scan:
1. Prompt user for the configurations they wish to use for the custom rule set, including the path to the rule set and any additional options. For example, OWASP top ten rules exist in public Semgrep registry as `p/owasp-top-ten` config flag. Ensure user provides the correct path or identifier for the custom rule set. If user is unsure, but still is performing specialized scans, guide them to select an appropriate rule set from the Semgrep registry or choose one from public Semgrep registry (https://semgrep.dev/explore). **Always document the chosen configurations and any deviations from the default settings.** Output shall be saved to `./artefacts/sast-results.json` file.
2. Navigate to the root directory of the repository - same level as `.github/`.
3. Run the following command (or multiple commands with different custom rule sets) to perform a SAST scan using Semgrep with a custom rule set:
    ```bash
    semgrep --config=<path-to-custom-rule-set> --json-output=./artefacts/sast-results.json
    ```

## Review the scan results
After JSON output is generated in `./artefacts/sast-results.json`, review the file to check for any detected vulnerabilities/issues. **DO NOT** modify the file yet. After you have reviewed the findings, continue with the steps. **If no findings exist, inform the user accordingly.**
1. Inform the user of any detected vulnerabilities/issues, including the:
    - `check_id` field
    - `extra` fields, if available (e.g., message, owasp, technology, subcategory, cwe, likelihood, confidence, severity, reference, source, vulnerability_class)
    - `path` field indicating source location
    - If any errors are found from results, inform user.
    - Remediation steps based on the type of an issue and how to properly handle it within the context of the repository.
2. Prompt user to confirm that they have reviewed and understood the findings before proceeding with any remediation steps.
3. After user confirmation, proceed with any necessary remediation steps to address the detected vulnerabilities/issues.

## Common Rationalizations
| Rationalization | Reality |
|---|---|
| "I am unsure if I need specialized scan, I will run general scan instead" | User is always present, ask the user to confirm if they want to proceed with a general scan or select an appropriate specialized scan. |

## Red Flags
- `./artefacts/sast-results.json` is empty, Semgrep should always produce some fields to the JSON even if scan results are empty.
-  Semgrep version was not displayed during initial version check command.

## Verification
After completing sast scan execution, confirm that:
- [ ] `./artefacts/sast-results.json` exists and contains the scan results (or at least some fields).
- [ ] If any vulnerabilities/issues were detected, user has been informed and given guidance on how to remediate them. Similarly, if no vulnerabilities/issues were detected, user has been informed accordingly.