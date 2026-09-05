---
name: secret-detection
description: Do a secret detection scan using gitleaks to identify any sensitive information (e.g, secrets, API keys, tokens) that may have been hardcoded locally, staged, or committed to the repository.
compatibility: Requires Gitleaks <= 8.30.0, Designed for Git repositories
metadata:
  author: Juho Salomäki
  version: "0.1.0"
---

## When to Use
- User is unfamiliar with the repository and no prior secret detection scan results exist in the `artefacts/` folder.
- User wants to ensure their code is secure, and thus no secrets are to be committed.
- When new modifications (e.g., features, bug fixes) are made (e.g., code, configuration files), to ensure no accidental secret commits will be made
- During maintenance check, to ensure no secrets have been accidentally committed over time.
## When NOT to use
- One-line changes (**However, minor edits and few lines of code must be scanned**)
- When user is highly confident that no secrets are present and a prior secret detection scan has already been performed in the `artefacts/` folder.

## Prerequisites
- **Confirm that gitleaks is installed**, and you have access to the commandline tool. The following command can be used to verify the installation, and should return version information if gitleaks exists on the machine:
  ```bash
  gitleaks version
  ```
- If the command returns an error or does not display version information, prompt user to install the secret detection tool - Gitleaks (with available package manager e.g., `brew install gitleaks` or `winget install gitleaks`). If user does not want to install, **stop** the skill execution and instruct user to install gitleaks before proceeding.

## Execution
1. Navigate to the root directory of the repository - same level as `.github/`.
2. Run the following commands to scan for secrets - If you are unsure whether user is new to the repository, it is recommended to run a full scan. Output shall be saved to `./artefacts/secret-detection-results.json` file.
    - **If user is new to the repository**, then run a full scan to detect secrets within the entire repository's git history:
      ```bash
      gitleaks git -v --report-format=json --report-path  ./artefacts/secret-detection-results.json --redact
      ```
    - **If user has staged changes**, then run a scan to detect secrets within the staged changes:
      ```bash
      gitleaks protect -v --staged --report-format=json --report-path  ./artefacts/secret-detection-results.json --redact
      ```
    - **If user has unstaged changes/local modifications**, then run a scan to detect secrets within the local working directory changes:
      ```bash
      gitleaks dir --report-format=json --report-path  ./artefacts/secret-detection-results.json --redact .
      ```
3. Review the output from `./artefacts/secret-detection-results.json` for any detected secrets. **DO NOT** read the secrets, or modify the files. User must manually verify and remediate the findings, and let user know if any secrets were found. You should always report to user:
    - `RuleID` field
    - Description
    - Where the secret can be found (e.g., file name/path, line number)
    - Fingerprint
    - Commit hash, if available
    - Date, if available
    - Author, if available
    - Remediation steps based on the type of an secret and how to properly handle secrets with the context of the repository.
    - Any other information you deem relevant for the user to know regarding the detected secret.

## Common Rationalizations
| Rationalization | Reality |
|---|---|
| "I don't need to run any scans since there are no changes" | Always prefer running a scan to ensure no secrets are accidentally committed, even if there are no apparent changes. |
| "User wants to make a commit, I only need to scan staged files" | Scanning only staged changes might miss secrets in working directory, that user may neglect later on if not addressed. Always prefer scanning working directory and staged changes. |
## Red Flags
- `./artefacts/secret-detection-results.json` is empty, there should at least be `[]` within the file, indicating that no secrets were detected.
-  Gitleaks version was not displayed during initial `gitleaks version` command.

## Verification
After completing secret detection, confirm that:
- [ ] `./artefacts/secret-detection-results.json` exists and contains the scan results (or at least `[]`).
- [ ] If any secrets were detected, user has been informed and given guidance on how to remediate them. Similarly, if no secrets were detected, user has been informed accordingly.