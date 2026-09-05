---
name: sca
description: Perform a Software Composition Analysis (SCA) to identify and manage open source components and their associated security vulnerabilities.
compatibility: Requires Software Bill of Materials (SBOM) to be available for dependency analysis (e.g., CycloneDX, SPDX)
metadata:
  author: Juho Salomäki
  version: "0.1.0"
---

## When to Use
- User has introduced new dependencies or made changes and/or updates to existing dependencies in the codebase.
- User is working in a new codebase and wants to see vulnerabilities in the dependencies.
- User is doing maintenance on the codebase and wants to check for new vulnerabilities in the dependencies.
## When NOT to use
- SBOM `sbom-results.json` does not exist for the current codebase in `artefacts/` folder. Though possible to scan without, SBOM should be generated first for accurate and deterministic analysis. Invoke `/sbom` skill to generate it before proceeding with SCA.

## Prerequisites
- **Confirm that SCA tool - Trivy is installed**, and you have access to the commandline tool. The following command can be used to verify the installation, and should return version information if the tool exists on the machine:
  ```bash
  trivy --version
  ```
- If the command returns an error or does not display version information, prompt user to install Trivy with the available package manager (e.g., `brew install trivy` or `winget install aquasecurity.trivy`). If user does not want to install, **stop** the skill execution and instruct user to install the tool before proceeding.

## Execution
1. Navigate to the root directory of the repository - same level as `.github/`.
2. Ensure that SBOM `sbom-results.json` exists in `./artefacts/` folder. If not, invoke `/sbom` skill to generate it first. Make sure the SBOM is up-to-date with the latest dependencies before running SCA.
3. Run the following command to perform SCA using the existing SBOM. Output shall be saved to `./artefacts/sca-results.json` file.
    ```bash
    trivy sbom ./artefacts/sbom-results.json --format json --output ./artefacts/sca-results.json
    ```
4. Review the output from `./artefacts/sca-results.json` for the generated SCA results. **DO NOT** modify the file. Generate summary and give the following summary for each vulnerability finding:
    - Library name
    - Vulnerability ID (e.g., CVE)
    - Severity of the vulnerability
    - Risk classification per `references/risk-classification.md`
    - Status of the vulnerability (e.g., open, fixed)
    - Installed version and fixed version
    - Description (i.e. `Title`) of the vulnerability
    - How to remediate the issue
5. Prompt user whether they want to continue with remediation based on the findings. If user chooses to proceed, remediate each issue accordingly.

## Common Rationalizations
| Rationalization | Reality |
|---|---|
| "I will run filesystem SCA scan since no SBOM is available" | Always invoke the SBOM skill first to generate the SBOM before running SCA |
| "I found SBOM and will use it" | Always check if the SBOM is up-to-date and valid before running SCA |

## Red Flags
- `./artefacts/sca-results.json` is empty, Trivy should always produce some output even if there are no available vulnerabilities.
-  Trivy version was not displayed during initial `trivy --version` command.

## Verification
- After completing SCA, confirm that:
- [ ] `./artefacts/sca-results.json` exists and contains the generated SCA results.
- [ ] If any results were detected, user has been informed and given guidance on how to manage them. Similarly, if no results were detected, user has been informed accordingly.