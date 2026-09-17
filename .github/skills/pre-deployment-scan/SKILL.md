---
name: pre-deployment-scan
description: Perform pre-deployment security scans within the SSDLC agent, involving tasks such as container misconfiguration detection, base image vulnerability scan, IaC scan.
metadata:
  author: Juho Salomäki
  version: "0.1.0"
---

## When to Use
- User has infrastructure, and deployment related code/configurations within the repository
## When NOT to use
- User has local development environment only and does not have infrastructure or deployment related code/configurations within the repository
- User is building a script as a standalone utility and not as part of a larger infrastructure or deployment setup

## Prerequisites
- **Confirm that SBOM tool - Trivy is installed**, and you have access to the commandline tool. The following command can be used to verify the installation, and should return version information if the tool exists on the machine:
  ```bash
  trivy --version
  ```
- If the command returns an error or does not display version information, prompt user to install Trivy with the available package manager (e.g., `brew install trivy` or `winget install aquasecurity.trivy`). If user does not want to install, **stop** the skill execution and instruct user to install the tool before proceeding.

- **Confirm that Node.js is available** (`node -v`) to run the bundled pre-deployment parsing and aggregation script `parse-container-scan-results.js`.

## Configuration scan execution
**Use this section when the repository contains infrastructure and deployment related IaC/configurations such as Dockerfiles, Kubernetes manifests, Terraform scripts, or similar.**
1. Navigate to the root directory of the repository - same level as `.github/`.
2. Run the following command to scan for misconfigurations. Output is saved to `./artefacts/misconfig-results.json` and parsed into clean findings:
    - **Recommended workflow (direct pipe & parse)**:
      ```pwsh
      trivy config --format json . | node .github/skills/pre-deployment-scan/parse-container-scan-results.js --type misconfig -o ./artefacts/misconfig-results.json
      ```
    - **Two-step workflow**:
      ```pwsh
      trivy config --format json --output ./artefacts/misconfig-results.json .
      node .github/skills/pre-deployment-scan/parse-container-scan-results.js --in-place
      ```


## Container scan (local/remote image)
**Use this section when the repository contains infrastructure and deployment related IaC/configurations such as Dockerfiles, Kubernetes manifests, Terraform scripts, or similar.**
1. Navigate to the root directory of the repository - same level as `.github/`.
2. Run the following command to scan for container vulnerabilities. Output shall be saved to `./artefacts/container-scan-base-results.json` file. Replace `<local-image>` with the actual local/remote image reference that was found to be used as base (e.g., `node:20-alpine`).
    - **Recommended workflow (direct pipe & parse)**:
      ```pwsh
      trivy image --format json <local-image> | node .github/skills/pre-deployment-scan/parse-container-scan-results.js --type container -o ./artefacts/container-scan-base-results.json
      ```
    - **Two-step workflow**:
      ```pwsh
      trivy image --format json --output ./artefacts/container-scan-base-results.json <local-image>
      node .github/skills/pre-deployment-scan/parse-container-scan-results.js --in-place
      ```

## Unified Consolidation (Single Report)
To combine both misconfigurations and container CVEs into a single canonical file with SSDLC risk classifications and security gate evaluation:
```pwsh
node .github/skills/pre-deployment-scan/parse-container-scan-results.js
```
This generates `./artefacts/container-security-report.json` containing:
- Pre-deployment security gate status (`PASSED` vs `FAILED`)
- Base image OS end-of-life detection
- Combined severity and risk classification metrics
- Clean, actionable list of misconfigurations with line numbers and snippets
- Deduplicated list of container vulnerabilities with available fixed versions and remediations

## Common Rationalizations
| Rationalization | Reality |
|---|---|
| "" |  |

## Red Flags
- `./artefacts/container-security-report.json` or any other generated Trivy output artefact is empty, Trivy should always produce some fields to the JSON even if there are no available dependencies.
- Trivy or Node.js version was not displayed during initial (e.g., `trivy --version` or `node --version`) command.

## Verification
After completing misconfiguration scan, confirm that:
- [ ] `./artefacts/container-security-report.json` exists and contains the generated pre-deployment security scan results in correct format.
- [ ] If any findings were detected, user has been informed and given guidance on how to manage them. Similarly, if no findings were detected, user has been informed accordingly.