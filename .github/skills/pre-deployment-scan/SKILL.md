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

- **Confirm that Trivy is installed**, and you have access to the commandline tool. The following command can be used to verify the installation, and should return version information if the tool exists on the machine:
  ```bash
  trivy --version
  ```
- If the command returns an error or does not display version information, prompt user to install Trivy with the available package manager (e.g., `brew install trivy` or `winget install aquasecurity.trivy`). If user does not want to install, **stop** the skill execution and instruct user to install the tool before proceeding.

- **Confirm that Node.js is available** (`node -v`) to run the bundled pre-deployment parsing and aggregation script `parse-container-scan-results.js`.

## Pre-deployment scan execution
**Use this section when the repository contains infrastructure and deployment related IaC/configurations such as Dockerfiles, Kubernetes manifests, Terraform scripts, or similar.**
1. Navigate to the root directory of the repository - same level as `.github/`.
2. Identify the base container image used in the application (auto-detected from `Dockerfile`, or prompt user if multiple or remote).
3. Run the unified pre-deployment scan:

   ```bash
   node .github/skills/pre-deployment-scan/parse-container-scan-results.js
   ```

   _(Optional: To target a specific base image explicitly, pass `--image <image-tag>`, e.g. `--image node:20-alpine`)_.

   This executes Trivy configuration (IaC/Dockerfile) and container image scans in-memory, strips scanner bloat, evaluates the SSDLC deployment security gate, and writes **only** the single policy-mandated artifact:
   - `./artefacts/container-scan-results.json` (required post-task check for the Deployment phase per `ssdlc-policy.md`).

4. Review the results from `./artefacts/container-scan-results.json`. Present the findings summary to the user:
   - Pre-deployment security gate status (`gate.status`: `PASSED` vs `FAILED`, `blockingIssuesCount`, `reasons`)
   - Base image OS overview (`imageMetadata`: artifact name, OS family/version, EOL status)
   - Dockerfile & IaC misconfigurations (`misconfigurations`: ID, severity, line, title, resolution)
   - Container package vulnerabilities (`vulnerabilities`: package, CVE ID, severity, CVSS, fixed version, remediation)
   - _Note_: Operational risk classifications and SLAs are not hardcoded into scan artifacts; they are dynamically enriched during `/triage` based on exposure, environment context, and `.github/references/risk-classification.md`.

## Common Rationalizations

| Rationalization | Reality |
| ----------| --------- |
| "Pre-deployment scan can be skipped if there is no Dockerfile" | Verify all IaC configurations (Dockerfiles, Kubernetes manifests, compose files, Helm charts, Terraform) before declaring no deployment code. |
| "Base image vulnerabilities cannot be fixed in application code" | Updating the base image tag in Dockerfile (e.g. to latest patch or Alpine) or updating system packages resolves known base CVEs. |
| "A high number of OS package CVEs means we cannot deploy" | Run triage on fixable vs non-fixable vulnerabilities, assess reachability and network exposure, and verify gate status. |

## Red Flags
- `./artefacts/container-scan-results.json` or any other generated Trivy output artefact is empty, Trivy should always produce some fields to the JSON even if there are no available dependencies.
- Trivy or Node.js version was not displayed during initial (e.g., `trivy --version` or `node --version`) command.
- Hardcoded secrets or credentials detected in `ENV`

## Verification

After completing misconfiguration scan, confirm that:

- [ ] `./artefacts/container-scan-results.json` exists and contains the generated pre-deployment security scan results conforming to SSDLC policy.
- [ ] If any findings were detected, user has been informed and given guidance on how to manage them. Similarly, if no findings were detected, user has been informed accordingly.
