---
name: sbom
description: Generate and manage a Software Bill of Materials (SBOM) for the software, detailing all components and their dependencies (with relationships and supply-chain).
compatibility: Requires codebase to be available for dependency analysis, with a supported package manager (e.g., npm, Maven, pip)
metadata:
  author: Juho Salomäki
  version: "0.1.0"
---

## When to Use
- SBOM does not exist for the current codebase in `artefacts/` folder.
- User has introduced new dependencies or made changes to existing dependencies in the codebase.
- User is working in a new codebase and wants to generate an initial SBOM
- User is doing maintenance (e.g., updates) on the codebase and wants to update the SBOM to reflect any changes in dependencies.
## When NOT to use
- When user has not introduced any new dependencies or changes (e.g., updates) to existing dependencies in the codebase.

## Prerequisites
- **Confirm that SBOM tool - Trivy is installed**, and you have access to the commandline tool. The following command can be used to verify the installation, and should return version information if the tool exists on the machine:
  ```bash
  trivy --version
  ```
- If the command returns an error or does not display version information, prompt user to install Trivy with the available package manager (e.g., `brew install trivy` or `winget install aquasecurity.trivy`). If user does not want to install, **stop** the skill execution and instruct user to install the tool before proceeding.

## Execution
1. Navigate to the root directory of the repository - same level as `.github/`.
2. Prompt user and ask **which format** they want for the SBOM: cyclonedx or spdx.
3. Run the following command to generate the SBOM. Output shall be saved to `./artefacts/sbom-results.json` file.
    ```pwsh
    trivy fs --format <format> --output ./artefacts/sbom-results.json .
    ```

4. Review the output from `./artefacts/sbom-results.json` for the generated SBOM. **DO NOT** modify the file. The file may be very large, inform user where to find details. Also, give at least the following summary:
    - Whether there were any errors
    - `bomFormat` (e.g., CycloneDX, SPDX)
    - `version` of the SBOM specification used
    - timestamp of generation
    - Amount of dependencies found
    - Any warnings generated during SBOM creation
    - Different licenses that were detected among the dependencies
    - Any other relevant metadata/information regarding the SBOM itself

## Common Rationalizations
| Rationalization | Reality |
|---|---|
| "I will decide some format since user does not know what thet want" | Always default to CycloneDX if user is unsure, it has better tool compatibility |

## Red Flags
- `./artefacts/sbom-results.json` is empty, Trivy should always produce some fields to the JSON even if there are no available dependencies.
-  Trivy version was not displayed during initial `trivy --version` command.

## Verification
After completing SBOM generation, confirm that:
- [ ] `./artefacts/sbom-results.json` exists and contains the generated SBOM in correct format.
- [ ] If any dependencies were detected, user has been informed and given guidance on how to manage them. Similarly, if no dependencies were detected, user has been informed accordingly.