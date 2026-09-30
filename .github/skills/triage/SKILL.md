---
name: triage
description: Vulnerability triage and prioritization within the SSDLC agent, ensuring that identified security issues are assessed, categorized, and addressed based on their severity and impact.
metadata:
  author: Juho Salomäki
  version: "0.1.0"
---

## When to Use
  - After automated security scans have been made with results which output can be reviewed
  - User is confused and needs guidance on prioritizing security issues
## When NOT to use
  - No security issues have been identified or tool output is available

## Instructions to follow during development and review
  - **Asset severity based on asset visibility**: Downgrade findings criticality if internal-only asset, non-production, air-gapped, or otherwise limited in exposure. With the exception of `data-classification.md` reference highly ranked assets should still be treated with appropriate severity.

## Gather Findings
During the gathering phase, collect all potential security findings from automated scans, code reviews, and other sources. Ensure that each finding is documented with sufficient detail to facilitate accurate triage and prioritization. **Only include findings found from `artefacts/` folder, unless user explicitly gives additional output (e.g., from manual testing or external reports).** Look for sources such as
  - Automated security scan reports (e.g., SCA, SAST, DAST)
  - Documented findings from code reviews
  - Findings from STRIDE threat modeling
  - Documented architectural flaws


## De-duplication and findings correlation
After gathering all potential security findings from various sources, correlate findigs to identify duplicated. Duplicates across sources can give higher confidence in the validity of the finding, but should not be blindly trusted. **Note that the tools may be pointing to the same finding but with different representations or levels of detail.** Do the following steps:
  1. Identify findings that appear multiple times across different sources.
  2. Compare the details of each finding to determine if they refer to the same underlying issue.
  3. Merge duplicate findings into a single entry, consolidating all relevant information. **You should also leave trail from the sources for each merged finding.**
  4. Maintain a record of the original sources for traceability and verification purposes.


## Triage
After de-duplication, with a consolidated list of findings, do the following steps for triage and look for real-world exploitable issues and false positives.

### Scope filtering
Filter out findings that exist outside of the production build, are solely related to development and testing, or otherwise redundant to include. Look for:
- Look for **dependency context**, especially for SCA findings
 - test scripts and configurations, build tools (e.g., webpack, gulp), local or development dependencies (e.g., devDependencies in package.json), linters
- Look for **code context**, especially for SAST findings
  - test fixtures (e.g., mock data, sample inputs, /tests), auto generated code paths, and non-production code sections

### Reachability analysis
Assess whether the vulnerable code or configuration is actually called by code (e.g., public API). Steps to perform reachability analysis include for each vulnerable method:
  1. Look at architectural decomposition results, if available, and perform analysis to look at DFD for data flow and interaction paths to get theoretical understanding.
  2. Trace the actual code paths
    - Run `grep` or similar code search tools to trace any imports of the vulnerable code or configuration throughout the codebase.
    - If no references are found, mark as unreachable.
    - If references are found, search for functions or methods that call the vulnerable code.
    - Continue tracing the call hierarchy until reaching entry points such as public APIs or user-facing functions.

### Network exposure analysis
Assess whether the finding is exposed to the network and could be exploited remotely.
  - Query deployment IaC or manifests to determine if the vulnerable code or configuration is exposed to the network or internal-only.
  - Check firewall rules, security groups, and network policies to verify if the vulnerable code or configuration is accessible from external networks.
  - Consider using network scanning tools to validate the actual exposure of the vulnerable code or configuration.

## Prioritization and results
After completing the triage steps, prioritize the findings based on the `risk-classification.md` reference file and output the results accordingly to `triage-results.md`.


## Common Rationalizations
| Rationalization | Reality |
|---|---|
| "I will downgrade this finding since it is not exploitable in our context" | Make sure that the asset does not introduce any indirect risks or dependencies that could still be exploited via the supply-chain. |

## Red Flags
- Finding is mentioned, that upon second look, does not exist.


## Verification
After completing the secure code review, confirm that:
  - [ ] `triage-results.md` has been created in `artefacts/` and contains the prioritized findings.
  