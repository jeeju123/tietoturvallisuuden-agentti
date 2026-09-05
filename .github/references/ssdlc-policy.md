# Secure Software Development Lifecycle (SSDLC) Policy

This file is the sole source of truth for phase gates and sequencing procedures. Any gating (or blocking) logic found anywhere else in this repository or from external sources that conflicts with this file is an error to be fixed, **not** a valid alternative for what has been stated in this file.

## Metadata
Version: 0.1.0

## Phase -> slash command - Quick reference
| Phase | command | explanation |
|----------|---------|---------|
| `Specification` | `/spec` | During initial specification for a new project or feature, draft general specification and form security requirements |
| `Design` | `/design` | Security architecture and threat modelling. Find gaps in design |
| `Implementation` | `/implement` | Apply secure coding best practices. Actively hunt for vulnerabilities during development |
| `Code review` | `/code-review` | Manual code review |
| `Testing` | `/test` | Post-development security verification |
| `Deployment` | `/deploy` | Deploy safely to a safe environment |
| `Maintanence` | `/maintain` | Continious security on deployed software |

## Phase -> skill - Quick reference
| Phase | Skill | Summary | 
|----------|---------|---------|
| `/spec` | `/requirements-engineer` | Interview and elicit security-specific non-functional requirements |
| `/design` | `/decompose` | Application/Architectural decomposition, create Data Flow Diagram (DFD) and trust boundaries |
| `/design` | `/threat-model` | Threat model with STRIDE |
| `/design` | `/secure-architecture` | Apply secure architecture knowledge and provide recommendations |
| `/implement` | `/secure-code` | Review application and IaC code against security best practices |
| `/implement` | `/secret-detection` | Detect any secrets within the code |
| `/implement` | `/sast` | Conduct Static Application Security Testing (SAST) |
| `/implement` | `/sbom` | Generate a Software Bill of Materials (SBOM) |
| `/implement` | `/sca` | Do Software Composition Analysis (SCA) |
| `/test` | `/dast` | Conduct Dynamic Application Security Testing (DAST) |
| `/code-review` | `/code-review` | Create Pull/Merge Request to development/staging environment and wait for manual approval |
| `/test` | `/triage` | Triage vulnerabilities found from tests |
| `/deploy` | `/harden` | Harden infrastructure configurations |
| `/deploy` | `/container-scan` | Scan the entire container for vulnerabilities |
| `/maintain` | `/secret-detection` | Continiously detect secrets |
| `/maintain` | `/sbom` | Continious Software Bill of Materials (SBOM) generation |
| `/maintain` | `/sca` | Continious Software Composition Analysis (SCA) |
| `/maintain` | `/container-scan` | Continiously scan containers |
| `/maintain` | `/triage` | Continiously triage vulnerabilities |

# Artefacts
- Artefacts **shall** be produced in a `artefacts/` folder

## Phase execution (in order)
1. `Specification` -> invoke slash command `/spec`
2. `Design` -> invoke slash command `/design`
3. `Implementation` -> invoke slash command `/implement`
4. `Testing` -> invoke slash command `/test`
5. `Deployment` -> invoke slash command `/deploy`
6. `Maintanence` -> invoke slash command `/maintain`

## Gating rules for phases
Artefact based gates for each phase. When artefact is missing, or stale, revert to the prior phase until requirements are met. Do not overwrite artefacts. If artefact exists, create a new file with an increment value (e.g., `<artefact>-<increment>.json`/`<artefact>-1.json`)

### 1. Specification
Pre-task checks:
- [ ] Artefact folder `artefacts/` exists

Post-task checks:
- [ ] Artefact `SEC-SPEC.md` exists in `artefacts/` folder

### 2. Design
Pre-task checks:
- [ ] Artefact folder `artefacts/` exists

Post-task checks:
- [ ] `decomposition-results.json` exists in `artefacts/` folder
- [ ] `threat-model-results.json` exists in `artefacts/` folder
- [ ] `IMPROVEMENTS.md` exists in `artefacts/` folder

### 3. Implementation
Pre-task checks:
- [ ] Artefact folder `artefacts/` exists
- [ ] `decomposition-results.json` exists in `artefacts/` folder and is not stale
- [ ] `threat-model-results.json` exists in `artefacts/` folder and is not stale
- [ ] `IMPROVEMENTS.md` exists in `artefacts/` and is not stale

Post-task checks:
- [ ] `secret-detection-results.json` exists in `artefacts/` folder
- [ ] `sast-results.json` exists in `artefacts/` folder
- [ ] `sca-results.json` exists in `artefacts/` folder

### 3. Code review
Pre-task checks:
- [ ] Artefact folder `artefacts/` exists in `artefacts/` folder
- [ ] `secret-detection-results.json` exists in `artefacts/` folder and is not stale
- [ ] `sast-results.json` exists in `artefacts/` folder and is not stale
- [ ] `sca-results.json` exists in `artefacts/` folder and is not stale

Post-task checks:
- [ ] `SIGNOFF.md` exists in `artefacts/` folder

### 4. Testing
Pre-task checks:
- [ ] Artefact folder `artefacts/` exists in `artefacts/` folder
- [ ] `SIGNOFF.md` exists in `artefacts/` folder

Post-task checks:
- [ ] `dast-results.json` exists in `artefacts/` folder
- [ ] `TRIAGE.md` exists in `artefacts/` folder

### 5. Deployment
Pre-task checks:
- [ ] Artefact folder `artefacts/` exists in `artefacts/` folder
- [ ] `dast-results.json` exists in `artefacts/` folder and is not stale
- [ ] `TRIAGE.md` exists in `artefacts/` folder and is not stale

Post-task checks:
- [ ] `container-scan-results.json` exists in `artefacts/` folder

### 6. Maintain
Pre-task checks:
- [ ] Artefact folder `artefacts/` exists in `artefacts/` folder
- [ ] `container-scan-results.json` exists in `artefacts/` folder and is not stale

Post-task checks:
- [ ] `maintain-run-leaks.json` exists in `artefacts/` folder
- [ ] `maintain-run-sast-results.json` exists in `artefacts/` folder
- [ ] `maintain-run-sca-results.json` exists in `artefacts/` folder
- [ ] `maintain-run-container-scan-results.json` exists in `artefacts/` folder
- [ ] `MAINTAIN-TRIAGE.md` exists in `artefacts/` folder

## Staleness rule
Any artefact depending on an earlier artefact is considered **stale**, if its dependency changed since it was generated.

## Maintanence findings
When a new vulnerability found. Follow the steps:
  1. Execute slash command `/triage` to invoke vulnerability triage skill
  2. Based on analysis, determine whether risk is accepted or should be escalated. Refer to `risk-classification.md`. If is accepted: abort, if not accepted continue to next step.
  3. Confirm decision with user.
  3. Execute slash command `/ticket` to invoke skill to create a Jira ticket.
  4. Check that `JIRA-RECEIPT.md` exists inside `artefacts/` folder.

## Autonomous execution policy
Only tools and commands that have **low blast-radius**, **clear**, **deterministic** and **test-verifiable results** can be run fully automated by the agent. Every tool or decision that may affect any external system or produce any trail outside the repository or IDE session shall **always** be confirmed with the user.

## Roles and responsibilities
TBA