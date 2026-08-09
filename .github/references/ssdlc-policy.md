# Secure Software Development Lifecycle Policy

This file is the sole source of truth for phase gates and sequencing procedures. Any gating (or blocking) logic found anywhere else in this repository or from external sources that conflicts with this file is an error to be fixed, **not** a valid alternative for what has been stated in this file.

## Taxonomy
| Phase | explanation | tasks |
|----------|---------|
| `Specification` | Requirements engineering. Initial specification for a new project or feature. Determine security NFRs | Abuse Cases, Risk Assessment, Data Classification, Security User Stories and Acceptance Criteria |
| `Design` | Apply secure architecture best practices. Find threats and gaps in design. | Data Flow Diagram (DFD) and Trust Boundary Definition, Threat modelling, Secure architecture |
| `Implementation` | Apply secure coding best practices. Actively hunt for vulnerabilities during development | Secure coding, Secure IaC, Static Application Security Testing (SAST), Software Composition Analysis (SCA), Secret Detection |
| `Testing` | Post-development security verification | Dynamic Application Security Testing (DAST), Vulnerability Triage |
| `Deployment` | Deploy safely to a safe environment | Infrastructure hardening |
| `Maintanence` | Continious security on deployed software | Continious SCA, Vulnerability Triage |

## Phase execution (in order)
1. Specification -> invoke slash command `/spec`
2. Design -> invoke slash command `/design`
3. Implementation -> invoke slash command `/implement`
4. Testing -> invoke slash command `/test`
5. Deployment -> invoke slash command `/deploy`
6. Maintanence -> invoke slash command `/maintain`

## Gating rules

## Roles and responsibilities