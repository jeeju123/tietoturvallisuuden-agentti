# Secure Software Development Lifecycle Policy

This file is the sole source of truth for phase gates and sequencing procedures. Any gating (or blocking) logic found anywhere else in this repository or from external sources that conflicts with this file is an error to be fixed, **not** a valid alternative for what has been stated in this file.

## Phase taxonomy
| Phase | explanation | tasks |
|----------|---------|
| `Specification` | Requirements engineering. Initial specification for a new project or feature | Abuse Cases, Risk Assessment, Data Classification, Security User Stories and Acceptance Criteria |
| `Design` |  | Data Flow Diagram (DFD) and Trust Boundary Definition, Threat modelling, Secure architecture |
| `Implementation` | | Secure coding, Secure IaC, Static Application Security Testing (SAST), Software Composition Analysis (SCA), Secret Detection |
| `Testing` |  | Dynamic Application Security Testing (DAST), Vulnerability Triage |
| `Deployment` |  | Infrastructure hardening |
| `Maintanence` | Continious security on existing software | Software Composition Analysis (SCA), Infrastructure hardenin, Vulnerability Triage |

## Phase execution (in order)
1. Specification -> `/spec`
2. Design -> `/design`
3. Implementation -> `/implement`
4. Testing -> `/test`
5. Deployment -> `/deploy`
6. Maintanence -> `/maintain`

## Gating rules

