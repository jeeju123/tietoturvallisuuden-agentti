# Compliance mapping

Quick reference for approved and preferred open-source security guidelines/frameworks with examples of use-cases and when to use.

## Metadata
Version 0.1.0

## Phase -> practical guideline
| Phase | Command | Guideline(s) |
|----------|---------|---------|
| `Specification` | `/spec` | NIST SSDF, OWASP SAMM, Microsoft SDL, Potential local compliance (e.g., EU GDPR) |
| `Design` | `/design` | OWASP ASVS, Cloud provider's well-architected frameworks and security best practices (e.g., AWS, Azure) |
| `Implementation` | `/implement` | OWASP ASVS, OWASP Top 10, OWASP Cheatsheets |
| `Code review` | `/code-review` | TBA |
| `Testing` | `/test` | OpenSSF SLSA, NIST SSDF, OWASP DSOMM |
| `Deployment` | `/deploy` | CIS Benchmarks (e.g., AWS), OWASP DSOMM, Kubernetes Pod Security Standards, OWASP cheatsheets (e.g., Docker), OWASP Docker Top 10 |
| `Maintanence` | `/maintain` | TBA |

## High-level guidelines to use
| Name | Description |
|----------|---------|
| OWASP DSOMM | Any DevSecOps task/implementation. Pair with OWASP SAMM |
| OWASP SAMM | General-use. High-level, abstract decisions, good baseline. Pair with OWASP DSOMM |
| Microsoft SDL | Best to use with microsoft ecosystem tools (e.g., Windows, Entra, Azure, GitHub) |
| NIST SSDF | General-use. Middle ground between high-level and technical |

## Common Rationalizations
| Rationalization | Reality |
|---|---|
| "I don't know what local compliance is required" | Prompt and ask the user, user is always available to clarify |