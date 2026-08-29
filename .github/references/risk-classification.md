# Risk classification

## Metadata
Version: 0.1.0

## Risk categories
| Risk class | Operation action | Target SLA |
|----------|---------|---------|
| Emergency/Critical | Upmost priority. Create backlog item outside sprint scope and hotfix immediately | 24-72 hours |
| High/Elevated | Bring item to sprint and ticket should be actively worked on within 24-48h | 7-14 days |
| Moderate | Treat as typical maintanence item, bring to next sprint | 30-60 days |
| Minor | Best effort fix, patch with typical cycles | 90+ days |
| Informational | Not actively tracked, good-to-know information | None |

## Combination matrix for risk
| Risk class | CVSS | EPSS | KEV | Description |
|----------|---------|---------|---------|---------|
| Emergency | Any | Any | Yes | Active target, upmost priority. Emergency patch |
| Critical | Critical/High (>= 7.0) | High (>= 10%) | No | Actively/probably used with high impact |
| High | Medium/Low (< 7.0) | High (>= 10%) | No | Low impact, but actively/probably used |
| Elevated | Critical/High (>= 7.0) | Low (< 10%) | No | Theoretically severe impact, but not actively used |
| Moderate | Medium (4.0-6.9) | Low (< 10%) | No | Standard maintanence patch |
| Minor | Low (< 4.0) | Low (< 1%) | No | Best effort patch |

## Normalization reference for tool output
| Tool output | CVSS | Risk class | Description |
|----------|---------|---------|---------|
| Gitleaks: leaks found | not applicable | Blocker | User should not do anything until exposed secret is removed |
| Trivy UNKNOWN | Medium (4.0-6.9) | refer to combination matrix | User should not do anything until exposed secret is removed |

## Source of truth
- Findings from security scanning tools: **Always use** tool's native severity. Utilize normalization table and risk combination matrix. Preserve and output direct scores with the resolved risk.
- Finding from secret scans: secret findings are **always** emergency risks. Remove exposed secrets from source code immediately, before commiting to version control.