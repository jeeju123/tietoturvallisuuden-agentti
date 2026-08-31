# Data classification

Quick reference for general data classification and handling practices.

## Metadata
Version 0.1.0

## Data classes
| Class | Description | Examples |
|----------|---------|---------|
| Restricted (T1) | Very sensitive data. Data that may be legally protected by regulations | Secrets, passwords, tokens, payment information, other credentials, private keys, PII |
| Confidential (T2) | Business-sensitive information, exposure can harm organization | Logs, metrics, internal documents |
| Internal (T3) | Private source-code and domain logic | Configurations, data structures, data stores, internal API descriptions |
| Public (T4) | Not sensitive. Allowed to be publicly accessible | Brand assets, public APIs, public pages (e.g, landing pages, documentation) |

## High-level guidelines to use
| Name | Description |
|----------|---------|
| OWASP DSOMM | Any DevSecOps task/implementation. Pair with OWASP SAMM |
| OWASP SAMM | General-use. High-level, abstract decisions, good baseline. Pair with OWASP DSOMM |
| Microsoft SDL | Best to use with microsoft ecosystem tools (e.g., Windows, Entra, Azure, GitHub) |
| NIST SSDF | General-use. Middle ground between high-level and technical |

## Rules
- Allowed by default
  - T4 and T3 data and data source read and all other interaction
- Human approval gated. **Must** ask before reading
  - Reading or interacting with T2 data source
  - Modifying database schema
  - Interacting with staging/test or production data source
- Strictly **Never allowed**
  - Reading/writing/editing/displaying/hardcoding or any other interaction with T1 data
