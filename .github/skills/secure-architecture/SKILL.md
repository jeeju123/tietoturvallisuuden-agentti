---
name: secure-architecture
description: Ensure the software architecture is designed with security in mind, identifying potential threats, architectural gaps, and anti-patterns, and providing recommendations for secure architectural improvements.
metadata:
  author: Juho Salomäki
  version: "0.1.0"
---

## When to Use
- After decomposition and threat modelling activities are completed
- Major refactor or upgrade
- Before starting development of a new feature
- Attack surface is extended (internet-facing components)
- New third-party system or an API is integrated
## When NOT to use
- Minor change to the software that does not affect the architecture or data flow
- Prototype software that is not intended for production use is under development
- Introducing a commercial software with no customizations or integrations (off-the-shelf software)
- Only static content
- Without pre-existing DFD and trust boundaries (use `decompose` skill first)
- Without pre-existing threat model (use `threat-model` skill first)

## Architectural Security Review
Collect architectural information and understand the system Data Flow Diagram (DFD), STRIDE Threats, possible mitigations and trust boundaries. Create `architecture-improvements.md` file in `artefacts/` folder and fill it with security recommendations for architectural improvements.

### Step 1. Collect initial information
Start by understanding DFD structure with trust boundaries and load it to context

1. In `decomposition-results.json` file, look for:
   - Actors (`tm.Actor`)
   - Processes (`tm.Process`)
   - Stores (`tm.Store`)
   - Flows (`tm.Flow`)
   - Boundaries (`tm.Boundary`)

2. In `threat-model.json` file, look for the previously found decomposition elements. For each element, find the associated `threats` array. From the array continue to collect the following information:
   - Type (`type`)
   - Title (`title`)
   - Description (`description`)
   - Mitigation (`mitigation`)
   - Severity (`severity`)
   - Status (`status`)
   - Score (`score`)

3. **Cross-check** identified threats against the actual trust boundary crossings in `decomposition-results.json` file. Ensure that:
    - No orphan threats exist (i.e., threats that do not have a corresponding DFD element)
    - Look for unmitigated ingress/egress points

4. Understand how the system works, specifically look for the following:
   - How data flows between components
   - Identify trust boundaries and potential attack surfaces
   - Identify any existing mitigations for the threats
   - Look for threat context and how it related to architecture

5. If `SPEC.md` exists, try to understand what changes user is trying to implement and how it will change the architecture

### Step 2. Analyse architectural gaps and anti-patterns
Based on the gathered information, identify architectural gaps and anti-patterns that may introduce security risks. Create `architecture-improvements.md` file in `artefacts/` folder and fill it with security recommendations for architectural improvements. Use the `secure-architecture/` folder inside `references/` for general reference and guidance.

1. Look for architectural gaps and anti-patterns that may introduce security risks. Such as:
    - Single point of failure/compromise
    - Lack of defense-in-depth and soft-shelling
      - No application/network segmentation (i.e. layering)
      - No mTLS for internal service-to-service communication
      - Internal services are not hardened (e.g., IAM, Encryption)
      - No observability (e.g., monitoring/logging) for internal traffic (system built with assumption that it will not be compromised)
    - Admin interfaces, DB connections or other endpoints (e.g., metrics) exposed to the internet
      - No VPN restrictions
    - Flat egress/ingress network topology (e.g., no DMZ, no internal firewalls, lack of security groups)
      - Also egress to avoid C2
    - IAM & trust anti-patterns
      - lack of least-privilege, no separation of duties, no role-based access control (RBAC)
      - No identity federation (e.g., SSO, OIDC, SAML)
      - Token passthrough (e.g., JWT, OAuth2) without proper validation
      - Hardcoded credentials, secrets or API keys in source code or IaC
      - Database as integration layer for microservices
      - God services (e.g., overprivileged services)
      - Confused deputy (e.g., service A can assume service B's role, and service B can assume service A's role)
    - Developer settings enabled in production (e.g., debug mode, verbose logging, test endpoints)
    - Data leakage via telemetry
    - Public data sources with direct access (e.g., no pre-signed urls)
    - Bad secret maanagement (e.g., no rotation, no vault, no KMS)
    - Excessive AI trust (e.g., LLMs, generative AI) without proper guardrails
    - Difficult to patch/update (e.g., no CI/CD, no IaC, no automated testing)
    - Security as obscurity
    - Client is overly trusted (e.g., no client-side validation, no mechanism to detect tampering, no observability for client-side events, no client-side rate limiting, no client-side authentication, no mechanism to delete/revoke client access)
    - Data leakage via client-side storage (e.g., localStorage, sessionStorage, cookies)
    - Data leakage via client-side caching (e.g., service workers, PWA, CDN)
    - Data leakage via database across multiple tenants (e.g., no row-level security, no tenant isolation)

2. For each potential architectural issue, provide a security recommendation for architectural improvements. Include the information in `architecture-improvements.md` file in the `artefacts/` folder. Include recommendations and aim for clear and readable list. The items should be actionable, if not, then include them to a separate "Potential issues" section. Give detailed explanations.

## Common Rationalizations
| Rationalization | Reality |
|---|---|
| "This issue may be abused in a very specific scenario, not actionable" | Add to a "Potential issues" section |

## Red Flags
- Empty `architecture-improvements.md` file
- No issues were found


## Verification
After completing the decomposition confirm that:
- [ ] `architecture-improvements.md` exists in `artefacts/` folder
- [ ] `architecture-improvements.md` has recommendations for architectural improvements
- [ ] `architecture-improvements.md` recommendations have been enriched with detailed explanations