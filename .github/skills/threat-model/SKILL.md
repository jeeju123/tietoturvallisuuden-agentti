---
name: threat-model
description: Do a threat modelling exercise for the software. Identify potential threats, vulnerabilities and attack vectors using the STRIDE framework
compatibility: Requires OWASP Threat Dragon formatted JSON diagram from the `decompose` skill
metadata:
  author: Juho Salomäki
  version: "0.1.0"
---

## When to Use
- After decomposing the software and creating a Data Flow Diagram (DFD) with trust boundaries
- Major refactor or upgrade
- Before security architecture review
- Attack surface is extended (internet-facing components)
- New third-party system or an API is integrated
## When NOT to use
- Minor change to the software that does not affect the architecture or data flow
- Prototype software that is not intended for production use is under development
- Introducing a commercial software with no customizations or integrations (off-the-shelf software)
- Only static content
- Without pre-existing DFD and trust boundaries (use `decompose` skill first)

## STRIDE Threat Modelling
Collect architectural information and understand the system Data Flow Diagram (DFD) and trust boundaries. Create `threat-model-results.json` file in `artefacts/` folder and fill it with `OWASP Threat Dragon` schema formatted DFD + trust boundaries + STRIDE threats. **Use** the `v2.x schema` (**use** `schema.json` as reference).

### Step 1. Collect initial information
Start by understanding DFD structure with trust boundaries and load it to context

1. In `decomposition-results.json` file, look for:
   - Actors (`tm.Actor`)
   - Processes (`tm.Process`)
   - Stores (`tm.Store`)
   - Flows (`tm.Flow`)
   - Boundaries (`tm.Boundary`)

2. Understand how the system works and how data flows between components. Identify trust boundaries and potential attack surfaces.

3. If `SPEC.md` exists, try to understand what changes user is trying to implement and how it will change the architecture

### Step 2. Start threat modelling
Threat Dragon element-by-element, identify potential threats using STRIDE framework. Populate `threat-model-results.json` file in `artefacts/` folder with identified threats.

**If `SPEC.md` exists, consider how the proposed changes may introduce new threats or modify existing ones.**

Instructions to follow: 
  - Analyze each DFD element (`tm.Actor`, `tm.Process`, `tm.Store`, `tm.Flow`, `tm.Boundary`) and identify potential threats based on STRIDE categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
  - When Boundary is crossed, any flow that crosses the boundary should be considered for threats. Especially for:
    - Spoofing & Tampering: Lack of authentication, weak authentication, broken authentication or signing across the trust boundary
    - Information Disclosure: Weak, missing or broken encryption across the trust boundary
  - For component analysis, especially look for (but **do not limit to**):
    - Data Stores: Evaluate tampering, Information Disclosure, Denial of Service threats
    - Actors: Evaluate Spoofing, Repudiation threats
    - Processes: Evaluate Elevation of Privilege and Tampering threats
  - Attach severity, description, and mitigation recommendations (among other available fields) for each identified threat (According to `v2.x schema`, **use** `schema.json` as reference). **Always** Refer to `risk-classification.md` for severity classification.
  - **Nest each cell's threats under `data.threats`** (e.g. `cell.data.threats = [...]`), **never** as a sibling property of `data` at the cell root. See the `decompose` skill's 'Rendering compatibility' notes. `schema.json` alone does not catch incorrect nesting. Failure to follow this rule will result in threats not being rendered correctly in Threat Dragon.


### Quick STRIDE threat reference
| Type | Violation | Risk | Examples
|---|-------|------|------|
| Spoofing | Authentication | Identity theft | Intercept and use personal links or  a session |
| Tampering | Integrity | Data modification without authorization | Man-in-the-Middle (MitM), modify parameters, modify cookies |
| Repudiation | Non-repudiation | Ability to deny malpractice due to no available proof | Delete audit logs |
| Information Disclosure | Confidentiality | Exposing sensitive data to unauthorized actors | Object storage left public, lack of encryption |
| Denial of Service | Availability | Exhausting or crashing service so no-one can use it | Sending overwhelming amount of traffic, uploading unprocessable content |
| Elevation of Privilege | Authorization | Gain higher privileges than given | Writing to privileged cron-jobs as unprivileged user, Broken Object Level Authorization (BOLA) |

### Quick STRIDE -> Threat Dragon compatibility reference
| DFD Element name | Possible STRIDE threat | Example of element
|---|-------|------|
| Actors (`tm.Actor`) | Spoofing, Repudiation | Human (e.g., Admin, User) or Machine (e.g., Webhooks, Third-party APIs) |
| Processes (`tm.Process`) | Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege | Microservices, Serverless functions (e.g., AWS Lambda), Cron workers, Edge routers, REST-APIs |
| Data Store (`tm.Store`) | Tampering, Repudiation, Information Disclosure, Denial of Service | Databases (e.g., PostgreSQL), Caches (e.g., Redis), Object Storage (e.g., AWS S3 Buckets) File systems, Elasticsearch |
| Data Flow (`tm.Flow`) | Tampering, Information Disclosure, Denial of Service | HTTP/gRPC calls, Message queues (e.g., Kafka, RabbiMQ), WebSocket channel, Database connections |
| Trust boundary (`tm.Boundary`) | Perimeter transitions | Unautenticated to authenticated, Public subnet to private subnet, internet to DMZ |

### Step 3. Post-threat modelling
If `SPEC.md` exists, review existing threats in `threat-model-results.json` and update them if necessary based on new information or changes proposed in `SPEC.md`.

## Common Rationalizations
| Rationalization | Reality |
|---|---|
| "I don't think this threat is realistic, I will skip it" | That might not be the case, prompt user for a justification |

## Red Flags
- Empty `threat-model-results.json` file
- Threats are not nested under `data.threats` in each cell
- All shapes placed at the same coordinates (e.g., 0,0)
- Threat lists are empty
- Threats have empty fields for severity, description, or mitigation recommendations

## Verification
After completing the decomposition confirm that:
- [ ] `threat-model-results.json` exists in `artefacts/` folder
- [ ] `threat-model-results.json` is populated and uses `OWASP Threat Dragon v2.x` schema (**use** `schema.json` as reference)
- [ ] `threat-model-results.json` has enriched threats with severity, description, and mitigation recommendations