# Decompose software

## Overview
Architecturally decompose unknown ("black-box") software to understand its inner workings, identify its components, and component relationships. Decompose, then produce OWASP Threat Dragon compabitile a Data Flow Diagram (DFD) and identify trust boundaries to support threat modeling and further security analysis.

## When to Use
- Before threat modelling, when Data Flow Diagram (DFD) and trust boundaries are not available
- Major refactor or upgrade
- Before security architecture review
- Attack surface is extended (internet-facing components)
- New third-party system or an API is integrated
## When NOT to use
- Minor change to the software that does not affect the architecture or data flow
- Minimum Viable Product (MVP) or prototype software that is not intended for production use is under development
- Introducing a commercial software with no customizations or integrations (off-the-shelf software)
- Only static content

## Data Flow Diagram (DFD) and Trust boundaries
Collect architectural information. Create `decomposition-results.json` file in `artefacts/` folder and fill it with `OWASP Threat Dragon` schema formatted DFD + trust boundaries  

### Step 1. Collect initial information
Start by understanding the system architecture and load it to context

1. Look for OpenAPI specifications and collect:
   - endpoints: (e.g., `/api/v1/profile`)
   - HTTP methods: (e.g., `GET`, `PUT`)
   - auth scopes: (e.g., `Bearer`)
   - request/response payloads
   - additional extensions (e.g., `x-amazon-apigateway-integration`)

2. Look though Infrastructure-as-Code (e.g., Terraform, Ansible):
    - Docker/Docker Compose files
    - CI/CD pipelines (e.g., `deploy.yml`)
    - Resources (e.g., Provider-specific Datastores, Compute, Integrations, APIs)
    - Firewall Configurations / Security Groups (e.g., ingess from service port/subnet)
    - Networking (e.g., subnetting structure)

3. Parse source-code and look for:
    - imports (e.g., HTTP libraries)
    - dependencies (e.g., external integrations)
    - ORM schemas and DTO models
    - security configurations
    - database drivers
    - file system writes or cloud resource calls
    - Web controllers
    - Application configuration files or manifests (always ask permission to view)

4. If `SPEC.md` exists, try to understand what changes user is trying to implement and how it will change the architecture

### Step 2. Create Initial OWASP Threat Dragon Catalogue
Draft OWASP Threat Dragon formatted json file based on the

Instructions to follow: 
  - Populate summary sections
  - Fill Actors, Processes, Stores, Flows, Boundaries (shape and type) based on technical findings
  - If `SPEC.md` exists, Fill Actors, Processes, Stores, Flows, Boundaries (shape and type) based on what user is trying to implement
  - Leave threats array empty

### Step 3. Visualize OWASP Threat Dragon Catalogue
Shapes should be logically structured and viewable by a human reviewer.

Instructions to follow: 
- Have clear horizontal flow: place from left to right (Actors in left, Processes middle, Stores right)
- Prevent overlapping nodes: add spacing, use different (but logical) coordinates
- Draw trust boundaries vertically between public and internal components

### Quick reference
| DFD Element name | Explanation | Examples
|---|-------|------|
| Actors (`tm.Actor`) | Externally accessing entity | Human (e.g., Admin, User) or Machine (e.g., Webhooks, Third-party APIs) |
| Processes (`tm.Process`) | Compute resource | Microservices, Serverless functions (e.g., AWS Lambda), Cron workers, Edge routers, REST-APIs |
| Data Store (`tm.Store`) | Data persistance | Databases (e.g., PostgreSQL), Caches (e.g., Redis), Object Storage (e.g., AWS S3 Buckets) File systems, Elasticsearch |
| Data Flow (`tm.Flow`) | Network communications | HTTP/gRPC calls, Message queues (e.g., Kafka, RabbiMQ), WebSocket channel, Database connections |
| Trust boundary (`tm.Boundary`) | Perimeter transitions | Unautenticated to authenticated, Public subnet to private subnet, internet to DMZ |

## Common Rationalizations
| Rationalization | Reality |
|---|---|
| "I already looked through IaC, no need to search for cloud calls in source-code" | The setup may be more complex than initially seemed |
| "I will switch to Open Threat Model format, so output is less coupled" | OWASP Threat Dragon specific schema is chosen intentionally |

## Red Flags
- Empty catalogue
- All shapes placed at the same coordinated (e.g., 0,0)
- Threat lists are not empty

## Verification
After completing the decomposition confirm that:
- [ ] `decomposition-results.json` exists in `artefacts/` folder
- [ ] `decomposition-results.json` is populated uses `OWASP Threat Dragon` schema
- [ ] `decomposition-results.json` has both types and shapes