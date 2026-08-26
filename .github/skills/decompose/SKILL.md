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
Collect architectural information. Create `decomposition-results.json` file in `artefacts/` folder and fill it with `OWASP Threat Dragon` schema formatted DFD + trust boundaries. **Use** the `v2.x schema` (**use** `schema.json` as reference).

### Step 1. Collect initial information
Start by understanding the system architecture and load it to context

1. Look for API specifications (e.g., OpenAPI/Swagger) and collect:
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
    - file types (e.g., `.ts` instead of `.js` indicates TypeScript)
    - dependencies (e.g., external integrations)
    - ORM schemas and DTO models
    - security configurations
    - database drivers
    - file system writes or cloud resource calls
    - Look for gRPC, REST, WebSocket, or other network calls
    - Web controllers (e.g., Express.js/Nest.js/Next.js routes, Spring MVC controllers)
    - Application configuration files or manifests (always ask permission to view)

4. If `SPEC.md` exists, try to understand what changes user is trying to implement and how it will change the architecture

### Step 2. Create Initial OWASP Threat Dragon Catalogue
Draft OWASP Threat Dragon formatted json file based on the `v2.x schema` (**use** `schema.json` as reference)

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
  - Human **will** read this diagram, adjust readability
  - Add enough spacing for clicking the objects in Threat Dragon Web-based UI
- Draw trust boundaries vertically between public and internal components

### Quick reference
| DFD Element name | Explanation | Examples
|---|-------|------|
| Actors (`tm.Actor`) | Externally accessing entity | Human (e.g., Admin, User) or Machine (e.g., Webhooks, Third-party APIs) |
| Processes (`tm.Process`) | Compute resource | Microservices, Serverless functions (e.g., AWS Lambda), Cron workers, Edge routers, REST-APIs |
| Data Store (`tm.Store`) | Data persistance | Databases (e.g., PostgreSQL), Caches (e.g., Redis), Object Storage (e.g., AWS S3 Buckets) File systems, Elasticsearch |
| Data Flow (`tm.Flow`) | Network communications | HTTP/gRPC calls, Message queues (e.g., Kafka, RabbiMQ), WebSocket channel, Database connections |
| Trust boundary (`tm.Boundary`) | Perimeter transitions | Unautenticated to authenticated, Public subnet to private subnet, internet to DMZ |

### Rendering compatibility that is not covered in `schema.json`

`schema.json` only validates structure/types, not the values Threat Dragon's UI actually needs to render the diagram. Knowledge gathered against the Threat Dragon `td.vue` source (`service/x6/shapes/*`, `service/entity/default-properties.js`):

- `diagram.diagramType` must be one of the threat-modeling methodologies Threat Dragon recognizes: `STRIDE`, `CIA`, `LINDDUN`, `PLOT4ai`, or `Generic`. Do **not** use a format name like `"DFD"` - the summary/description still loads, but the diagram canvas silently fails to render.
- Registered `shape` values are exactly: `actor`, `process`, `store`, `flow`, `trust-boundary-curve`, `trust-boundary-box`, `td-text-block`.
- `data.type` values are exactly: `tm.Actor`, `tm.Process`, `tm.Store`, `tm.Flow`, `tm.Boundary` (curve), `tm.BoundaryBox`, `tm.Text`.
- **Visible labels are NOT driven by `data.name`.** Each cell needs its own separate label field or it renders with a generic/localized shape name (e.g. Finnish UI shows "Toimija"/"Prosessi"/"Tietovirta"/"Säilö"):
  - Node shapes (`actor`, `process`, `store`) need a top-level `"label": "<name>"` string property (sibling of `shape`/`position`/`size`).
  - Edge shapes (`flow`, `trust-boundary-curve`) need a top-level `"labels": ["<name>"]` array of plain strings (sibling of `shape`/`source`/`target`).
  - Keep `data.name` populated too (used for reports/properties panel), but it does not by itself paint the on-canvas text.
- `store` shapes render as parallel lines, not a stroked box: give them `attrs.topLine`/`attrs.bottomLine` (stroke/strokeWidth), and leave `attrs.body` transparent/unstroked (don't just reuse the `actor`/`process` `attrs.body` stroke pattern).
- `trust-boundary-curve` is an edge (not a box): its `source`/`target` can be plain `{x, y}` canvas coordinates (not `{cell: id}`), `connector: "smooth"`, and `attrs.line` typically uses `strokeWidth: 3`, `strokeDasharray: "10 5"`, `sourceMarker`/`targetMarker: null` (dashed, no arrowheads).

## Common Rationalizations
| Rationalization | Reality |
|---|---|
| "I already looked through IaC, no need to search for cloud calls in source-code" | The setup may be more complex than initially seemed |
| "I will switch to Open Threat Model format, so output is less coupled" | OWASP Threat Dragon specific schema is chosen intentionally, use it strictly |

## Red Flags
- Empty catalogue
- All shapes placed at the same coordinates (e.g., 0,0)
- Threat lists are not empty

## Verification
After completing the decomposition confirm that:
- [ ] `decomposition-results.json` exists in `artefacts/` folder
- [ ] `decomposition-results.json` is populated and uses `OWASP Threat Dragon v2.x` schema (**use** `schema.json` as reference)
- [ ] `decomposition-results.json` has both types and shapes