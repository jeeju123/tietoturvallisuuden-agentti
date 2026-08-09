# Secure database

Quick reference for secure database design best practices. This document offers guidance at the database layer. Refer to '.github/references/secure-iac' folder for database related infrastructure security best practices.

## Scope
This reference offers database security guidelines at an abstract level. There are many database technologies (e.g., PostgreSQL, MicrosoftSQL Server) that differ in capabilities on how these measures could be implemented. **Always** take the database technology into context, note its limits and where it works the best.

## Privileges
### 1. Users

### 2. User privileges
**Always** follow the least privilege principle. Only apply privileges that are necessary for actions. Furthermore, evaluate whether the action resulting in privilege is even necessary.

### 3. Audit information
Audit data should remain **immutable**. The audit infromation shall not be deleted, updated or tampered with in any other way. This shall be technologically enforced. Audit data is for example:
  - Columns such as `created_at`, `updated_by`. Also known as "audit columns"
  - Tables keeping track of changes. Also known as "audit tables" or "log tables"

## Tenant isolation
When a database contains organization-specific or **any** other data that will be separated into different tenants, such tenants should **always** be logically or physically isolated from accessing each others data. **Avoid** shared schemas when possible. Database isolation itself is not enough, defense-in-depth should always be applied when possible and therefore applications level constraints are highly important.

### 1. Shared schema
Database environment where database and schema are shared. Should be used **only** if tenant count is expected to be very large (e.g., from thousands upwards) or other similar reason where further isolation is not feasible from infrastrucure standpoint. Shared schema should use row level isolation. For example, in most databases: **Row Level Security (RLS)** or similar is supported.

### 2. Separated schema per tenant
Have one database, but separate tenants with schema-isolation. Allocate entire schema to a tenant. Offers logical isolation, but is scalable: **Best solution** in most cases.

### 3. Physical database separation
Different databases for each tenant. Offers best security, but is hard to manage and will require infrastructure resources. Use when necessary, for example due to compliance reasons.

## Auditability
A database should be designed in a manner that it is auditable and that it allows for post-mortem incident investigation. 

### 1. Enrich with audit columns
When creating a new table that concerns user actions, **always** enrich the table with following columns:
  - Timestamp which tells when row was created: `created_at`
  - Timestamp which tells when row was updated: `updated_at`
  - Unique identifier which tells who created the row: `created_by`
  - Unique identified which tells who updated the row: `updated_by`

### 2. Do not delete a record
Upon `DELETE`, **never** actually delete the record, instead:
  - Apply logic that defines a deletion. For example, `is_deleted` boolean flag
  - **Always** leave a timestamp that determines when row was deleted
  - Include a `deleted_by` column that ties the deletion to the deleter with an unique identifier

### 3. Keep correlation data
Transactions, government-ID identifications and other sensitive procedures may require an uniquely identifiable identificator that can be tied to the same instance throughout a procedure. For example, when an transactional procedure starts, client gets issued a unique ID. At some point of the instance, the procedure moves to an external system and unique ID is passed. When the external system passes procedure back to originator, the unique ID ties back to the instance. Throughout the procedure, the unique ID persists and in each system covering the procedure, ID can be correlated to the instance. Thus, in such scenarios, a correlation ID such as `request_id` shall be used.

### 4. Audit log table


## Backup & disaster recovery

## Encryption and key management


