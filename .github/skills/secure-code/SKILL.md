---
name: secure-code
description: Ensure that the code follows secure coding practices to prevent common vulnerabilities and security issues.
compatibility: Requires codebase made with supported language to be available for static analysis and review
metadata:
  author: Juho Salomäki
  version: "0.1.0"
---

## When to Use
  - When program code (e.g., Java, TypeScript, Python) is being written or modified.
  - When infrastructure as code (IaC) is being written or modified
## When NOT to use
  - When performing non-coding activities
  - For lower-level programming (e.g., C, C++), where manual memory management and hardware interactions are prevalent

## Principles to follow during development and review
  - **Least privilege**: Ensure that users, processes, and systems have the minimum level of access necessary to perform their functions
  - **Defense in depth**: Implement multiple layers of security controls to protect against potential threats, rather than relying on a single security measure
  - **Secure by default**: Configure systems and applications to be secure out-of-the-box, minimizing the need for additional security configurations and risk of persisting configuration errors (e.g., development bypasses to production)
  - **Always limit exposure even in development environments**: For example, when deploying a new service, ensure that it is not accessible to the public internet by default. Let user manually open the service (e.g., by configuring firewall rules or access control lists)
  - **Fail securely**: Ensure that systems and applications fail in a secure manner, avoiding the exposure of sensitive information or leaving the system in an insecure state

## Analyze the threat model
**If artefact `threat-model.json` exists in `artefact/` folder** analyze the threat model to enrich your understanding of potential coding vulnerabilities and their impact on broader system security. 
  1. Identify trust-boundaries, data assets, and potential entry points for attackers
  2. Understand data flow within the system, including how data moves between components and where it may be exposed to potential threats
  3. Look through the threat modelled threats and mitigations to identify areas where additional security controls or code changes may be necessary
  4. Consider potential attack scenarios and how they could be mitigated through secure coding practices
  5. **Write your findings in memory and use them for guiding secure coding decisions and implementing appropriate security controls**
  
## Common pitfalls

### OWASP Top ten
**Always look out for the latest OWASP Top Ten vulnerabilities and ensure that your code addresses them appropriately.** Usual suspects include:
  - Broken access control
    - **Typical threats**: BOLA, IDOR, Metadata manipulation, Privilege escalation, Force browsing
  - Security misconfigurations
    - **Typical threats**: Default framework configurations, exposed sensitive endpoints, misconfigured permissions, Security headers misconfigurations, CSP/CORS issues
  - Software supply-chain failure
    - **Typical threats**: Supply-chain attacks via compromised dependencies, malicious package updates, dependency confusion, tampered build scripts
  - Cryptographic failure
    - **Typical threats**: Brute-force, stolen keys, trust-chain not validated -> bypassed, cryptography downgrade
  - Injection
    - **Typical threats**: SQL injection, Command injection, LDAP injection, XML injection
  - Insecure design
    - **Typical threats**: Lack of threat modeling, insecure architecture decisions, missing security controls
  - Authentication failure
    - **Typical threats**: Weak passwords, credential stuffing, missing multi-factor authentication, session hijacking
  - Software and data integrity failure
    - **Typical threats**: Tampered dependencies, compromised build pipelines, unauthorized code changes, lack of integrity checks
  - Security logging and alerting failure
    - **Typical threats**: Missing or inadequate logging, delayed or absent alerting, log tampering, insufficient monitoring, debug logging enabled
  - Mishandling of exceptional conditions
    - **Typical threats**: Unhandled exceptions revealing sensitive information, improper error messages, failure to clean up resources, denial of service through exception flooding

### Framework-specific pitfalls
Different frameworks have their own functionality, security features, and thus potential attack vectors which may not be associated with the underlying programming language itself.

- Quick red flags for Spring Boot
  - `/actuator` endpoints are publicly available, which can expose sensitive application information and management operations
  - Uses Spring Security but may have default configurations that are not secure, such as default login pages or CSRF protection being disabled.
  - Spring-MVC autobinding Entities can lead to mass assignment -> use DTOs for user facing objects
  - Over reliance on ORM, can lead to string interpolation -> SQL injection vector if not using named or indexed parameters
  - Sending untrusted client-data directly to Spring ExpressionParser (e.g., through `@Value` annotations or SpEL expressions) can lead to remote code execution vulnerabilities
  - Binding misconfigurations (e.g., configuration properties)
  - Bean overrides

- Quick red flags for Next.js
  - Over-reliance on `middleware` for security checks -> not all assets are covered
  - Not restricting route access based on authentication or authorization, potentially exposing sensitive pages to unauthorized users
  - Improper handling of sensitive data in `getServerSideProps` or `getStaticProps`, which can lead to data leaks if not carefully managed
  - Importing server components to RSC which may lead into bundling sensitive information into the client-side bundle
  - Not trating server actions as public endpoints (e.g., bypass validation checks or authentication)
  - No background workers, no caching-mechanisms for resource-intensive tasks
  - Exposing private environment variables via `NEXT_PUBLIC_` prefix, which makes them accessible on the client-side
  - Sensitive or dynamic pages not marked with `export const dynamic = 'force-dynamic'` or use of `cookies()`/`headers()` to control caching and data exposure

- Quick red flags for React
  - Using `dangerouslySetInnerHTML`
  - Merging unvalidated JSON objects to state or props can mutate object prototypes
  - Dynamic URL values in HTML attributes -> not auto-escaped by React
  - Using `<script>` tags with dynamic content, using `eval()` (Universal JS risks)

## Security Headers
Always confirm that the following security headers are set correctly.

### Content Security Policy (CSP) - quick red flags
Signs of an bad CSP include:
  - Using `unsafe-inline` for scripts or styles
  - Wildcards within the policy `*`, `data:`, `blob:`, `https:` etc. sources
  - Missing `default-src` directive
  - Whitelisting CDNs or JSONP (even if trusted sources like AWS -> attackers may exploit these sources to inject malicious content)
  - Missing `frame-ancestors` or `object-src` directive
  - Overly permissive `connect-src` or `img-src` directives

Prefer tactics such as using nonce-based or hash-based CSP directives to allow only trusted scripts and styles. Apply least-privilege principles when defining the policy.

### Other security headers - good practices reference
Must be included - bad sign if missing or incorrectly configured.
  - Strict-Transport-Security (HSTS)
    - Ensure that the HSTS header is set with a long max-age and includes the `includeSubDomains` and `preload` directives if applicable.
  - X-Content-Type-Options
    - Ensure that the header is set to `nosniff` to prevent MIME type sniffing.
  - Referrer-Policy
    - Ensure that the header is set to an appropriate value such as `no-referrer` or `strict-origin-when-cross-origin` to control the information sent in the Referer header.
  - Permissions-Policy
    - Ensure that the header is set to restrict access to sensitive browser features (e.g., `geolocation=(), microphone=(), camera=()`)

Pages displaying sensitive information:
  - Cache-Control headers should be set to prevent sensitive information from being stored in caches.
    - Set the `Cache-Control` header to `no-store` or `private` to prevent sensitive information from being cached by browsers or intermediary caches. Along with `max-age=0`
  - Clear-Site-Data headers (on logout)
    - Ensure that the `Clear-Site-Data` header is set to clear cookies, storage, and cache when a user logs out to prevent sensitive information from being retained

- Applications handling sensitive client-state:
  - Cross-Origin-Opener-Policy (COOP)
    - Ensure that the header is set to `same-origin` to prevent cross-origin interactions that could compromise sensitive client-state
- Cross-Origin-Embedder-Policy (COEP)
  - Cross-Origin-Embedder-Policy (COEP)
    - Ensure that the header is set to `require-corp` to prevent the application from loading cross-origin resources that do not explicitly grant permission
- Cross-Origin-Resource-Policy (CORP)
  - Cross-Origin-Resource-Policy (CORP)
    - Ensure that the header is set to `same-origin` to prevent the application from sharing resources with cross-origin contexts that do not explicitly grant permission

## Cross Origin Resource Sharing (CORS) - quick red flags
Apply least-privilege principles when configuring CORS to ensure that only trusted origins have access to the necessary resources. Common red-flags to look for include:
  - Using wildcard (`*`) for the `Access-Control-Allow-Origin` header, **especially when allowing credentials** `Access-Control-Allow-Credentials: true`
  - Reflecting headers in the `Access-Control-Allow-Origin` response without proper validation
  - Potential Regex misconfigurations in the `Access-Control-Allow-Origin` header that could allow unintended origins
  - Using overly permissive methods in the `Access-Control-Allow-Methods` header
  - Including `null` as an allowed origin in the `Access-Control-Allow-Origin` header
  - Caching preflight responses for too long, which could allow outdated or insecure CORS configurations to be used

## Client-side storage - quick red flags
Never store sensitive information to client-side store. If necessary to use, then use encrypted cookies with the `HttpOnly` and `Secure` flags set and consider using the `SameSite` attribute to mitigate CSRF attacks. Red flags to look for include:
  - Storing authentication tokens (e.g., JWTs) or other sensitive information in LocalStorage/SessionStorage
  - Storing any PII client-side
  - Cookies missing the `HttpOnly` and `Secure` flags, or not using the `SameSite` attribute to mitigate CSRF attacks

## Access to third-party integrations

### OAuth - quick red flags
When integrating with OAuth providers, the following findings are red flags:
  - No PKCE (Proof Key for Code Exchange) implemented, which is essential for securing OAuth authorization code flows, especially in public clients
  - Using Resource Owner Password Credentials (ROPC) flow, which is generally discouraged due to security risks and should only be used in highly trusted applications
  - Hardcoding client secrets
  - `redirect_uri` wildcards -> use exact string matching to prevent open redirect vulnerabilities.
  - Missing `state` parameter in the authorization request
  - Not validating the `id_token` or `access_token` received from the OAuth provider (e.g., signature against jwks, iss matches idp, aud matches client_id). Also, consider expiration, replay, revocation status
  - Storing tokens (e.g., `id_token`, `access_token`, `refresh_token`) insecurely on the client-side, such as in LocalStorage or SessionStorage -> prefer BFF (Backend for Frontend) design pattern
  - Refresh token not rotated -> implement refresh token rotation to reduce the risk of token theft
  - Not invalidating tokens properly (e.g., after logout or revocation)

### SAML - quick red flags
When integrating with SAML providers, the following findings are red flags:
  - SP silently accepts SAML unsigned assertions: validates only if signature is present
  - SP extracts x509 embedded certificate directly from the SAML assertion -> may be self-signed
  - Using outdated XML libraries or parsers that may be vulnerable to XML External Entity (XXE) attacks.
  - Not validating the `AudienceRestriction`, `Recipient`, `NotBefore`, and `NotOnOrAfter` attributes in the SAML assertion
  - Insecure HTTP bindigs or unencrypted assertions (e.g., accepting assertions via `HTTP-REDIRECT`)

## Input Validation and Sanitization

## Database auditability - quick reference
### 1. audit columns
- Enrich with audit column - **Always** include following for user actions.
  - `created_at` timestamp and `created_by` unique user identifier
  - `updated_at` timestamp and `updated_by` unique user identifier
  - `deleted_at` timestamp and `deleted_by` unique user identifier

### 2. Do not delete a record
Upon `DELETE`, **never** actually delete the record, instead:
  - Apply logic that defines a deletion. For example, `is_deleted` boolean flag
  - **Always** leave a timestamp that determines when row was deleted
  - Include a `deleted_by` column that ties the deletion to the deleter with an unique identifier

### 3. Keep correlation data
Transactions, government-ID identifications and other sensitive procedures may require an uniquely identifiable identificator that can be tied to the same instance throughout a procedure. For example, when an transactional procedure starts, client gets issued a unique ID. At some point of the instance, the procedure moves to an external system and unique ID is passed. When the external system passes procedure back to originator, the unique ID ties back to the instance. Throughout the procedure, the unique ID persists and in each system covering the procedure, ID can be correlated to the instance. Thus, in such scenarios, a correlation ID such as `request_id` shall be used.

## Cryptography - quick red flags
In terms of cryptography, red flags to look for:
  - Using weak, weakened (e.g., certain suite) or deprecated cryptographic algorithms (e.g., MD5, SHA-1)
  - Hardcoding cryptographic (e.g., private or symmetric) keys in the source code
  - Not using proper key management practices (e.g., bad rotation logic, not using KMS in cloud environments)
  - Using predictable initialization vectors (IVs) or nonces
  - Failing to validate certificates or public keys properly (e.g., mTLS, certificate pinning)
  - Implementing custom cryptographic algorithms instead of using well-established libraries
  - Not properly handling cryptographic errors or exceptions (e.g., ignoring failed decryption or signature verification)
  - Unhashed sensitive data (e.g., passwords, personal information) without proper hashing (e.g., using bcrypt, Argon2) or salt
  - Client-side cryptography (e.g., encrypting sensitive data in the browser)
  - Not utilizing mTLS or VPN (e.g., AWS Direct Connect) in external communications

## Object storage - good practices reference
### Common
  - **Enable server-side encryption**: Ensure that all objects stored in the object storage are encrypted at rest using strong encryption algorithms (e.g., AES-256)
  - **Implement access controls**: Use bucket policies, IAM roles, and ACLs to restrict access to the object storage
  - **Enable logging and monitoring**: Keep track of access and modifications to the object storage for auditing and security purposes
  - **Disable public access**: Ensure that the object storage is not publicly accessible unless explicitly required for specific use cases

Prefer organization wide default bucket policies.

### Resource sharing
If the application purposefully shares resources from object storage via public URLs, include at least the following:
  1. Use cryptographically signed URLs signed by the server

  **Good example:**
  ```
  https://my-bucket.s3.amazonaws.com/private/invoice-<uuid>.pdf
    ?X-Amz-Algorithm=AWS4-HMAC-SHA256
    &X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20260908%2Fus-east-1%2Fs3%2Faws4_request
    &X-Amz-Date=20260908T140000Z
    &X-Amz-Expires=3600
    &X-Amz-SignedHeaders=host
    &X-Amz-Signature=9f8c7d3e2a1b...c4d5e6f7 
  ```

  **Bad example:**
  ```
  https://my-bucket.s3.amazonaws.com/private/invoice-1234.pdf
  ```

  2. Set TTL or time-based expiration to limit visibility window
  3. URL should not be publicly accessible without proper authorization
  4. Signing **does not mean** encryption -> still visible to anyone who has the signed link

## Multi-tenancy
When a database contains organization-specific or **any** other data that will be separated into different tenants, such tenants should **always** be logically or physically isolated from accessing each others data. **Avoid** shared schemas when possible. **Database isolation itself is not enough, defense-in-depth should always be applied when possible and therefore applications level constraints are highly important.**

### 1. Shared schema
Database environment where database and schema are shared. Should be used **only** if tenant count is expected to be very large (e.g., from thousands upwards) or other similar reason where further isolation is not feasible from infrastrucure standpoint. Shared schema should use row level isolation. For example, in most databases: **Row Level Security (RLS)** or similar is supported.

### 2. Separated schema per tenant
Have one database, but separate tenants with schema-isolation. Allocate entire schema to a tenant. Offers logical isolation, but is scalable: **Best solution** in most cases.

### 3. Physical database separation
Different databases for each tenant. Offers best security, but is hard to manage and will require infrastructure resources. Use when necessary, for example due to compliance reasons.

## Re-inventing the wheel
A common mistake is attempting to implement functionality that is already well-maintained and supported by existing libraries or frameworks made by third-party developers with expertise in the area. You should not:
  - Implement your own cryptographic algorithms instead of using well-established libraries (e.g., bcrypt, OpenSSL)
  - Build your own authentication and authorization mechanisms instead of using identity providers (IDPs) (e.g., Cognito, Keycloak)
  - Develop custom payment processing solutions instead of using well-established payment providers (e.g., Stripe, Paytrail).
  - Create your own logging or monitoring solutions instead of using well-established observability tools (e.g., ELK Stack, Prometheus, CloudWatch)
  - Implement your own database abstraction layer instead of using well-established ORM libraries (e.g., Prisma, Hibernate)
  - Implement validation and sanitization logic instead of using well-established libraries (e.g., OWASP Java HTML Sanitizer, Zod)
  - Building custom infrastructure if application is already deployed to a cloud provider (e.g., AWS, Azure, GCP)

## Best practice references
Map each finding to the relevant best practice or framework to ensure comprehensive coverage.
  - OWASP Top Ten
  - CIS Benchmarks
  - OWASP Application Security Verification Standard (ASVS)
  - OWASP Cheatsheets
  - Cloud provider best practices (e.g., AWS Well-Architected Framework, Azure Security Benchmark, Google Cloud Security Best Practices)

### Reporting findings
After gathering all the potential security findings, document them clearly, and provide remediation recommendation. Output the findings during development and create report `security-code-review.md` inside the `artefacts/` folder. Iterature through each finding and provide at least the following:
  - Name of vulnerability or issue (if directly applicable - e.g., SQL Injection)
  - Severity or risk level of the finding based on `risk-classification.md` reference
  - Description of the finding 
  - File path and code line number (if applicable)
  - Remediation recommendation (**Do not proceed with the remediation without user approval**)

## Common Rationalizations
| Rationalization | Reality |
|---|---|
| "User is not going to production, security is good enough" | While user may be CURRENTLY in a non-production environment, they may deploy later on without your knowledge, thus issues will persist into production |

## Red Flags
- Disablement of security defaults and policies (e.g., no csrf token, broad CSP, "*" in CORS, inclusion of flags such as `--insecure` or environment variables that disregard TLS)
- Lack of security headers (e.g., HSTS, X-Content-Type-Options, X-Frame-Options)
- Hardcoded secrets, tokens, or credentials in the codebase
- `eval` or `innerHTML` usage in the codebase
- Any security control bypasses (e.g., development shortcuts) not clearly isolated or documented
- Not using ORM for database interactions without proper cause (e.g., performance)
- Re-inventing the wheel instead of using well-established libraries, frameworks or other technologies
- Using insecure or deprecated functions, libraries, or APIs
- Lack of input validation and sanitization
- Lack of proper error handling and exception management
- Lack of logging and monitoring mechanisms
- Weak cryptography or insecure cryptographic practices
- Verbose logging of potentially sensitive information
- Unsafe deserialization (e.g., no strict type checks)
- No defense-in-depth mechanisms in place (e.g., relying solely on perimeter security such as endpoint annotations)


## Verification
After completing the secure code review, confirm that:
  - [ ] `security-code-review.md` has been created in `artefacts/` and reviewed
  - [ ] `security-code-review.md` is not empty -> contains documented findings and rationalizations
  