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

## Principles
- **Least privilege**: Ensure that users, processes, and systems have the minimum level of access necessary to perform their functions
- **Defense in depth**: Implement multiple layers of security controls to protect against potential threats, rather than relying on a single security measure
- **Secure by default**: Configure systems and applications to be secure out-of-the-box, minimizing the need for additional security configurations and risk of persisting configuration errors (e.g., development bypasses to production)
  - **Always limit exposure even in development environments**: For example, when deploying a new service, ensure that it is not accessible to the public internet by default. Let user manually open the service (e.g., by configuring firewall rules or access control lists)
- **Fail securely**: Ensure that systems and applications fail in a secure manner, avoiding the exposure of sensitive information or leaving the system in an insecure state

## Analyze the threat model

## Implement good security practices


## Security Headers
Always confirm that the following security headers are set correctly.

### Content Security Policy (CSP)
Signs of an bad CSP include:
- Using `unsafe-inline` for scripts or styles
- Wildcards within the policy `*`, `data:`, `blob:`, `https:` etc. sources
- Missing `default-src` directive
- Whitelisting CDNs or JSONP (even if trusted sources like AWS -> attackers may exploit these sources to inject malicious content)
- Missing `frame-ancestors` or `object-src` directive
- Overly permissive `connect-src` or `img-src` directives

Prefer tactics such as using nonce-based or hash-based CSP directives to allow only trusted scripts and styles. Apply least-privilege principles when defining the policy.

### Other security headers
Must be included - bad sign if missing or incorrectly configured.
- Strict-Transport-Security (HSTS)
  - Ensure that the HSTS header is set with a long max-age and includes the `includeSubDomains` and `preload` directives if applicable.
- X-Content-Type-Options
  - Ensure that the header is set to `nosniff` to prevent MIME type sniffing.
- Referrer-Policy
  - Ensure that the header is set to an appropriate value such as `no-referrer` or `strict-origin-when-cross-origin` to control the information sent in the Referer header.
- Permissions-Policy
  - Ensure that the header is set to restrict access to sensitive browser features (e.g., `geolocation=(), microphone=()`)

Pages displaying sensitive information:
- Cache-Control headers should be set to prevent sensitive information from being stored in caches.
  - Set the `Cache-Control` header to `no-store` or `private` to prevent sensitive information from being cached by browsers or intermediary caches. Along with `max-age=0`
- Clear-Site-Data headers (on logout)
  - Ensure that the `Clear-Site-Data` header is set to clear cookies, storage, and cache when a user logs out to prevent sensitive information from being retained

Applications handling sensitive client-state:
- Cross-Origin-Opener-Policy (COOP)
  - Ensure that the header is set to `same-origin` to prevent cross-origin interactions that could compromise sensitive client-state
- Cross-Origin-Embedder-Policy (COEP)
  - Ensure that the header is set to `require-corp` to prevent the application from loading cross-origin resources that do not explicitly grant permission
- Cross-Origin-Resource-Policy (CORP)
  - Ensure that the header is set to `same-origin` to prevent the application from sharing resources with cross-origin contexts that do not explicitly grant permission

## Cross Origin Resource Sharing (CORS)
Apply least-privilege principles when configuring CORS to ensure that only trusted origins have access to the necessary resources. Common red-flags to look for include:
- Using wildcard (`*`) for the `Access-Control-Allow-Origin` header, **especially when allowing credentials** `Access-Control-Allow-Credentials: true`
- Reflecting headers in the `Access-Control-Allow-Origin` response without proper validation
- Potential Regex misconfigurations in the `Access-Control-Allow-Origin` header that could allow unintended origins
- Using overly permissive methods in the `Access-Control-Allow-Methods` header
- Including `null` as an allowed origin in the `Access-Control-Allow-Origin` header
- Caching preflight responses for too long, which could allow outdated or insecure CORS configurations to be used

## Client-side storage
Never store sensitive information to client-side store. If necessary to use, then use encrypted cookies with the `HttpOnly` and `Secure` flags set and consider using the `SameSite` attribute to mitigate CSRF attacks. Red flags to look for include:
- Storing authentication tokens (e.g., JWTs) or other sensitive information in LocalStorage/SessionStorage
- Storing any PII client-side
- Cookies missing the `HttpOnly` and `Secure` flags, or not using the `SameSite` attribute to mitigate CSRF attacks

## Access to third-party integrations

### OAuth
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

### SAML
When integrating with SAML providers, the following findings are red flags:
- SP silently accepts SAML unsigned assertions: validates only if signature is present
- SP extracts x509 embedded certificate directly from the SAML assertion -> may be self-signed
- Using outdated XML libraries or parsers that may be vulnerable to XML External Entity (XXE) attacks.
- Not validating the `AudienceRestriction`, `Recipient`, `NotBefore`, and `NotOnOrAfter` attributes in the SAML assertion
- Insecure HTTP bindigs or unencrypted assertions (e.g., accepting assertions via `HTTP-REDIRECT`)

## Input Validation and Sanitization

## Error Handling and Logging

## Cryptography

## Object storage
### Common
- **Enable server-side encryption**: Ensure that all objects stored in the object storage are encrypted at rest using strong encryption algorithms (e.g., AES-256)
- **Implement access controls**: Use bucket policies, IAM roles, and ACLs to restrict access to the object storage
- **Enable logging and monitoring**: Keep track of access and modifications to the object storage for auditing and security purposes
- **Disable public access**: Ensure that the object storage is not publicly accessible unless explicitly required for specific use cases

Prefer organization wide default bucket policies.

### Resource sharing
If the application purposefully shares resources from object storage via public URLs, include at least the following:
1. Use cryptographically signed URLs signed by the server

Good example:
```
https://my-bucket.s3.amazonaws.com/private/invoice-<uuid>.pdf
  ?X-Amz-Algorithm=AWS4-HMAC-SHA256
  &X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20260908%2Fus-east-1%2Fs3%2Faws4_request
  &X-Amz-Date=20260908T140000Z
  &X-Amz-Expires=3600
  &X-Amz-SignedHeaders=host
  &X-Amz-Signature=9f8c7d3e2a1b...c4d5e6f7 
```

Bad example:
```
https://my-bucket.s3.amazonaws.com/private/invoice-1234.pdf
```

2. Set TTL or time-based expiration to limit visibility window
3. URL should not be publicly accessible without proper authorization
4. Signing **does not mean** encryption -> still visible to anyone who has the signed link

## Framework specifics
There will be differences between different frameworks, and those configurations are important to understand to properly secure applications built on top of them.

## Multi-tenancy
Once multiple organization start to use the same application, it becomes crucial to implement proper isolation and access controls to ensure that data and resources are securely separated between tenants. You should:
- Add database row-level security, schema isolation or complete database isolation
- Add tenant specific access controls to application code (prefer defense-in-depth approach)

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
After gathering all the potential security findings, document them clearly, and provide remediation recommendation. Output the findings and create a report `security-code-review.md` inside the `artefacts/` folder. Iterature through each finding and provide at least the following:
- Name of vulnerability or issue (if directly applicable - e.g., SQL Injection)
- Severity or risk level of the finding based on `risk-classification.md` reference
- Description of the finding 
- File path and code line number (if applicable)
- Remediation recommendation (**Do not proceed with the remediation without user approval**)

## Common Rationalizations
| Rationalization | Reality |
|---|---|
| "" |  |

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
- [ ] 