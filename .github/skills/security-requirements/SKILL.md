---
name: security-requirements
description: Create security objectives and specifications before starting development. Elicit security requirements from the developer and update them as necessary throughout the development process.
metadata:
  author: Juho Salomäki
  version: "0.1.0"
---

## When to Use
- Starting a new software project or feature and the change affects multiple files, codebases, architectural changes, or introduces new dependencies/integrations.
- Security requirements do not exist yet for the project or are outdated/ambiguous.

## When NOT to use
- Minor updates such as single line code changes that do not affect security requirements

## Step 0: Identify potential compliance and scope down to correct guidelines
Interview the user for a high-level understanding of potential changes and identify relevant compliance requirements and security guidelines.

1. Ask the user about the scope of the changes and any new dependencies or integrations being introduced.
  - Identify all the relevant guidelines and compliance requirements that apply to the changes. For example:
    - User states that they are integrating a new cloud service, identify the relevant best practice guidelines that should apply (e.g., AWS Best Practices, Azure Security Best Practices, CIS Controls). 
    - User is developing a new feature into an existing web application, identify related security guidelines and best practices (e.g., OWASP Top Ten, OWASP ASVS, OWASP best practices).
    - User is developing a mobile application, identify related security guidelines and best practices (e.g., OWASP Mobile Top Ten, OWASP MASVS, platform-specific security best practices).
2. Identify potential compliance requirements
  - Ask the user about any regulatory requirements that the project must adhere to (e.g., GDPR, HIPAA, PCI-DSS).
  - Analyse the potential compliance requirements user may be not aware of and interview the possibility. For example:
    - User is handling personal data and located in EU, consider potential GDPR implications.
    - User is processing payment information, consider potential PCI-DSS requirements.
    - User is building for a public sector client (potential local government regulations).
    - User is building a product for a company (e.g., EU CRA/CSA, ISO 27001).
    - Does the user use any API/integration with their own internal policy for granting usage rights? (e.g., certain logging requirements) 
  - Determine if there are any industry-specific standards that need to be considered (e.g., ISO 27001, NIST Cybersecurity Framework).

## Step 1: Interview further
Now that high-level guidelines/frameworks are noted, start analysing the specific section that should be followed. Conduct a more detailed interview with the user to gather specific security requirements and constraints for the project. Many of the requirements you can already determine from the high-level analysis itself. However, ask follow-up questions to clarify any ambiguities or assumptions when needed. Ask in specifity, if applicable to the feature, for example:
- Will there be any sensitive data handled by the feature (e.g., personal data, payment information)?
- Are you integrating any third-party services or libraries?
- Have you planned any logging or monitoring for security events?
- Do you have internal breach response procedures in place that should be also considered in the technical design?

Out of the answers gathered during the interview, identify the specific security requirements and constraints that need to be addressed in the developed changes.

## Specify the Security Requirements
After conducted interviews, document the specific security requirements and constraints identified for the upcoming changes.

### Rules
- **Always surface assumptions**: Clearly document any assumptions made during the requirement gathering and analysis process and tell them to the user. The whole point is to surface potential security related misunderstandings and ensure they are addressed appropriately.

### Format
Document the security requirements and constraints in the following format:

```markdown
# Security Specification: [Change name]

## Quick summary
[What we're building and why.]

## Tech Stack
[Framework, language, key dependencies with versions]

## Compliance mapping
[Specific requirements derived from security standards, guidelines, regulations, best practices and internal policies. Follow format SR-001 [title], SR-002 [title], etc.]

## Potential key security issues
[Example snippet + key conventions]

## Quick wins
[Examples of quick security improvements that will have tremendous impact.]

## Best mitigation strategies
[Examples of high-level connected strategies to mitigate the identified security issues.]

## Testing strategies
[Specific tests, methodologies, and tools to verify the security requirements and mitigations.]

## Success Criteria
[Specific criteria for how to know this is done]

## Open Questions
[Anything unresolved issues which may require human input]
```

## Common Rationalizations
| Rationalization | Reality |
|---|---|
| "The spec is redundant, I can memorize issues as they come" | "Your context will reset at some point due to technical limitations, spec makes sure every agent instance has the necessary context." |
| "Security requirements slow down development" | "Addressing security early prevents costly fixes and vulnerabilities later." |
| "We can handle security issues as they arise" | "Proactive security planning reduces the risk of critical vulnerabilities and ensures compliance." |
| "Security requirements are someone else's responsibility" | "Everyone involved in the development process shares responsibility for security, and early involvement prevents gaps." |

## Red Flags
- The `SEC-SPEC.md` in `artefacts/` folder is empty or missing
- Starting to create specification before throughouly interviewing the user and analysing requirements

## Verification
After completing the decomposition confirm that:
- [ ] Artefact `SEC-SPEC.md` exists in `artefacts/` folder
- [ ] Artefact `SEC-SPEC.md` contains all identified security requirements and constraints and is not empty