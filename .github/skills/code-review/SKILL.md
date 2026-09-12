---
name: code-review
description: Facilitate and manage the process of reviewing code within the SSDLC agent. Create pull requests with Copilot reviewer to development branch and manage state of automatic code reviews for the agent.
metadata:
  author: Juho Salomäki
  version: "0.1.0"
---

## When to Use
- User has finished all tasks within the `implementation` phase until the code review phase according to the SSDLC policy process, has been asked for their consent, and is ready to have their code reviewed automatically by the Copilot reviewer.
## When Not to Use
- User has not completed all previous phases leading up to the code review phase.
- User prefers manual code reviews over automatic reviews by the Copilot reviewer.
- User has not been asked whether they want to proceed with an automatic code review by the Copilot reviewer - always ask before initiating GitHub pull requests.

## Preconditions
- User has completed all tasks within the `implementation` phase according to the SSDLC policy process `ssdlc-policy.md` found in `references/`.
- User has been asked for their consent to proceed with an automatic code review by the Copilot reviewer.

## Process
In each step of the process, **ensure that the user has consented to proceed with each action** related to the automatic code review by the Copilot reviewer. Interacting with user's personal GitHub account should always be done with explicit consent and **you should act with extreme caution**. **Any destructive operations are not allowed.**

1. Confirm that the user has consented to proceed with an automatic code review by the Copilot reviewer.
2. Create a pull request pointing to the development branch with the Copilot reviewer as the assignee. If branch does not exist, create it first before opening the pull request.
  - If repository has only one branch (e.g., `main`), create the pull request against that branch instead of the development branch.
  - If repository has multiple branches such as `main` and `development`, create the pull request against the development branch unless otherwise specified by the user.
  - Corresponding naming conventions for development branch may be `develop`, `dev` or something in local language. **Never create pull request against a production branch, unless there is only one deployment branch available and thus trunk-based development is being used.**. **When in doubt, always ask the user for clarification before proceeding.**
  - Prefer Copilot reviewer's "balanced" mode by default unless the user specifies otherwise.
3. Monitor the pull request for any comments or requested changes from the Copilot reviewer and notify the user accordingly.
4. Fix the Copilot reviewer's comments and requested changes in the pull request. Consider whether the changes align with the project's coding standards and guidelines before committing them. Update the pull request accordingly.
5. Once the pull request is approved by the Copilot reviewer, write `signoff.md` file to `artefacts/` indicating that the code review has been completed and approved. **DO NOT MERGE THE PULL REQUEST - USER WILL MERGE IT MANUALLY WHEN READY**
  - `artefacts/signoff.md` should contain a clear statement that the code review has been completed and approved by the Copilot reviewer. It should contain timestamp, Copilot reviewer mode, and fixed issues. Also, add potential open questions, if any.

## Common Rationalizations
| Rationalization | Reality |
|---|---|
| "I cannot find development branch, I will create it first before opening the pull request" | Never ever create any branches other than feature branch, when in doubt you should prompt and ask user for clarification |
| "Fixing code review issues seems like a developer task, not a security one" | Code review is a step part of an overall security and quality assurance process, and addressing the issues is crucial for maintaining code quality and security standards. |

## Red flags
- Creating a branch other than feature branch
- Interacting with user's personal GitHub MCP without user consent
- Merging the pull request - user will do manually when ready

## Verification
- After completing orchestration, confirm that:
- [ ] `signoff.md` file has been written to `artefacts/` indicating that the code review has been completed and approved.