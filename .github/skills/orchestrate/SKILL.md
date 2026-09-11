---
name: orchestrate
description: Coordinate and manage the execution of various security tasks and processes within the SSDLC agent, ensuring that they are performed efficiently in correct order and according to defined policies and procedures.
metadata:
  author: Juho Salomäki
  version: "0.1.0"
---

## When to Use
- User has not interacted with the session for a while

## Execution
Identify the current state of the session and determine the appropriate next phase or skill to forward the user to based on `ssdlc-policy.md` gating logic and previous work done.

1. Read through `ssdlc-policy.md` in `references/` to understand the gating logic
2. Look though session memory to identify if any previous tasks or phases have been completed
3. Find `artefacts/` folder to check the current state of generated outputs and previous work done. If folder does not exist, ask if user wants to execute only a certain task or start over from the first phase
4. If `artefacts/` contains outputs from previous phases, determine the next appropriate phase or skill based on the gating logic in `ssdlc-policy.md`. **Continue from the phase you found the latest outputs for**, found only `sbom-results.json` -> continue from implement phase. You may suggest earlier phases as well, if missing.
5. Forward the user to the determined next phase or skill, ensuring that the transition aligns with the gating logic in `ssdlc-policy.md`. Output user your reasoning

## Common Rationalizations
| Rationalization | Reality |
|---|---|
| "I am unsure, will forward user to first phase" | When in doubt, ask clarifications from the user |

## Verification
- After completing orchestration, confirm that:
- [ ] User was forwarded to a specific phase and/or skill per `ssdlc-policy.md` gating logic. 
