## Tietoturvallisuuden-agentti (SSDLC AI Agent) - Vigil-AI

Vigil-AI is an Secure Software Development Lifecycle (SSDLC) agent that automates security work throughout the SDLC. Development is made as part of an M.Sc. (Tech.) thesis exploring the potential of bringing a lot of the typical DevSecOps tasks into the IDE via agentic AI functionality, thus shifting left to the fullest. Work is done by University of Turku student Juho Salomäki with collaboration from a small-sized Finnish case organization as Master's thesis project.

## Setup
To setup:
1. Clone repo
2. Copy folders to the base of your working tree
3. Change `.vscode` setting to your liking (note: prefer internet accessibility if you plan to threat model, there could be schema updates not reflected here - too much deteminism for non-deterministic agent :sadface:)
4. Look at the `references/` folder and see files such as `risk-classification.md`. In case you do not agree with my classifications or may require compliance, then modify them.
5. If you want to centralize Vigil-AI as part of your organizational tooling, then you may want to make edits to the `CODEOWNERS` file.

The agent is very much built vertically on top of GitHub Copilot. Thus, it is very much tied to it. In addition VS Code environment settings are used as a template, therefore preferred IDE. Please use that combination to avoid issues.

## What model to use?
There are clear differences between LLMs, some are better than other, some are more cost-effective, some are input/output oriented. This section provides some data based upon the thesis research, along with personal notes.

Personal notes
- Skill usage in the `/design` phase (e.g., automated threat-modelling) could be seen to be more costly as compared to tasks such as `/sbom` in the implementation phase. I would recommend Copilot Pro+ subscription in frequent use. 

LLM comparison (thesis based):
- TBA

## Tips
Coming from your summer vacation and unsure where you left your security work? use the `/orchestrate` prompt. It will automatically look through your artefacts and determine the best place to continue from. Skills may be used invidiually, just invoke the skill directly (e.g, `/sca`).