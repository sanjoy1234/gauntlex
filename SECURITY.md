# Security Policy

GAUNTLEX is a security-testing tool, so vulnerabilities in it specifically matter — please report them responsibly.

## Reporting a vulnerability

**Preferred:** use GitHub's private vulnerability reporting — go to the [Security tab](https://github.com/sanjoy1234/gauntlex/security) and click "Report a vulnerability." This opens a private advisory only visible to the maintainer until a fix is ready.

**Fallback:** email sanjoy.sghosh@yahoo.co.in with a clear description, reproduction steps, and impact assessment. Please don't open a public issue for a security report.

## What to expect

- Acknowledgment within a few days.
- An assessment of severity and, where applicable, a CWE classification — consistent with how GAUNTLEX itself classifies findings.
- Coordinated disclosure once a fix is available. Credit given if you'd like it.

## Supported versions

The latest release on [PyPI](https://pypi.org/project/gauntlex-ai/) is the only version receiving security fixes. There is no long-term support branch at this stage of the project.

## Scope

In scope: the GAUNTLEX CLI, MCP server, dashboard, and the core engine (`src/gauntlex/`). Vulnerabilities in third-party dependencies should be reported upstream, though flagging them here is welcome too — GAUNTLEX's own dependency posture is part of its own attack surface.
