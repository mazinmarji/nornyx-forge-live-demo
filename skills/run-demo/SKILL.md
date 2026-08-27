---
name: run-demo
description: Launch and exercise the completed governed customer-operations application. The shipped `demo` path drives the stages with `run_sequential()` and reports `observed_execution_backend: sequential`; naming CrewAI unconditionally is true of the `build` path and false of the one this skill launches.
allowed-tools: Read, Glob, Grep, Bash
---

# Run live demo

Run deterministic validation first, launch the application, invoke both low-risk and high-risk cases, confirm the high-risk action is prevented in autonomous-demo mode, validate evidence, and report all URLs and limitations.
