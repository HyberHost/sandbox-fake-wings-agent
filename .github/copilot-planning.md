# sandbox-fake-wings-agent — Project Plan

Last updated: 2025-12-19

Purpose
-------
This repository provides a fake Pterodactyl Wings-like agent for Windows that:
- Provisions and controls local S&Box server instances (create/install/start/stop).
- Exposes test-facing services (HTTPS & SFTP) that mimic real Wings/Panel interactions for integration testing.

Goals
-----
1. Provide a reliable local agent that can be controlled by a panel (fake or real) for testing workflows.
2. Implement an SFTP server that allows uploads/downloads for per-server files and maps to a per-server filesystem.
3. Implement a mock Wings API (HTTPS) that registers server state and accepts power/command requests.
4. Make the system easy to run locally for development and CI, and safe with respect to credential handling.

Milestones
----------
- M1: Planning doc (this file)
- M2: Robust SFTP server (paramiko) with per-server directories and credentials
- M3: Mock Wings API (Flask), HTTPS with test cert, endpoints for server lifecycle and commands
- M4: Integration wiring (API calling local scripts, SFTP mapping to server folders)
- M5: Tests + CI workflow, README and docs
- M6: Security review and operational notes (secrets handling, logs)

Initial Tasks (short-term)
--------------------------
- Create `.github/copilot-planning.md` (completed)
- Replace the temporary SFTP logger with a paramiko-based SFTP server listening on 2022
- Support server-specific credentials read from `C:\Servers\sbox-<id>\server.json` for realism
- Implement a Flask-based mock Wings on HTTPS port 8080 that logs requests and optionally calls `start_server.ps1`/`stop_server.ps1`
- Update `tmp/` scripts and `tmp/README.md` to run both services locally
- Add unit/integration tests and a GitHub Actions workflow to smoke-test these services

Design choices / Notes
----------------------
- SFTP: initial implementation will use username/password auth and per-server home directories. Later we can add public-key auth and more complex filesystem semantics.
- HTTPS: use the existing self-signed cert for `SBOX-GB-1.gameforge.gg` for local testing and document how to trust it in development environments.
- Secrets: Steam usernames/passwords and game tokens will not be persisted to server.json. `STEAM_LOGIN` can be read from envs for install/update steps only. We will document best practices for storing tokens in a real deployment.
- Safety: Use `pid_start_time` and `instance_token` to validate running processes to avoid killing recycled PIDs.

Acceptance criteria
-------------------
- SFTP server accepts connections and places files into `C:\Servers\sbox-<id>\files` for that server
- Mock Wings endpoints return expected JSON and can trigger start/stop operations on local server instances
- Tests that run in CI can start the mock services, exercise a power command, and verify state changes

Updating this plan
------------------
This document should be used to track high-level progress and will be updated as tasks are completed. For task-level tracking see the repository's TODOs and GitHub Issues.