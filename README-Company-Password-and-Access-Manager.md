# Company Password & Access Manager (CLI)

**Goal:** Manage employees, roles, resources, and credentials for a 20-person company. Enforce RBAC, rotate secrets, and produce audit/compliance reports. Python-only, local-first. Optional GUI is a stretch.

---

## Scope & Must‑Have Features
- Employees/roles/resources CRUD.
- Role → permission → resource mapping; per-employee grants & overrides.
- Credentials per resource (username, secret, rotation date, tags).
- Grant/revoke access; RBAC check on credential fetch (`--reveal` to show).
- Rotation workflows: mark rotated; report overdue by resource/owner dept.
- Full audit trail for all changes; export audit CSV.
- Encrypted vault at rest (master key unlock).
- Import/export JSON; backup/restore encrypted vault; soft-delete + undo.

## Core Entities (Data Model)
- **Employee**: id, name, dept, status
- **Role**: name, permissions[]
- **Resource**: id, name, type, owner_dept
- **Credential**: resource_id, username, secret(enc), rotation_date, tags[]
- **AccessGrant**: employee_id, role(s), resource_scope/overrides
- **AuditEvent**: ts, actor, action, entity, details

## Design Patterns (Required)
- **Strategy**: pluggable crypto providers; password generation policies.
- **Command**: each CLI action (add/update/delete/grant) with undo (soft delete restore).
- **Factory / Abstract Factory**: create storage backends (JSON / SQLite) & crypto provider.
- **Facade**: `AccessService` exposing `grant/check/revoke` over roles/permissions.
- **Observer**: event bus for audit & rotation reminders.

## Team Roles
- **Tech Lead** (only one to ask instructor questions): architecture, patterns map, delegation, reviews, CLI UX sign‑off.
- **Backend**: models/repos, encryption layer, RBAC checks, import/export.
- **Frontend/CLI**: `typer` commands, friendly help, masked output/`--reveal`, tables via `rich`.
- **Tester**: pytest fixtures (temp DB, sample data), tests for RBAC, rotations, audit/undo paths.

## Acceptance Criteria
- Unauthorized credential fetch is blocked with clear error; audit log records attempt.
- Rotation report lists overdue credentials; includes resource & owner dept.
- Import/export round‑trips without data loss (IDs preserved).
- Undo successfully restores soft‑deleted entities.

## Sample CLI
```bash
vault init --backend sqlite --path data/vault.db
vault employee add "Ava Pop" --dept Support
vault role add SupportAgent --perm read:vpn --perm read:ticketing
vault access grant --emp "Ava Pop" --role SupportAgent
vault resource add "VPN" --type network --owner IT
vault cred add "VPN" --username ava --generate
vault cred get "VPN" --emp "Ava Pop" --reveal
vault rotation report --overdue
vault audit export --out audit.csv
```

## Milestones (2 Weeks)
- **D1–2:** domain models, plaintext storage, CLI skeleton.
- **D3–5:** RBAC + encryption (Strategy/Factory).
- **D6–8:** Command/undo + Observer audit; rotation report.
- **D9–11:** import/export; polish; docs.
- **D12–14:** tests, packaging, demo.

## Stretch Goals
- Per‑resource password policies; TOTP; read‑only service accounts view.

---

## Common Stack & Layout
```
app/
  cli/                # Command pattern commands
  domain/             # Entities, value objects
  services/           # Facades (AccessService, RotationService)
  infra/              # Repos (Repository pattern), storage, crypto adapters
  rules/              # Strategy/Factory implementations
  events/             # Observer bus + handlers (audit, reminders)
  tests/              # Unit + scenario tests
```
