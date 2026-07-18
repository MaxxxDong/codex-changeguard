# Windows 11 multi-identity fixture notes

Runtime tests under `tests/ticket14-windows11.test.ts` inject a temporary
Windows layout (MSIX alias, Desktop app, Desktop-bundled CLI, PATH CLI, WSL,
and multiple user profiles) via `systemCaps`. No real Windows host is required.

Platform support remains PREVIEW until a real-machine receipt covers W11-S01…S11.
