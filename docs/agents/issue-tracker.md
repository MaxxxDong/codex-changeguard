# Issue Tracker: Local Markdown

Specifications and implementation tickets for this repository live as Markdown files under `.scratch/`.

## Conventions

- Use one directory per feature: `.scratch/<feature-slug>/`.
- Store the feature specification at `.scratch/<feature-slug>/spec.md`.
- Store each implementation ticket in its own file at `.scratch/<feature-slug>/issues/<NN>-<slug>.md`.
- Number tickets in dependency order, with blockers before the work they block.
- Record agent-ready work with a `Status: ready-for-agent` line near the top of each ticket.
- Append later discussion under a `## Comments` heading instead of rewriting the original acceptance criteria.

## Publishing From Engineering Skills

When an engineering skill says to publish a specification or ticket, create the corresponding Markdown file under `.scratch/<feature-slug>/`.

The tracker may be migrated to GitHub Issues after the repository receives separate publication authorization. Until then, local Markdown is the canonical tracker.
