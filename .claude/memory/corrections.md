# Corrections log

Conventions and facts that a maintainer has had to correct an AI agent on, and that `AGENTS.md` doesn't already cover. Every agent should read this before starting work (see *Agent resources* in `AGENTS.md`).

**Adding an entry:** when a maintainer corrects you on something not covered here or in `AGENTS.md`, append an entry in the same PR, newest first, in this shape:

```
## YYYY-MM-DD — <area>: <one-line rule>
<What the agent got wrong, and the correct behaviour.>
**Why:** <the mechanism or reason, so the rule can be applied to cases it doesn't name>
**Source:** <issue / PR / commit, if any>
```

**Keep it short:** if an entry applies broadly, promote it into `AGENTS.md` and delete it here. Delete entries that stop being true.

---

## 2026-09-28 — CI logs: `[ERROR]` lines from the UI build are not the failure
Maven prints `vite-plugin-svelte` compiler warnings (`state_referenced_locally`, `a11y_*`) and `npm warn EBADENGINE` as `[ERROR]` because they go to stderr. Grepping a failed CI log for `ERROR` surfaces pages of these and hides the real failure. Read the end of the log for the `Failed to execute goal` line, then search for `<<< FAILURE!`.
**Why:** a red build was nearly misdiagnosed as a Svelte problem when the actual failure was a launcher integration test.
**Source:** #2012, #2014

## 2026-09-28 — Async work: session-scoped beans must be settled on the request thread
Code that hands work to an executor thread (e.g. `AsyncQueryService`) and touches a session-scoped bean proxy (`thinQueryBean`, `olapQueryBean`, …) must obtain the session on the request thread before handing off. Propagating `RequestAttributes` alone isn't enough.
**Why:** once the HTTP request completes, Spring's `ServletRequestAttributes` can only create a session-scoped bean through an `HttpSession` it already cached. The failure ("Scope 'session' is not active for the current thread") is timing-dependent, so it passes locally and fails in CI.
**Source:** #2015, #2016

## 2026-09-15 — Merging: `gh pr merge` can silently do nothing
With a required check still pending, `gh pr merge` prints a "requirements not met" notice and leaves the PR open. After any merge, confirm it: `gh pr view <n> --json state` should say `MERGED`, and the base branch should have advanced. This matters most before tagging a release, where it once led to tagging the old commit.
**Why:** later steps (tagging, back-merges, deploys) otherwise run against the wrong commit.
**Source:** v4.6.x release; see `.claude/skills/cut-release/SKILL.md`

## 2026-08-16 — App Builder: chart-tile Sort and Top N work; don't "fix" the docs
Chart-tile **Sort categories** and **Top N** are applied client-side (`ChartTile.svelte` → `projectForChart()` in `$lib/dashboard/chartOptions.ts` → `applySortLimit()` from `$lib/charts/sortLimit`). The App Builder docs saying they're client-side, don't re-query, and persist with the tile are accurate.
**Why:** an older note claimed they were inert, and an agent nearly rewrote correct docs from it. Check the code before "correcting" docs.
**Source:** saiku#1797

## 2026-08 — Cube Designer: prefer host glue over editing shared components
The Cube/Schema Designer (`saiku-ui/src/lib/cube-designer/**`) is vendored into saiku-cloud too. Put OSS-specific behaviour in host glue (`oss-backend.ts`, the `routes/admin/cube-designer/` route). When a shared component must change, keep it portable so saiku-cloud can copy it verbatim, and change the `CubeDesignerBackend` seam only additively (new optional members).
**Why:** a change to a shared component that only works in OSS forks the two copies.
**Source:** saiku#1634

## 2026-08 — Local App Builder: "broken" tiles are usually configuration
On a local launcher, app tiles that all show a red "AI policy does not permit sending AGGREGATED_RESULT_VALUES" box mean the AI policy is at its default. Set `SAIKU_AI_POLICY=aggregated` (tiles query through the AI Query path). An empty app list on an existing `saiku-home` means the seed app wasn't staged: seed assets only stage on a fresh home, so copy `saiku-launcher/src/main/resources/seed/apps/foodmart-ops.saikuapp` into `saiku-home/repository/data/unknown/homes/admin/`.
**Why:** both look like application bugs and have sent agents debugging code that was fine.
