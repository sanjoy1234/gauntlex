# Demo video build pipeline

Source for `docs/media/GAUNTLEX_Demo.mp4` (v3, 2026-07-12). Each scene is a static
1600x900 composite: the left ~1197px is a real terminal/browser screenshot, the
right ~403px is an HTML-rendered sidebar panel (`panels/scene_NN.html`, generated
by `gen_panels.py`), joined with a 4px blue left border baked into the panel.
`scene_00_title.html` and `scene_99_closing.html` are full-bleed, no screenshot.

## Rebuilding a scene

1. Crop the left portion from the source screenshot (terminal/browser capture) at
   x=0..1197, y=0..900.
2. Edit the copy in `gen_panels.py` (or the standalone `scene_09b_enterprise.html`
   for the Enterprise Features scene) and re-render via headless Chrome at
   403x900.
3. Composite left + panel into a 1600x900 PNG.
4. Apply a Ken Burns zoom via ffmpeg's `zoompan` filter (slow zoom to ~1.08x over
   the clip duration), output 1280x720.
5. Concatenate all clips in order via `ffmpeg -f concat`.

No audio track. Scene order and counters ("NN / 13"): title (unnumbered) → Setup
(model) → Setup (business intent) → Core Engine → Findings → The Gate → Tracking
→ Compliance → No Mercy → Dashboard → **Enterprise** → Architecture → Range →
Integrations → closing (unnumbered).

Copy standards applied throughout (see repo history / commit messages for the
full rationale): outcome-driven over process-descriptive, enterprise/industry
vocabulary (CI pipeline, PR gate, audit trail — not vague "before it ships"),
and verified accuracy against the actual codebase before making any claim
(e.g. compliance-framework mapping checked against
`src/gauntlex/output/report.py`'s `CONTROL_MAPPINGS`).
