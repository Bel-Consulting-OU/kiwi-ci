# Kiwi CI visual identity

Source of truth: [Kiwi_CI_Visual_Identity.pdf](Kiwi_CI_Visual_Identity.pdf)
(11 Oct 2026 · baseline `d00ede206f`).

**The logo is the selected artwork from that document.** The PNG marks in
`assets/` are extracted from the identity PDF pages (lockups and bird on
pages 1 and 8). Do not redraw, retype, or “improve” the silhouette or
wordmark. Color and type rules below are the implementation values from
the same document.

**Primary descriptor:** Execution, with evidence.  
**Campaign line:** Run. Record. Verify.

In prose and first references, write **Kiwi CI**. Use the bird alone only
when the product name is already clear.

## Palette

| Token | Hex | Role |
|-------|-----|------|
| Ink | `#08110C` | Primary dark ground; text on light surfaces |
| Forest | `#143D2B` | Light-theme emphasis; secondary dark panels |
| Kiwi | `#68DC93` | Brand accent; dark-theme mark; selected actions |
| Paper | `#F3F5EF` | Light-theme ground; dark-theme primary text |
| Sage | `#92AA99` | Secondary information on dark surfaces |

| Pair | Contrast | Use |
|------|----------|-----|
| Paper on Ink | 17.45:1 | Primary text on dark backgrounds |
| Kiwi on Ink | 11.18:1 | Brand accents and dark-theme labels |
| Sage on Ink | 7.69:1 | Secondary dark-theme metadata |
| Forest on Paper | 11.04:1 | Secondary text / emphasis in light theme |
| Kiwi / Sage on Paper | 1.56:1 / 2.27:1 | Decorative only — use Ink or Forest for normal text |

Normal interface text targets ≥ 4.5:1; large text and required graphical
controls ≥ 3:1. Color always needs a label or shape when it carries state.

Machine-readable tokens: [`assets/brand-tokens.json`](assets/brand-tokens.json) ·
CSS custom properties: [`assets/brand-tokens.css`](assets/brand-tokens.css).

## Typography

- **Inter** (400 / 600 / 700 / 800) — interface text and communication.
  Enable tabular figures for numerical tables.
- **IBM Plex Mono** (400 / 500) — commands, hashes, attempt identities,
  logs. Preserve exact characters and copyable values.

| Role | Size / line height | Weight |
|------|--------------------|--------|
| Marketing hero | 56 / 60 px (responsive) | 700–800 |
| Page / section title | 32 / 38 px; 24 / 30 px | 700 / 600 |
| Body / supporting label | 16 / 24 px; 13 / 18 px | 400 / 400–600 |
| Technical data and logs | 14 / 21 px | Mono 400–500 |

**Logo lettering is fixed artwork from the identity document.** Do not
recreate the wordmark by typing the name in the interface font.

## Layout rhythm

- 4 px subgrid, 8 px base rhythm
- Panel padding 16–24 px
- Radii 8–12 px
- Visible focus ring 2 px
- Interactive hit area ideally 44 × 44 px

## Mark rules

Artwork below is extracted from the identity PDF — use these files as-is.

| Asset | Path | Use |
|-------|------|-----|
| Symbol (Ink) | [`assets/logo-mark.png`](assets/logo-mark.png) | Light grounds |
| Symbol (Kiwi) | [`assets/logo-mark-kiwi.png`](assets/logo-mark-kiwi.png) | Dark grounds |
| Symbol (Paper) | [`assets/logo-mark-paper.png`](assets/logo-mark-paper.png) | Reverse on Ink/Forest |
| Symbol (black) | [`assets/logo-mark-black.png`](assets/logo-mark-black.png) | One-ink print |
| Lockup (Ink) | [`assets/logo-lockup.png`](assets/logo-lockup.png) | Primary horizontal lockup |
| Lockup (Kiwi) | [`assets/logo-lockup-dark.png`](assets/logo-lockup-dark.png) | Dark-theme lockup |
| Lockup (Paper) | [`assets/logo-lockup-paper.png`](assets/logo-lockup-paper.png) | Reverse lockup |
| Transparent overlays | `assets/logo-lockup-*-transparent.png` | Arbitrary grounds |
| Favicon / app icon | [`assets/favicon.png`](assets/favicon.png) · [32](assets/favicon-32.png) · [64](assets/favicon-64.png) | 16–48 px family |

- **Clear space:** let H be the bird’s height including feet. Leave ≥ H/4
  around the complete lockup. Keep internal spacing and proportions fixed.
- **Small sizes:** standard bird width ≥ 32 px; full lockup ≥ 160 px.
  A 16–24 px favicon uses the rounded-square master in `favicon.png`.
- **Prohibitions:** gradients, outlines, glow, busy photography, UI status
  symbols, animation of the decorative mark (supporting motion must
  respect `prefers-reduced-motion`).
- **Silhouette:** low solid body, short stable feet, one circular eye
  knockout, long probing beak. One fill only (Ink, Kiwi, Paper, or black).
  This geometry is the selected mark — do not redraw it.

## Secondary motif

Sparse orthogonal **execution-trace** lines sit *outside* the mark. A few
nodes suggest records and causality. Keep them decorative unless they
correspond to actual execution data.

## Voice and states

Prefer specific verbs: **Run pipeline**, **View evidence**, **Replay job**,
**Verify signature**. Use explicit `success` / `failure` / `queued` labels.

Keep these distinctions sharp:

- A **test result** is not evidence integrity. `Signature verified` and
  `tests passed` are two distinct results.
- **Requested** controls are separate from **effective** facts and
  **observed** receipts.
- **Recorded-job replay** re-executes recorded semantics and available
  snapshots; different external state can change resulting bytes.

## Audience notes

| Audience | What they need |
|----------|----------------|
| Developers | Warm, recognizable bird; simple language; clear entry points |
| Platform teams | Controlled hierarchy; durable navigation; readable status labels |
| Verification consumers | Exact metadata; explicit provenance; requested/effective/observed separation |

## Production finishing

The identity document’s production checklist still applies when the mark
is treated as a finished trademark: optional path-based vector masters
for print/EPS workflows, verification of the 16/24/32/48 px family at
actual size, clean alpha edges, and physical black-only print. Until
those exist, the PNG exports above are the canonical in-repo artwork and
must be used unchanged.

## Where the identity is applied

- Control-plane dashboard: `internal/server/web/` (tokens, lockup, status voice)
- CLI usage / help: `cmd/kiwi` (descriptor + campaign line)
- Product README: header descriptor and brand links
- Docker image labels: `Dockerfile`
- This brand kit: `docs/brand/`
