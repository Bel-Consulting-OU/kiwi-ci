# Kiwi CI visual identity

Source of truth: [Kiwi_CI_Visual_Identity.pdf](Kiwi_CI_Visual_Identity.pdf)
(11 Oct 2026 · baseline `d00ede206f`).

The logo is the selected artwork from that document. The PNG marks in
`assets/` are extracted from the identity PDF pages (lockups and bird on
pages 1 and 8). Do not redraw the silhouette. Do not retype the wordmark.
Color and type rules below are the implementation values from the same
document.

Primary descriptor: Execution, with evidence.

Campaign line: Run. Record. Verify.

In prose and first references, write Kiwi CI. Use the bird alone only
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
| Forest on Paper | 11.04:1 | Secondary text and emphasis in light theme |
| Kiwi / Sage on Paper | 1.56:1 / 2.27:1 | Decorative only; use Ink or Forest for normal text |

Normal interface text targets at least 4.5:1. Large text and required
graphical controls target at least 3:1. Color always needs a label or
shape when it carries state.

Machine-readable tokens: [`assets/brand-tokens.json`](assets/brand-tokens.json).
CSS custom properties: [`assets/brand-tokens.css`](assets/brand-tokens.css).

## Typography

- Inter (400 / 600 / 700 / 800) for interface text and communication.
  Enable tabular figures for numerical tables.

- IBM Plex Mono (400 / 500) for commands, hashes, attempt identities, and
  logs. Preserve exact characters and copyable values.

| Role | Size / line height | Weight |
|------|--------------------|--------|
| Marketing hero | 56 / 60 px (responsive) | 700–800 |
| Page / section title | 32 / 38 px; 24 / 30 px | 700 / 600 |
| Body / supporting label | 16 / 24 px; 13 / 18 px | 400 / 400–600 |
| Technical data and logs | 14 / 21 px | Mono 400–500 |

Logo lettering is fixed artwork from the identity document. Do not
recreate the wordmark by typing the name in the interface font.

## Layout rhythm

- 4 px subgrid, 8 px base rhythm

- Panel padding 16–24 px

- Radii 8–12 px

- Visible focus ring 2 px

- Interactive hit area ideally 44 × 44 px

## Mark rules

Artwork below is extracted from the identity PDF. Use these files as-is.

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
| Favicon / app icon | [`assets/favicon.png`](assets/favicon.png) | 16–48 px family ([32](assets/favicon-32.png), [64](assets/favicon-64.png)) |
| GitHub social preview | [`assets/github-social-preview.png`](assets/github-social-preview.png) | Repository social image |
| README hero | [`assets/readme-hero.png`](assets/readme-hero.png) | Optional light-ground header card |

Clear space: let H be the bird height including feet. Leave at least H/4
around the complete lockup. Keep internal spacing and proportions fixed.

Small sizes: standard bird width at least 32 px. Full lockup at least
160 px. A 16–24 px favicon uses the rounded-square master in `favicon.png`.

Prohibitions: gradients, outlines, glow, busy photography, UI status
symbols, and animation of the decorative mark. Supporting motion must
respect `prefers-reduced-motion`.

Silhouette: low solid body, short stable feet, one circular eye knockout,
long probing beak. One fill only (Ink, Kiwi, Paper, or black). This
geometry is the selected mark. Do not redraw it.

## Secondary motif

Sparse orthogonal execution-trace lines sit outside the mark. A few nodes
suggest records and causality. Keep them decorative unless they
correspond to actual execution data.

## Voice and states

Prefer specific verbs: Run pipeline, View evidence, Replay job, Verify
signature. Use explicit `success`, `failure`, and `queued` labels.

Keep these distinctions sharp.

- A test result is not evidence integrity. `Signature verified` and
  `tests passed` are two distinct results.

- Requested controls are separate from effective facts and observed
  receipts.

- Recorded-job replay re-executes recorded semantics and available
  snapshots. Different external state can change resulting bytes.

## Audience notes

| Audience | What they need |
|----------|----------------|
| Developers | Warm, recognizable bird; simple language; clear entry points |
| Platform teams | Controlled hierarchy; durable navigation; readable status labels |
| Verification consumers | Exact metadata; explicit provenance; requested/effective/observed separation |

## Production finishing

The identity document's production checklist still applies when the mark
is treated as a finished trademark. Optional path-based vector masters
for print and EPS workflows should use the same geometry. Verify the
16/24/32/48 px family at actual size, clean alpha edges, and a physical
black-only print. Until those exist, the PNG exports above are the
canonical in-repo artwork and must be used unchanged.

## Where the identity is applied

- Control-plane dashboard: `internal/server/web/` (tokens, lockup, status voice)

- CLI usage and help: `cmd/kiwi` (descriptor and campaign line)

- Product README: lockup artwork, descriptor, and campaign line

- Docker image labels: `Dockerfile`

- GitHub: issue and PR templates, `ISSUE_TEMPLATE/config.yml` voice, and
  social preview. Upload `assets/github-social-preview.png` (also at
  `.github/social-preview.png`) in repo Settings, General, Social preview.

- This brand kit: `docs/brand/`
