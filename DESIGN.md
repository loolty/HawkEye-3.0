# HawkEye Optical Clinic: design system

Surfaces: patient portal, staff portal, sign-in/sign-up, landing. All share `static/css/tokens.css` (tokens) and `static/css/style.css` (components).

## Idea
The brand is a red hawk. The old UI ignored it and used generic blue SaaS. Now: neutral, flat, quiet surfaces; the hawk red is the action and "you are here" colour; the eye chart (landing, patient sign-in) and the prescription slip (patient Rx page) are the product's own motifs.

## Tokens (three layers)
1. Primitives: `--ink-*` cool slate, `--hawk-*` red sampled from the logo (#ed2b20), status greens/ambers, a fixed type scale, a 4px space scale, two radii (6 controls, 10 panels).
2. Semantic (swapped by `data-theme`): `--canvas --surface --surface-2 --sunken --line --text --text-2 --accent --on-accent --ok --warn --bad`.
3. Component rules live in `style.css` next to the component.

Light primary button #c8231a on white = 5.7:1. Dark theme uses #ff6a5f with ink text.

## Rules
- One typeface: Instrument Sans (self-hosted in `static/fonts`, OFL), weights 400 and 700 only. Patient pages run at 17px, staff at 15px.
- Red is used for: primary action, selected day, current nav marker, unread badge, focus ring. Not for decoration.
- Status = dot + word (`.badge`), never a filled pill. Cancelled/Rejected are hollow dots.
- Elevation is a 1px `--line` border or a tone step. No shadows at rest, no gradients, no glow.
- Tables: header text in the secondary colour with one rule under it, no banding, tabular figures. Only the one decision per row is a filled button; other row actions are quiet text.
- KPIs are numbers set as type in one panel, not tiles. Page titles are 28px (staff) / 40px (patient).
- Icons: one stroke set (1.75px) in `templates/_icons.html`, used with `<svg class="icon"><use href="#i-name"/></svg>`.
- No eyebrows, no 01/02/03 step chips, no emoji, no glyph icons in tinted squares.

## Files
- `static/css/tokens.css`, `style.css`, `chat.css`
- `templates/_brand.html` (lockup), `_icons.html` (sprite), `_macros.html` (date helpers)
- `base_staff.html` (sidebar, active state from `request.endpoint`), `base_patient.html` (top bar + tabs)
