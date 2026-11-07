# UI styling

How the web UI is styled, so new pages look like the rest in both light and
dark mode. Everything is in `internal/server/web/style.css` (one file) and
the templates beside it.

## Ground rules

- **No JavaScript, no third-party assets.** The CSP allows only
  `/static/style.css`. Anything interactive is a link, a GET form, a POST
  form with the CSRF field, `<details>`, or CSS (`:has()`, `:checked`).
- **Use the palette variables, never a raw colour.** A hex value in a rule
  is right in one mode and wrong in the other. If no variable fits, add
  one to the palette (both values) rather than hard-coding it.
- **Reuse the existing components** (below) before writing new CSS. When
  you do add some, put it next to the component it belongs with and give
  it a one-line comment saying what it's for.
- The stylesheet is linked as `style.css?v=<hash of the file>`, so phones
  pick up changes on the next load; nothing to bump by hand.

## Light and dark

One palette in `:root`, each colour written as `light-dark(<light>, <dark>)`:

```css
:root{color-scheme:light dark; --bg:light-dark(#f7f6fb,#1f1d2b); ...}
:root[data-theme=light]{color-scheme:light}
:root[data-theme=dark]{color-scheme:dark}
```

`light-dark()` picks by `color-scheme`. By default that follows the device
(**System**). **Settings → Appearance** stores Light or Dark in a
per-browser cookie (`__Host-keydrop-theme`, or `keydrop-theme` without
TLS); `layout.html` then sets `data-theme` on `<html>` and the
`color-scheme` meta tag, which pins it. System deletes the cookie. Nothing
else in the CSS knows which mode is on, and nothing should: write rules
against the variables and both modes follow.

| Variable | Use |
|---|---|
| `--bg` | Page background; also input fields |
| `--card` | Panels: `.card`, `.group`, `.list`, phone tab bar |
| `--fg`, `--muted` | Body text, secondary text (`.muted`, `small`, `dt`) |
| `--line`, `--line-soft` | Panel borders; dividers inside a panel |
| `--hover` | Row hover, group headers, secondary-button hover |
| `--side`, `--side-fg`, `--side-on` | Sidebar / phone top bar, its links, the active or hovered link |
| `--accent`, `--on-accent` | Primary button fill and its text |
| `--accent-fg`, `--accent-soft` | Links and accented text; light accent fills (badges, focus ring) |
| `--ok`, `--warn`, `--bad` (+ `-soft`) | Status text and its pill background |
| `--attn-bg`, `--attn-fg` | The "needs you" banner |
| `--lift` | Panel shadow (see below) |
| `--c` | The current group colour, set by `.color-<name>` |

**Dark mode is not black.** The background is a slate violet (`#1f1d2b`)
and panels sit a step lighter (`#2b2839`) with visible borders (`#45405a`).
The earlier near-black palette read as one merged black panel. Keep that
contrast between `--bg`, `--card` and `--line` if you change any of them.

**Panels lift.** `.card`, `.group` and `.list` use
`box-shadow:var(--lift)`: a faint drop shadow in light mode, and a darker
shadow plus a 1px top highlight in dark mode, so panels stand off the
page. New panel-like containers should use `--card`, a `--line` border,
`--lift` and a 14px radius.

**Soft fills in dark mode are translucent** (`rgba(...)` over the card)
rather than solid tints, so pills and banners keep working on any
background. Light mode uses solid pale tints.

**Group colours** (`.color-red` … `.color-pink`) set `--c` to one value
that reads on both backgrounds; use `var(--c)` for swatches, the icon and
the coloured group name.

## Components

| Class | What |
|---|---|
| `.top` with `h1` | Page title row; buttons on the right (`.button`, `+ New`/`+ Add`) |
| `.lead` | Muted intro paragraph under the title |
| `.back` | "← Back" link above a title |
| `.card` (`.danger`, `.flush`, `.g`) | General panel; red border; no padding; group-colour left edge |
| `.group` > `.gh` + `.erow` | Secrets list: a group card, its header, its rows |
| `.list` | Plain list of links in a panel (agents, groups) |
| `button` / `.button` | Primary. Add `.secondary` (outline), `.danger`, `.small`, `.link` |
| `.actions` | Row of buttons under a form; full width on phones |
| `.seg` | Segmented choice: the current option `class="on small"`, others `secondary small` |
| `.chip`, `.badge`, `.st.new/.soon/.bad/.ok` | Outline chip; status pills |
| `.flash`, `.error`, `.attn` | Success message, error message, attention banner |
| `.filters`, `.pager` | GET filter form and prev/next links (Log page) |
| `details.more` | "More options" disclosure |
| `dl` | Label/value pairs (Settings, agent page); stacks on phones |

Icons are inline SVG from the sprite in `layout.html` (`<svg class="ic">`),
16px, coloured by `currentColor`. No emoji.

## Phones (`max-width:700px`)

The sidebar becomes a top bar (`.mtop`) and a bottom tab bar (`.tabs`).
The page is an app frame: the body doesn't scroll, `main` does. The long
comment in that media block explains the tab-bar placement and the
padding; read it before touching either, since each part fixed a real
phone bug. Buttons in `.actions` go full width, and inputs are 16px so
iOS doesn't zoom.

## Checking a change

Look at every page you touched in **both** modes and at phone and desktop
widths. Playwright can do it headless: a browser context with
`color_scheme="dark"` (or `"light"`) shows System mode, and the Appearance
setting covers the pinned modes. A computed `background-color` on `body`
of `rgb(31, 29, 43)` confirms dark is active.
