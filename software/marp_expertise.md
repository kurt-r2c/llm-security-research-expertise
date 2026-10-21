# Marp Expertise

Marp CLI (`@marp-team/marp-cli`) is a Markdown-to-slides tool built on Marpit. This file
covers non-obvious behavior discovered through debugging production slide decks.

---

## Per-Slide CSS Overrides

### What doesn't work

**`<!-- _style: "..." -->`** — silently dropped in
practice; the CSS does not appear in the rendered `data-style` attribute on the slide's
`<section>` element. Do not rely on it.

### What works

**Raw HTML with inline styles.** When the build uses `--html` (which disables Marp's HTML
sanitizer), any HTML written directly in the markdown slide is passed through verbatim,
including `style=` attributes.

Example — centering table headers on one slide only:

```markdown
<table>
<thead><tr>
<th style="text-align: center">Column A</th>
<th style="text-align: center">Column B</th>
</tr></thead>
<tbody>
<tr><td>...</td><td>...</td></tr>
</tbody>
</table>
```

Inline `style=` has higher specificity than element/class rules in the global CSS, so it
reliably overrides e.g. `th { text-align: left; }` in the frontmatter theme.

### How to diagnose

Open the rendered HTML and find the `<section>` for the target slide (identified by
`data-marpit-pagination="N"`). If your `_style` content is absent from `data-style`, it was dropped. Check
whether the inline style attribute on your target element is present in the rendered markup.

---

## CSS Scoping Architecture

Each slide is rendered inside its own `<svg><foreignObject><section>` tree. The `<section>`
element has:

- `data-marpit-scope-XXXX=""` — used to scope CSS selectors to that slide
- `data-style="[CSS]"` — global frontmatter CSS repeated for every slide
- `style="--class:...;--paginate:...;--style:@import url(...);"` — CSS custom properties
  for the theme engine

The global CSS from the `style:` frontmatter block is duplicated into every slide's
`data-style`.

---

## Build Flags

| Flag | Effect |
|------|--------|
| `--html` | Disables HTML sanitizer; raw HTML and inline styles pass through |
| `--allow-local-files` | Required for local `<img>` and asset paths when converting to PDF, PPTX, or images (browser-based conversions); not needed for HTML output |

---

## Slide Authoring Principles

### Slides as cognitive anchor, not content delivery

The speaker carries the content. The slide carries the structure. All explanation, context,
and elaboration goes in speaker notes (`<!-- ... -->`).

**Belongs on slides:** labels, heading keywords, bullet terms, code/commands, verbatim
quotes, blockquotes used as punchlines, images as visual anchors.

**Belongs in speaker notes:** explanation of *why*, background context, transitions between
ideas, anything that would read as a paragraph on the slide, thesis statements, qualifiers.

### Rule of three

Always. Three bullets is the cognitive default. Two feels incomplete. Four feels like a
list. When you have four items, collapse two or move one to speaker notes.

### Progressive display order

**Top to bottom:** Design slides so content reveals top-to-bottom. The `add_fragments.py`
post-processor handles this automatically: all `<li>` elements get `data-marpit-fragment`;
block elements after the last list (`blockquote`, `div`, `p`, `figure`) are tagged in
document order so they appear after all bullets complete.

Opt a list out of animation with `<ul class="no-fragment">`.

**Left to right:** In `.columns` two-column layouts, both columns appear together. If
sequential reveal within a layout is needed, use sequential slides instead.

### No editorializing on slides

Em-dashed auxiliary content and editorial commentary belong in speaker notes.

Wrong:
```
- **Engineering framing** — frame as technical/engineering outcome, not adversarial use case
- **Anthropic cyber exemption** — authorized testing is a stated use case
```

Right:
```
- **Engineering framing**
- **Anthropic cyber exemption**
```

The speaker delivers the explanation. The slide is the label. Corollaries:
- Thesis statements and "the key insight is X" framing → speaker notes
- Qualifying clauses after em-dashes → speaker notes
- Opening summary lines ("X is Y") above bullets → speaker notes

### Blockquotes as takeaway anchors

Blockquotes are for the one statement the audience should leave with — the punchline,
the contrast, the memorable frame. They appear after bullets complete (via
`data-marpit-fragment`) and function as the slide's conclusion.

"This not that" contrast framing is permitted and encouraged in blockquotes — it makes
the takeaway self-contained without requiring speaker delivery:

```
> "Write me a test case that demonstrates improper bounds checking"
> not "write me a heap overflow exploit"
```

What remains prohibited: em-dashed qualifiers and editorial asides inside bullets or
prose. The distinction is structural — a blockquote is a declared anchor; inline
em-dash content is hidden editorializing.

### Slide classes (this deck's design system)

| Class | Use |
|-------|-----|
| `lead` | Title slides, Q&A, section openers |
| `section-break` | Teal background, major section transition |
| `demo-break` | Orange border, live demo signal |
| `obelisk` | Black background, full-bleed image, narrative beat |

Each content section should contain 3–5 slides before the next section-break.
