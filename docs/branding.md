# distrorejuve branding

Use **distrorejuve** with this spelling. The tagline is **“Move your Linux server forward.”**
and the short description is “Linux release upgrades and migration checks.”

Three server-release stages rise from lower left to upper right and increase in size. A forward arrow represents progress through Linux releases and renewing an existing server.

## RimuHosting design system

The tool uses RimuHosting's brand colours and CartoGothic Std typography.
The banner follows the site's Warm Surface masthead style, with Warm Ink text,
a Bark edge, a small mono eyebrow and secondary RimuHosting attribution.
The official tree and wordmark retain their canonical logo colours.

| Token | Colour | Role |
| --- | --- | --- |
| `--rr-clr-brand-surface-warm` | `#F4EEDB` | Banner surface |
| `--rr-clr-brand-ink` | `#251D18` | Product name and description |
| `--rr-clr-brand-bark` | `#452008` | Tagline and top edge |
| `--rr-clr-brand-clay` | `#996444` | Tool symbol |
| `--rr-clr-brand-leaf` | `#88AA00` | Decorative status accents |
| `--rr-clr-brand-green-text` | `#587200` | Arrow or magnifier with contrast on light surfaces |
| `--rh-clr-clay-deep` | `#8A5A3C` | Small eyebrow and attribution text |
| `--rr-clr-brand-nav-tan` | `#BC9B85` | Tool symbol on dark surfaces only |
| `--rr-clr-brand-leaf-soft` | `#BFE369` | Arrow or magnifier on dark surfaces |

Leaf is decorative; it is not used for body text on light surfaces.
CartoGothic lettering is converted to paths so viewers need no installed fonts.
The standalone tool symbol is transparent and contains no embedded fonts or images.

## Assets

| File | Use |
| --- | --- |
| [SVG logo](../assets/branding/logo.svg) | Editable tool symbol on a transparent background. |
| [PNG logo](../assets/branding/logo.png) | 1024 × 1024 transparent export for avatars and presentations. |
| [Dark-surface SVG logo](../assets/branding/logo-dark.svg) | Navigation Tan and Leaf Soft variant for Bark or other dark backgrounds. |
| [Dark-surface PNG logo](../assets/branding/logo-dark.png) | 1024 × 1024 transparent export of the dark-surface variant. |
| [SVG README banner](../assets/branding/readme-banner.svg) | Editable 2172 × 724 artwork, including outlined brand typography and the company lockup. |
| [PNG README banner](../assets/branding/readme-banner.png) | README masthead with an opaque surface for either GitHub theme. |

Keep the symbol's proportions and clear space. Prefer at least 48 pixels for
the standalone logo. Use the banner when the name and tagline are needed.
Use `logo.svg` or `logo.png` on light surfaces and the `logo-dark` variant on dark surfaces.
Describe supported operations and their limits; the artwork does not guarantee a successful result.

## Editing and export

The SVG files are the current source artwork. The symbols were developed from
image-generated concepts; the current banners use vector shapes and brand typography.
To change wording, set it in CartoGothic Std and convert the lettering to paths.
Preserve the official company lockup. Regenerate PNGs after editing:

```sh
cairosvg assets/branding/logo.svg -o assets/branding/logo.png -s 2
cairosvg assets/branding/logo-dark.svg -o assets/branding/logo-dark.png -s 2
cairosvg assets/branding/readme-banner.svg -o assets/branding/readme-banner.png
```

CairoSVG is a maintainer export tool, not a dependency of the server tools.

## Recreation brief

This brief describes the current design. The checked-in SVGs preserve the exact
colours, shapes and lettering; image generation would produce a new variation.

```text
Create a 3:1 banner for distrorejuve. Use RimuHosting Warm Surface #F4EEDB, Warm Ink #251D18 text, Bark #452008, Clay #996444, decorative Leaf #88AA00 and Green Text #587200 for the arrow or magnifier. Use CartoGothic Std, a small mono eyebrow and the official light-surface RimuHosting lockup. Preserve this symbol: Three server-release stages rise from lower left to upper right and increase in size. A forward arrow represents progress through Linux releases and renewing an existing server. Show the exact wording: distrorejuve / Move your Linux server forward. / Linux release upgrades and migration checks. Keep the company lockup secondary. Use simple flat shapes and generous clear space.
```

The artwork uses the repository's existing [licence](../LICENSE).
