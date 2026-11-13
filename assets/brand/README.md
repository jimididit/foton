# Foton brand mark

The mark is the photon wave packet from the HTML reports: one smooth line whose swing grows to the centre and fades at both ends.

| File | Use |
|------|-----|
| `foton-tile.svg` | App icon and avatar: beam cyan on the reports' near-black, rounded tile |
| `foton-tile-small.svg` | The same at 16 to 24 px: three bold turns instead of six |
| `foton-mark.svg` | One colour (black), for print or on a light background |
| `foton-mark-white.svg` | One colour (white), for a dark background |
| `foton.ico` | The Windows icon of the four executables: the small cut at 16, 20, and 24 px, the full mark at 32 to 256 px |

## Colours

| Role | HEX |
|------|-----|
| Beam (the wave) | `#37D6FF` |
| Ink (the tile) | `#0B1016` |

They are the reports' `--beam` and `--bg`.

## Use

- Keep clear space around the tile of at least one eighth of its width; do not crop, rotate, stretch, outline, or add effects.
- Below 32 px, use `foton-tile-small.svg`; the full packet turns into a squiggle at that size.
- On a light page without the tile, use `foton-mark.svg`; do not put the cyan wave on white (it falls below 3:1 contrast).
- `foton.ico` is built from the two tile SVGs (frames up to 64 px as 32-bit bitmaps, 256 px as PNG); `IconRules` checks that every executable carries it.
