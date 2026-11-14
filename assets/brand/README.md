# Foton brand marks

The master mark is the photon wave packet from the HTML reports: one smooth line whose swing grows
to the centre and fades at both ends. Each executable carries a sibling of it — the same photon doing
a different thing, in a different colour from the reports' own palette.

## The family

| Executable | Mark | Idea | Colour | Report token |
|---|---|---|---|---|
| `foton-console.exe` | wave packet | the photon itself | `#37D6FF` | `--beam` |
| `foton.exe` | prompt + quantum | a beam reflected at a mirror, emitting | `#A98BFF` | *(new)* |
| `foton-collect.exe` | aperture | light enters, the quantum is held | `#FFB340` | `--med` |
| `foton-baseline.exe` | reference beam and break | the datum, and where the second run diverges | `#7CF5C4` | `--beam2` |

The tile is always `#0B1016` — the reports' `--bg`.

`#A98BFF` is the one colour not already in the reports. It fills the gap at the short-wavelength end
of the palette, so the four marks run violet → cyan → mint → amber across the visible spectrum.
A fifth tool should take `--low` `#7CC4FF`, then `--high` `#FF5C6C`.

## Files

| File | Use |
|---|---|
| `foton-tile.svg` | Master mark. App icon and avatar: beam cyan on the reports' near-black, rounded tile |
| `foton-tile-small.svg` | The master at 16 to 24 px: three bold turns instead of six |
| `foton-mark.svg` / `-white.svg` | Master, one colour, for print or a light/dark background |
| `foton-cli-tile.svg` | `foton.exe` — prompt + quantum |
| `foton-collect-tile.svg` | `foton-collect.exe` — aperture |
| `foton-baseline-tile.svg` | `foton-baseline.exe` — reference beam and break |
| `*-tile-small.svg` | The 16 to 24 px cut of each sibling: heavier stroke, wider gaps |
| `*-mark.svg` / `*-mark-white.svg` | One-colour cuts of each sibling |
| `icons/<assembly>.ico` | The Windows icon of each executable, named for its `AssemblyName` |

Every `.ico` holds 16, 20, 24, 32, 40, 48, 64 and 256 px. Frames up to 64 px are 32-bit bitmaps and
256 px is PNG. **16, 20 and 24 px are built from the small cut, not from the full mark** — rebuilding an
icon from one SVG will silently lose that and the marks will smear in Explorer's detail view.
`build-ico.py` rebuilds all four the right way (`python build-ico.py . icons` from this folder; needs Pillow and
`rsvg-convert`). `cli/Directory.Build.targets` gives each executable `icons/$(AssemblyName).ico`, and IconRules checks
that each carries its own icon and no other.

## Use

- Keep clear space around a tile of at least one eighth of its width; do not crop, rotate, stretch,
  outline, or add effects.
- Below 32 px use the `-tile-small` cut; the full packet turns into a squiggle at that size.
- On a light page without the tile, use the `-mark.svg`; do not put a brand colour on white
  (all four fall below 3:1 contrast there). On the `#0B1016` tile every colour clears 8:1.
- Do not recolour a sibling's mark into another sibling's colour: shape and colour identify the
  executable together, and the colour alone is what separates them at 16 px.
