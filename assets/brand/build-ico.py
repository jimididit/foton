"""Rebuilds assets/brand/icons/<AssemblyName>.ico from the tile SVGs. Needs Pillow and rsvg-convert.

Each icon mixes two drawings: the -tile-small cut at 16, 20, and 24 px and the full -tile at 32 px and above.
Frames up to 64 px are 32-bit bitmaps (what the .NET Framework icon loader reads everywhere); 256 px is PNG.
Run from assets/brand:  python build-ico.py . icons
"""
import io, os, struct, subprocess, sys
from PIL import Image

SMALL = [16, 20, 24]
FULL = [32, 40, 48, 64, 256]

# (full tile, small tile, icon named for the executable's AssemblyName)
ICONS = [
    ("foton-tile.svg", "foton-tile-small.svg", "foton-console.ico"),
    ("foton-cli-tile.svg", "foton-cli-tile-small.svg", "foton.ico"),
    ("foton-collect-tile.svg", "foton-collect-tile-small.svg", "foton-collect.ico"),
    ("foton-baseline-tile.svg", "foton-baseline-tile-small.svg", "foton-baseline.ico"),
]


def render(svg, px):
    out = subprocess.run(["rsvg-convert", "-w", str(px), "-h", str(px), svg], capture_output=True, check=True)
    return Image.open(io.BytesIO(out.stdout)).convert("RGBA")


def bmp_payload(im):
    w, h = im.size
    hdr = struct.pack("<IiiHHIIiiII", 40, w, h * 2, 1, 32, 0, w * h * 4, 0, 0, 0, 0)
    px = im.load()
    xor = bytearray()
    for y in range(h - 1, -1, -1):  # bottom-up
        for x in range(w):
            r, g, b, a = px[x, y]
            xor += bytes((b, g, r, a))
    row = ((w + 31) // 32) * 4  # 1 bpp AND mask, 4-byte aligned
    return hdr + bytes(xor) + bytes(row * h)


def build(full_svg, small_svg, dest):
    frames = [(px, bmp_payload(render(small_svg, px))) for px in SMALL]
    for px in FULL:
        im = render(full_svg, px)
        if px == 256:
            buf = io.BytesIO()
            im.save(buf, format="PNG", optimize=True)
            frames.append((px, buf.getvalue()))
        else:
            frames.append((px, bmp_payload(im)))
    offset = 6 + 16 * len(frames)
    out = bytearray(struct.pack("<HHH", 0, 1, len(frames)))
    for px, data in frames:
        d = 0 if px == 256 else px
        out += struct.pack("<BBBBHHII", d, d, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    for _, data in frames:
        out += data
    with open(dest, "wb") as f:
        f.write(out)
    return len(frames), os.path.getsize(dest)


if __name__ == "__main__":
    svgdir, icodir = sys.argv[1], sys.argv[2]
    for full, small, ico in ICONS:
        n, size = build(os.path.join(svgdir, full), os.path.join(svgdir, small), os.path.join(icodir, ico))
        print(f"{ico:22s} {n} frames  {size:,} bytes")
