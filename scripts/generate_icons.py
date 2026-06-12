"""Generate Splunk app icons that satisfy AppInspect's icon checks.

Splunk expects two PNGs in splunk_app/static/:
  - appIcon.png      (36 x 36)
  - appIcon_2x.png   (72 x 72)

The icon is a stylized 'C' (Counterspell) over a dark slate background — clean
enough to read at 36px in the Splunk app grid.

Run once after cloning, or any time the brand changes:

    python scripts/generate_icons.py
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

REPO_ROOT = Path(__file__).resolve().parents[1]
STATIC = REPO_ROOT / "splunk_app" / "static"

BG = (15, 23, 42, 255)        # slate-900
FG = (14, 165, 233, 255)      # sky-500 (matches the Architect node in the diagram)
RING = (124, 58, 237, 255)    # violet-600


def _draw_icon(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), BG)
    draw = ImageDraw.Draw(img)

    # Outer ring suggesting a closed loop (the design-validate-deploy cycle).
    pad = max(2, size // 12)
    ring_width = max(2, size // 16)
    draw.ellipse(
        (pad, pad, size - pad, size - pad),
        outline=RING,
        width=ring_width,
    )

    # The C — a thick arc with a notch on the right.
    inset = pad + ring_width + max(2, size // 18)
    arc_width = max(3, size // 7)
    draw.arc(
        (inset, inset, size - inset, size - inset),
        start=40, end=320,
        fill=FG,
        width=arc_width,
    )
    return img


def main() -> int:
    STATIC.mkdir(parents=True, exist_ok=True)
    for name, size in (("appIcon.png", 36), ("appIcon_2x.png", 72)):
        img = _draw_icon(size)
        out = STATIC / name
        img.save(out, "PNG", optimize=True)
        print(f"wrote {out}  ({size}x{size})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
