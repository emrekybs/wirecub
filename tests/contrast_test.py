#!/usr/bin/env python3
"""
Measure real text contrast, with custom properties resolved.

Two separate colour bugs shipped from the same blind spot: a regex that
rewrote `background-color` because it contains the word `color`, and a
check that only looked for one of the two ways text can vanish. Reading
the stylesheet is not enough — `var()` chains have to be expanded and the
actual ratio computed, because every one of these bugs produced perfectly
valid CSS.

Fails on any rule that sets both a text and a background colour whose
contrast falls below the WCAG AA threshold for large text.
"""
import re
import sys
from pathlib import Path

CSS = Path(__file__).resolve().parent.parent / "public" / "app" / "styles.css"
MIN_RATIO = 3.0


def parse_variables(css: str) -> dict[str, str]:
    """Read the custom properties, then resolve chains between them."""
    raw = dict(re.findall(r"--([\w-]+):\s*([^;]+);", css))
    resolved: dict[str, str] = {}

    def expand(name: str, depth: int = 0) -> str:
        if depth > 8:
            return ""
        value = raw.get(name, "").strip()
        match = re.fullmatch(r"var\(--([\w-]+)\)", value)
        if match:
            return expand(match.group(1), depth + 1)
        return value

    for name in raw:
        resolved[name] = expand(name)
    return resolved


def to_rgb(value: str, variables: dict[str, str]) -> tuple[int, int, int] | None:
    """Turn a colour value into RGB, following var() references."""
    value = value.strip()
    match = re.fullmatch(r"var\(--([\w-]+)\)", value)
    if match:
        value = variables.get(match.group(1), "")

    value = value.strip()
    if value.startswith("#"):
        digits = value[1:]
        if len(digits) == 3:
            digits = "".join(c * 2 for c in digits)
        if len(digits) >= 6:
            return tuple(int(digits[i:i + 2], 16) for i in (0, 2, 4))
        return None

    match = re.match(r"rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)", value)
    if match:
        return tuple(int(float(g)) for g in match.groups())

    named = {"white": (255, 255, 255), "black": (0, 0, 0)}
    return named.get(value.lower())


def luminance(rgb: tuple[int, int, int]) -> float:
    channels = []
    for c in rgb:
        c = c / 255
        channels.append(c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4)
    r, g, b = channels
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: tuple[int, int, int], b: tuple[int, int, int]) -> float:
    la, lb = luminance(a), luminance(b)
    lighter, darker = max(la, lb), min(la, lb)
    return (lighter + 0.05) / (darker + 0.05)


def main() -> int:
    css = CSS.read_text()
    variables = parse_variables(css)
    failures = []

    for rule in re.finditer(r"([^{}]+)\{([^}]*)\}", css):
        selector = " ".join(rule.group(1).split())
        body = rule.group(2)
        if selector.startswith("@") or "--" in selector:
            continue

        # A few rules sit on a coloured ancestor, so the pair in the rule
        # is not the pair the eye sees. Those are marked explicitly rather
        # than lowering the threshold for everything.
        if "contrast-ignore" in body:
            continue

        fore = re.search(r"(?<![-\w])color:\s*([^;]+);", body)
        back = re.search(r"(?<![-\w])background(?:-color)?:\s*([^;]+);", body)
        if not (fore and back):
            continue

        # A gradient or image is not a flat colour and cannot be measured.
        if "gradient" in back.group(1) or "url(" in back.group(1):
            continue

        fg = to_rgb(fore.group(1), variables)
        bg = to_rgb(back.group(1), variables)
        if not fg or not bg:
            continue

        ratio = contrast(fg, bg)
        if ratio < MIN_RATIO:
            failures.append((selector[:64], ratio, fore.group(1).strip(),
                             back.group(1).strip()))

    # Sanity check the palette itself: body text on the page, and on cards.
    page = to_rgb("var(--page)", variables)
    surface = to_rgb("var(--surface)", variables)
    ink = to_rgb("var(--ink)", variables)
    for name, background in (("page", page), ("surface", surface)):
        if ink and background:
            ratio = contrast(ink, background)
            if ratio < 4.5:
                failures.append((f"body text on {name}", ratio, "--ink", f"--{name}"))

    if failures:
        print(f"{len(failures)} contrast failures (need {MIN_RATIO}:1):")
        for selector, ratio, fore, back in failures:
            print(f"  {ratio:4.1f}:1  {selector}")
            print(f"          color: {fore}   background: {back}")
        return 1

    print(f"contrast: every measurable rule clears {MIN_RATIO}:1")
    if ink and surface:
        print(f"  body text on cards: {contrast(ink, surface):.1f}:1")
    if ink and page:
        print(f"  body text on page : {contrast(ink, page):.1f}:1")
    return 0


if __name__ == "__main__":
    sys.exit(main())
