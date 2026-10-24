"""Export a dependency-free SVG robustness/utility plot from measured self-play data."""

import argparse
import json
from pathlib import Path


def plot(source: Path, destination: Path) -> None:
    report = json.loads(source.read_text(encoding="utf-8"))
    rounds = report["rounds"]
    width = max(1, len(rounds) - 1)
    series = []
    for field, color in (("adaptive_evasion_rate", "#b44637"), ("benign_fpr", "#227665")):
        points = " ".join(
            f"{70 + r['round'] * 420 / width:.1f},{220 - r[field] * 160:.1f}" for r in rounds
        )
        series.append(
            f'<polyline points="{points}" fill="none" stroke="{color}" stroke-width="3"/>'
        )
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="640" height="300" role="img" '
        'aria-label="BERT self-play attack evasion and benign false positives">'
        '<rect width="640" height="300" fill="white"/>'
        '<text x="30" y="25">BERT fixture self-play: frozen held-out evaluation</text>'
        '<path d="M70 60V220H520" fill="none" stroke="black"/>'
        '<text x="15" y="65">100%</text><text x="32" y="225">0%</text>'
        + "".join(series)
        + '<text x="70" y="250" fill="#b44637">Attack evasion</text>'
        '<text x="250" y="250" fill="#227665">Benign false positives</text>'
        '<text x="220" y="280">Retraining round (0, 1, 2)</text></svg>'
    )
    destination.write_text(svg, encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    plot(args.source, args.destination)
