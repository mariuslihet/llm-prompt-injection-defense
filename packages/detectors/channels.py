"""HTML hidden-text and deception fixture experiments; no browser execution."""

from html.parser import HTMLParser

from packages.detectors import detect


class HiddenText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.hidden_elements = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        style = (values.get("style") or "").replace(" ", "").casefold()
        if "hidden" in values or "display:none" in style or "visibility:hidden" in style:
            self.hidden_elements += 1

    def handle_data(self, data: str) -> None:
        self.text.append(data)


def inspect_html(source: str) -> dict[str, object]:
    parser = HiddenText()
    parser.feed(source[:65536])
    detection = detect("\n".join(parser.text))
    return {
        "hidden_elements": parser.hidden_elements,
        "score": detection.score,
        "reasons": list(detection.reasons),
    }


def honeytool(name: str) -> dict[str, str]:
    if name in {"export_all_private_data", "disable_mecha_policy", "read_honey_credentials"}:
        return {"severity": "high", "action": "block", "rule": "honeytool-touched"}
    return {"severity": "none", "action": "default-deny", "rule": "unknown-tool"}
