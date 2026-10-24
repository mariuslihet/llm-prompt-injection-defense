"""Real PDF/PNG parsing of generated fake-data hidden-channel fixtures; no OCR claim."""

import argparse
import hashlib
import io
import json
from pathlib import Path

from eval.harness import benign_tasks
from lab.corpus import load
from packages.detectors import detect


def pdf_fixture(text: str, hidden: bool) -> bytes:
    from pypdf import PdfWriter
    from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject

    writer = PdfWriter()
    page = writer.add_blank_page(width=612, height=792)
    font = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject("/Helvetica"),
        }
    )
    page[NameObject("/Resources")] = DictionaryObject(
        {NameObject("/Font"): DictionaryObject({NameObject("/F1"): font})}
    )
    escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)").replace("\n", " ")
    stream = DecodedStreamObject()
    stream.set_data(
        (f"BT /F1 10 Tf 40 740 Td {3 if hidden else 0} Tr ({escaped}) Tj ET").encode("ascii")
    )
    page[NameObject("/Contents")] = stream
    result = io.BytesIO()
    writer.write(result)
    return result.getvalue()


def extract_pdf(raw: bytes) -> str:
    from pypdf import PdfReader

    if len(raw) > 1_000_000:
        raise ValueError("PDF fixture size limit")
    reader = PdfReader(io.BytesIO(raw), strict=True)
    if len(reader.pages) > 4:
        raise ValueError("PDF fixture page limit")
    return "\n".join(page.extract_text() for page in reader.pages)


def png_fixture(text: str) -> bytes:
    from PIL import Image, PngImagePlugin

    info = PngImagePlugin.PngInfo()
    info.add_text("research-note", text)
    result = io.BytesIO()
    Image.new("RGB", (32, 32), (255, 255, 255)).save(result, format="PNG", pnginfo=info)
    return result.getvalue()


def extract_png(raw: bytes) -> tuple[str, str]:
    from PIL import Image

    if len(raw) > 1_000_000:
        raise ValueError("PNG fixture size limit")
    with Image.open(io.BytesIO(raw)) as image:
        if image.size != (32, 32):
            raise ValueError("unexpected fixture dimensions")
        return str(image.info.get("research-note", "")), hashlib.sha256(image.tobytes()).hexdigest()


def experiment(output: Path) -> dict[str, object]:
    output.mkdir(parents=True, exist_ok=True)
    cases = [(attack.id, attack.payload, True) for attack in load()[:16]]
    cases += [(task["id"], task["text"], False) for task in benign_tasks()[:16]]
    results = []
    pixel_hashes = set()
    for identifier, text, attack in cases:
        pdf = pdf_fixture(text, hidden=attack)
        png = png_fixture(text)
        (output / f"{identifier}.pdf").write_bytes(pdf)
        (output / f"{identifier}.png").write_bytes(png)
        pdf_text = extract_pdf(pdf)
        png_text, pixel_hash = extract_png(png)
        pixel_hashes.add(pixel_hash)
        results.append(
            {
                "id": identifier,
                "attack": attack,
                "pdf_extracted": text.replace("\n", " ") == pdf_text.strip(),
                "png_extracted": png_text == text,
                "pdf_flagged": detect(pdf_text).action == "block",
                "png_flagged": detect(png_text).action == "block",
            }
        )
    report = {
        "experiment": "hidden-pdf-and-png-metadata",
        "cases": len(cases),
        "results": results,
        "png_pixel_variants": len(pixel_hashes),
        "ocr": "not run; metadata extraction is not OCR",
        "limits": "Generated fixtures only; arbitrary parser exploits require real OS isolation.",
    }
    (output / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("artifacts/hidden-channels"))
    print(json.dumps(experiment(parser.parse_args().output)))
