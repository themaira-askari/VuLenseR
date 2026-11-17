"""Parse an uploaded requirement document into ordered text blocks with locations.

The parser does NOT assume any requirement format. It only extracts paragraphs,
headings, list items and table rows and remembers where each one came from, so
the LLM can later decide which blocks are real requirements and each finding can
point back to its original location.
"""

import re
from io import BytesIO

HEADING_STYLE = re.compile(r"^heading\s*(\d)", re.IGNORECASE)
MARKDOWN_HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(.*\S)")


def _location(base: str, section: str) -> str:
    return f"{base}, Section: {section[:60]}" if section else base


def _text_blocks(text: str, prefix: str = "") -> list:
    """Split plain text into one block per non-empty line, tracking headings."""
    blocks = []
    section = ""
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        heading = MARKDOWN_HEADING.match(line)
        if heading:
            section = heading.group(1).strip()
        base = f"{prefix}Line {number}" if prefix else f"Line {number}"
        blocks.append({"text": line, "location": _location(base, section)})
    return blocks


def _docx_blocks(raw: bytes) -> list:
    from docx import Document
    from docx.table import Table
    from docx.text.paragraph import Paragraph

    document = Document(BytesIO(raw))
    blocks = []
    section = ""
    paragraph_number = 0
    table_number = 0

    for element in document.element.body.iterchildren():
        if element.tag.endswith("}p"):
            paragraph = Paragraph(element, document)
            text = paragraph.text.strip()
            if not text:
                continue
            paragraph_number += 1
            style = paragraph.style.name if paragraph.style is not None else ""
            if HEADING_STYLE.match(style or "") or style == "Title":
                section = text
            blocks.append({
                "text": text,
                "location": _location(f"Paragraph {paragraph_number}", section),
            })
        elif element.tag.endswith("}tbl"):
            table_number += 1
            table = Table(element, document)
            for row_number, row in enumerate(table.rows, start=1):
                cells, seen = [], set()
                for cell in row.cells:
                    if id(cell._tc) in seen:
                        continue
                    seen.add(id(cell._tc))
                    if cell.text.strip():
                        cells.append(cell.text.strip())
                if cells:
                    blocks.append({
                        "text": " | ".join(cells),
                        "location": _location(f"Table {table_number}, Row {row_number}", section),
                    })
    return blocks


def _pdf_blocks(reader) -> list:
    blocks = []
    for page_number, page in enumerate(reader.pages, start=1):
        blocks.extend(_text_blocks(page.extract_text() or "", prefix=f"Page {page_number}, "))
    return blocks


def parse_text(raw: bytes) -> list:
    return _text_blocks(raw.decode("utf-8-sig"))


def parse_docx(raw: bytes) -> list:
    return _docx_blocks(raw)


def parse_pdf_reader(reader) -> list:
    return _pdf_blocks(reader)
