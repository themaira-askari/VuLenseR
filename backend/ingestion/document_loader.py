
from pathlib import Path
from docx import Document


# --------------------------------------------------
# 1. KNOWLEDGE BASE PATH
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent.parent

OWASP_PATH = BASE_DIR / "knowledge_base" / "owasp"


# --------------------------------------------------
# 2. EXTRACT PARAGRAPHS AND TABLES IN ORDER
# --------------------------------------------------

def extract_document_blocks(document):

    content = []

    body = document.element.body

    for element in body.iterchildren():

        # Extract paragraphs.
        if element.tag.endswith("}p"):

            from docx.text.paragraph import Paragraph

            paragraph = Paragraph(element, document)
            paragraph_text = paragraph.text.strip()

            if paragraph_text:
                content.append(paragraph_text)

        # Extract tables.
        elif element.tag.endswith("}tbl"):

            from docx.table import Table

            table = Table(element, document)

            for row in table.rows:

                cells = []
                seen_cells = set()

                for cell in row.cells:

                    cell_id = id(cell._tc)

                    if cell_id in seen_cells:
                        continue

                    seen_cells.add(cell_id)

                    cell_text = cell.text.strip()

                    if cell_text:
                        cells.append(cell_text)

                if cells:
                    content.append(" | ".join(cells))

    return content


# --------------------------------------------------
# 3. LOAD WORD DOCUMENT
# --------------------------------------------------

def load_docx(file_path: Path) -> str:

    document = Document(file_path)

    content = extract_document_blocks(document)

    # Extract headers and footers.
    for section in document.sections:

        header_text = section.header.paragraphs
        footer_text = section.footer.paragraphs

        for paragraph in header_text + footer_text:

            text = paragraph.text.strip()

            if text and text not in content:
                content.append(text)

    return "\n\n".join(content)


# --------------------------------------------------
# 4. LOAD MARKDOWN DOCUMENT
# --------------------------------------------------

def load_markdown(file_path: Path) -> str:

    return file_path.read_text(encoding="utf-8")


# --------------------------------------------------
# 5. LOAD ALL OWASP DOCUMENTS
# --------------------------------------------------

def load_owasp_documents() -> list:

    documents = []

    # Load ASVS DOCX files.
    asvs_folder = OWASP_PATH / "asvs"

    if asvs_folder.exists():

        for file_path in sorted(asvs_folder.glob("*.docx")):

            content = load_docx(file_path)

            if content.strip():

                documents.append({
                    "source": str(file_path.relative_to(OWASP_PATH)).replace("\\", "/"),
                    "category": "ASVS",
                    "content": content
                })

    # Load Top 10 Markdown files.
    top10_folder = OWASP_PATH / "top10"

    if top10_folder.exists():

        for file_path in sorted(top10_folder.glob("*.md")):

            content = load_markdown(file_path)

            if content.strip():

                documents.append({
                    "source": str(file_path.relative_to(OWASP_PATH)).replace("\\", "/"),
                    "category": "Top 10",
                    "content": content
                })

    if not documents:
        raise FileNotFoundError(
            "No OWASP documents found. "
            "Check knowledge_base/owasp folders."
        )

    print("\n========== DOCUMENT LOADING ==========")

    for document in documents:

        print(
            f"{document['source']} | "
            f"{document['category']} | "
            f"{len(document['content'])} characters"
        )

    print("Total documents:", len(documents))
    print("======================================\n")

    return documents
