
from pathlib import Path
from docx import Document


# --------------------------------------------------
# 1. KNOWLEDGE BASE PATH
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent.parent

OWASP_PATH = BASE_DIR / "knowledge_base" / "owasp"


# --------------------------------------------------
# 2. LOAD WORD DOCUMENT
# --------------------------------------------------

def load_docx(file_path: Path) -> str:

    document = Document(file_path)

    text = []

    # Extract normal paragraphs.
    for paragraph in document.paragraphs:

        paragraph_text = paragraph.text.strip()

        if paragraph_text:
            text.append(paragraph_text)

    # Extract table content.
    for table in document.tables:

        for row in table.rows:

            cells = []

            for cell in row.cells:

                cell_text = cell.text.strip()

                if cell_text and cell_text not in cells:
                    cells.append(cell_text)

            if cells:
                text.append(" | ".join(cells))

    return "\n".join(text)


# --------------------------------------------------
# 3. LOAD MARKDOWN DOCUMENT
# --------------------------------------------------

def load_markdown(file_path: Path) -> str:

    return file_path.read_text(
        encoding="utf-8"
    )


# --------------------------------------------------
# 4. LOAD ALL OWASP DOCUMENTS
# --------------------------------------------------

def load_owasp_documents() -> list:

    documents = []

    # Load ASVS Word documents.
    asvs_folder = OWASP_PATH / "asvs"

    if asvs_folder.exists():

        for file_path in sorted(
            asvs_folder.glob("*.docx")
        ):

            content = load_docx(file_path)

            if content.strip():
                documents.append({
                    "source": file_path.name,
                    "category": "ASVS",
                    "content": content
                })

    # Load OWASP Top 10 Markdown documents.
    top10_folder = OWASP_PATH / "top10"

    if top10_folder.exists():

        for file_path in sorted(
            top10_folder.glob("*.md")
        ):

            content = load_markdown(file_path)

            if content.strip():
                documents.append({
                    "source": file_path.name,
                    "category": "Top 10",
                    "content": content
                })

    if not documents:
        raise FileNotFoundError(
            "No OWASP documents found. "
            "Check the knowledge_base/owasp folders."
        )

    print(
        f"Loaded {len(documents)} OWASP documents."
    )

    for document in documents:
        print(
            "Loaded:",
            document["source"],
            "| Category:",
            document["category"]
        )

    return documents
