
import re


def chunk_text(
    text: str,
    chunk_size: int = 1200,
    overlap: int = 200
) -> list[str]:

    if not text or not text.strip():
        return []

    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero.")

    if overlap < 0 or overlap >= chunk_size:
        raise ValueError("Overlap must be smaller than chunk size.")

    # Normalize text without removing paragraph boundaries.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()

    if len(text) <= chunk_size:
        return [text]

    chunks = []
    start = 0

    while start < len(text):

        end = min(start + chunk_size, len(text))

        if end < len(text):

            # Prefer paragraph, line, sentence and word boundaries.
            minimum = start + int(chunk_size * 0.70)

            boundaries = [
                text.rfind("\n\n", minimum, end),
                text.rfind("\n", minimum, end),
                text.rfind(". ", minimum, end),
                text.rfind("? ", minimum, end),
                text.rfind("! ", minimum, end),
                text.rfind(" ", minimum, end)
            ]

            boundary = max(boundaries)

            if boundary >= minimum:
                if text.startswith("\n\n", boundary):
                    end = boundary + 2
                else:
                    end = boundary + 1

        chunk = text[start:end].strip()

        if chunk:
            chunks.append(chunk)

        if end >= len(text):
            break

        # Calculate the next starting position with overlap.
        next_start = max(start + 1, end - overlap)

        # Avoid starting in the middle of a word.
        while (
            next_start < end
            and next_start > 0
            and not text[next_start - 1].isspace()
            and not text[next_start].isspace()
        ):
            next_start += 1

        while next_start < len(text) and text[next_start].isspace():
            next_start += 1

        start = next_start

    return chunks


# ==================================================
# HYBRID SECTION-BASED + BOUNDARY-AWARE CHUNKING
# ==================================================

_HEADING = re.compile(r"^\s{0,3}(#{1,6})\s+(.*\S)\s*$")
_ASVS_CONTROL = re.compile(r"\bV\d{1,2}\.\d{1,2}(?:\.\d{1,2})?\b")
_TOP10_CONTROL = re.compile(r"\bA(?:0[1-9]|10):\d{4}\b")
MIN_SECTION_CHARS = 150


def _clean_heading(text: str) -> str:
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)(\{[^}]*\})?", "", text)  # drop markdown images
    return re.sub(r"\s+", " ", text).strip(" .#")


def extract_control_id(source: str, section: str, text: str) -> str:
    """Find an OWASP control identifier (A01:2025, V6.2.1) from the section/text."""
    for candidate in (section, text):
        match = _TOP10_CONTROL.search(candidate or "") or _ASVS_CONTROL.search(candidate or "")
        if match:
            return match.group(0)
    file_match = re.search(r"(A(?:0[1-9]|10))_(\d{4})", str(source))
    return f"{file_match.group(1)}:{file_match.group(2)}" if file_match else ""


def chunk_by_sections(
    text: str,
    chunk_size: int = 1200,
    overlap: int = 200,
) -> list[dict]:
    """Split a document by its headings, then split long sections recursively.

    Returns [{"text": chunk, "section": "Heading > Subheading", "chunk_in_section": n}].
    Each chunk is prefixed with its section path so the embedding keeps context.
    Short sections are merged forward so tiny fragments are not indexed alone.
    """
    if not text or not text.strip():
        return []

    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # 1. Parse headings into (path, body) sections.
    sections = []
    stack = []  # [(level, title)]
    body = []
    in_fence = False

    def flush():
        content = "\n".join(body).strip()
        if content:
            sections.append((" > ".join(title for _, title in stack), content))
        body.clear()

    for line in text.split("\n"):
        if line.strip().startswith("```"):
            in_fence = not in_fence
        match = None if in_fence else _HEADING.match(line)
        # ASVS table header rows look like "# | Description | Level" -> that's a table, not a heading
        if match and (match.group(2).lstrip().startswith("|") or " | " in match.group(2)):
            match = None
        if match:
            flush()
            level = len(match.group(1))
            title = _clean_heading(match.group(2))
            while stack and stack[-1][0] >= level:
                stack.pop()
            if title:
                stack.append((level, title))
        else:
            body.append(line)
    flush()

    if not sections:
        return [
            {"text": chunk, "section": "", "chunk_in_section": i}
            for i, chunk in enumerate(chunk_text(text, chunk_size, overlap))
        ]

    # 2. Merge very small sections into the following one.
    merged = []
    carry_path, carry_text = "", ""
    for path, content in sections:
        if carry_text:
            content = f"{carry_text}\n\n{content}"
            path = path or carry_path
            carry_text = ""
        if len(content) < MIN_SECTION_CHARS and (path, content) != sections[-1]:
            carry_path, carry_text = path, content
            continue
        merged.append((path, content))
    if carry_text:
        merged.append((carry_path, carry_text))

    # 3. Split long sections on paragraph/sentence boundaries, keep overlap.
    chunks = []
    for path, content in merged:
        prefix = f"[Section: {path}]\n" if path else ""
        room = max(300, chunk_size - len(prefix))
        pieces = chunk_text(content, room, min(overlap, room // 4))
        for i, piece in enumerate(pieces):
            chunks.append({
                "text": prefix + piece,
                "section": path,
                "chunk_in_section": i,
            })
    return chunks
