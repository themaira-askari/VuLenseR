
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
