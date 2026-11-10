
import re


def chunk_text(
    text: str,
    chunk_size: int = 1200,
    overlap: int = 200
) -> list[str]:
    """
    Divide document text into readable chunks.

    - Preserves paragraph and line boundaries where possible.
    - Avoids cutting words in half.
    - Maintains a small overlap between chunks.
    """

    if not text or not text.strip():
        return []

    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero.")

    if overlap < 0 or overlap >= chunk_size:
        raise ValueError(
            "overlap must be non-negative and smaller than chunk_size."
        )

    # Split document into non-empty lines.
    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip()
    ]

    # Split exceptionally long lines at word boundaries.
    prepared_lines = []

    for line in lines:

        while len(line) > chunk_size:

            split_position = line.rfind(
                " ",
                0,
                chunk_size
            )

            if split_position <= 0:
                split_position = chunk_size

            prepared_lines.append(
                line[:split_position].strip()
            )

            line = line[split_position:].strip()

        if line:
            prepared_lines.append(line)

    chunks = []
    current = ""

    for line in prepared_lines:

        candidate = (
            current + "\n" + line
            if current
            else line
        )

        if len(candidate) <= chunk_size:
            current = candidate
            continue

        if current:
            chunks.append(current.strip())

        # Preserve a small overlap from the previous chunk.
        if current and overlap > 0:
            overlap_text = current[-overlap:]

            # Avoid starting the next chunk in the middle of a word.
            first_space = overlap_text.find(" ")

            if first_space != -1:
                overlap_text = overlap_text[first_space + 1:]

            current = overlap_text.strip()
        else:
            current = ""

        candidate = (
            current + "\n" + line
            if current
            else line
        )

        # A line may still be too large after adding overlap.
        if len(candidate) > chunk_size:
            current = line[:chunk_size].strip()
        else:
            current = candidate

    if current.strip():
        chunks.append(current.strip())

    return chunks
