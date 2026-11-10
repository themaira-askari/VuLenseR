
from ingestion.document_loader import load_owasp_documents
from ingestion.text_chunker import chunk_text


# Step 1: OWASP documents load karna
documents = load_owasp_documents()

print("\nTotal OWASP documents loaded:", len(documents))


# Step 2: Har document ko chunks mein divide karna
total_chunks = 0

for document in documents:

    chunks = chunk_text(document["content"])

    total_chunks += len(chunks)

    print("\nSource:", document["source"])
    print("Category:", document["category"])
    print("Total chunks:", len(chunks))


# Step 3: Final result
print("\n----------------------------")
print("TOTAL DOCUMENTS:", len(documents))
print("TOTAL CHUNKS:", total_chunks)
print("----------------------------")
