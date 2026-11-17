from services.rag_service import store_owasp_documents, retrieve_relevant_chunks


def main():
    print("\\n--- Building / synchronizing OWASP index ---")
    total = store_owasp_documents()
    print("Indexed chunks:", total)

    print("\\n--- Testing retrieval ---")
    query = "The system should prevent unauthorized users from accessing other users accounts."
    results = retrieve_relevant_chunks(query, n_results=3)

    if not results:
        print("No relevant chunks passed the retrieval filter.")
        return

    for index, chunk in enumerate(results, start=1):
        print(f"\\nResult {index}")
        print("Source:", chunk.get("source"))
        print("Category:", chunk.get("category"))
        print("Distance:", chunk.get("distance"))
        print("Content:", chunk.get("content", "")[:500])


if __name__ == "__main__":
    main()
