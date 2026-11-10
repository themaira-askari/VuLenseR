
from services.rag_service import (
    store_owasp_documents,
    retrieve_relevant_chunks
)


# Step 1: OWASP data ChromaDB mein store karna
print("\n--- Storing OWASP Documents ---")

total = store_owasp_documents()


# Step 2: Security-related query test karna
print("\n--- Testing Retrieval ---")

query = "The system should prevent unauthorized users from accessing other users' accounts."

results = retrieve_relevant_chunks(query, n_results=3)


# Step 3: Retrieved chunks display karna
for index, chunk in enumerate(results["documents"][0]):

    source = results["metadatas"][0][index]["source"]

    print(f"\nResult {index + 1}")
    print("Source:", source)
    print("Content:", chunk[:500])


print("\n--- RAG Test Completed ---")
