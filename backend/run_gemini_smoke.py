
from services.gemini_service import generate_response

answer = generate_response(
    "Explain SQL injection in two simple sentences."
)

print(answer)
