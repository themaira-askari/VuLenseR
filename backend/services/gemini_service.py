
from openai import OpenAI
from config import OPENROUTER_API_KEY, OPENROUTER_MODEL


client = OpenAI(
    api_key=OPENROUTER_API_KEY,
    base_url="https://openrouter.ai/api/v1",
    timeout=90.0
)


def generate_response(prompt: str) -> str:

    try:
        response = client.chat.completions.create(
            model=OPENROUTER_MODEL,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            max_tokens=8000,
            temperature=0.1,
            extra_body={
                "reasoning": {
                    "effort": "low"
                }
            }
        )

        if not response.choices:
            raise RuntimeError(
                "OpenRouter returned no response choices."
            )

        choice = response.choices[0]
        content = choice.message.content

        print("\n========== OPENROUTER RESPONSE ==========")
        print("Model:", response.model)
        print("Finish reason:", choice.finish_reason)
        print("Usage:", response.usage)
        print("=========================================\n")

        if not content:
            raise RuntimeError(
                f"Empty AI response. Finish reason: "
                f"{choice.finish_reason}"
            )

        return content.strip()

    except Exception as error:
        print(
            f"OpenRouter API Error: "
            f"{type(error).__name__}: {error}"
        )
        raise RuntimeError(str(error)) from error
