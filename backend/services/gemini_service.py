from openai import OpenAI
from config import OPENROUTER_API_KEY, OPENROUTER_MODEL


def generate_response(prompt: str) -> str:
    if not OPENROUTER_API_KEY:
        raise RuntimeError(
            "OPENROUTER_API_KEY is missing. Add it to backend/.env and restart the API."
        )

    client = OpenAI(
        api_key=OPENROUTER_API_KEY,
        base_url="https://openrouter.ai/api/v1",
        timeout=90.0
    )

    try:
        response = client.chat.completions.create(
            model=OPENROUTER_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=8000,
            temperature=0,
            seed=42,
            extra_body={"reasoning": {"effort": "none"}}
        )

        if not response.choices:
            raise RuntimeError("OpenRouter returned no response choices.")

        choice = response.choices[0]
        content = choice.message.content

        if not content:
            raise RuntimeError(
                f"Empty AI response. Finish reason: {choice.finish_reason}"
            )

        return content.strip()

    except Exception as error:
        print(f"OpenRouter API Error: {type(error).__name__}: {error}")
        raise RuntimeError(
            "AI analysis service could not complete the request. Check the API key, model and network connection."
        ) from error
