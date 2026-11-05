# VuLenseR — SDLC Vulnerability Finder AI

VuLenseR analyzes software requirements using three layers:

1. **Rule engine** — flags ambiguous wording and missing security controls.
2. **RAG layer** — retrieves relevant OWASP and secure-requirement guidance from a local ChromaDB collection.
3. **AI analysis** — sends the requirement and server-side context to the configured Groq model and validates the structured response.

## Backend setup

Use Python 3.10 or newer.

### Windows (PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Open `.env` and set:
- `GROQ_API_KEY` to your Groq API key.
- `APP_API_KEY` to a long, private key of your choice.
- `CORS_ORIGINS` to the frontend origin(s), comma-separated.

Start the API from the project root:

```powershell
uvicorn main:app --reload
```

API documentation is available at `http://127.0.0.1:8000/docs`.

## Frontend setup

Open a second terminal:

```powershell
cd srs-frontend
npm install
Copy-Item .env.example .env
npm run dev
```

The frontend defaults to `http://127.0.0.1:8000` for the backend. To use another backend URL, change `VITE_API_BASE_URL` in `srs-frontend/.env`.

Enter the backend `APP_API_KEY` in the API Key field in the browser when analyzing a requirement. The key is not hard-coded in the frontend bundle or saved in browser storage.

## Tests and quality checks

From the project root:

```powershell
pytest -q
```

For frontend checks:

```powershell
cd srs-frontend
npm run lint
npm run build
```

The AI and RAG integrations require their configured services/dependencies. The API test suite mocks the external AI/RAG calls so request validation and API behavior can be tested without making paid AI requests.
