# SDLC VuLenseR — Authentication & Admin Update

## What was added
- User registration and login with role-based access (User/Admin).
- Password hashing using PBKDF2; signed, time-limited bearer sessions.
- SQLite database for accounts and per-user analysis history.
- Admin-only user management (create, activate/deactivate, delete).
- Admin-only knowledge-base document management for ASVS `.docx` and OWASP Top 10 `.md` files. Upload/replace/delete triggers ChromaDB re-indexing.
- Protected `/analyze` and user-specific `/analyses` API routes.

## Setup (Windows)
1. Open `backend` in terminal.
2. Create/activate your existing virtual environment.
3. Install dependencies: `pip install -r requirements.txt`.
4. Copy `.env.example` to `.env` and add your real `OPENROUTER_API_KEY`. Set `AUTH_SECRET_KEY` to a long random secret.
5. Create the first admin: `python create_admin.py` (enter admin name, email and password when prompted).
6. If you did not copy your existing `chroma_db` folder into this project, build the initial index once from the `backend` folder with: `python -c "from services.rag_service import rebuild_owasp_knowledge_base; print(rebuild_owasp_knowledge_base())"`. If you already have the working ChromaDB folder, preserve it instead of rebuilding.
7. Start backend from the `backend` folder: `uvicorn main:app --reload`.
8. Open `frontend/index.html` with VS Code Live Server. The API base URL is currently `http://127.0.0.1:8000`.
9. Register a normal user from the Sign In page, or sign in using the admin account created in step 5.

## Important
- Public registration always creates a normal `user`; it cannot create an admin. Admin role assignment is restricted to the admin setup script or an authenticated admin.
- The SQLite database is created automatically at `backend/data/vulenser.db`. Do not upload this file publicly.
- Analysis history is stored per account in SQLite.
- The admin document uploader currently follows the existing ingestion design: ASVS documents are `.docx` in the `ASVS` category, and OWASP Top 10 documents are `.md` in the `Top 10` category. Other standards/file formats need an ingestion-pipeline extension first.
- The existing analysis service and its output fields were preserved. This update does not change requirement-analysis prompts or scoring logic.
- For production deployment, replace the development CORS policy with the exact frontend origin and use HTTPS.

## Admin Dashboard (current implementation)

The Admin Dashboard is limited to three project-related areas:

1. **Knowledge Base Management** — list, upload, replace, and delete the currently supported reference files (ASVS `.docx` and OWASP Top 10 `.md`). Upload/replace/delete triggers a full knowledge-base rebuild.
2. **Document Processing & Indexing** — shows extraction, chunking, embedding, and ChromaDB indexing status per file. The Re-index Knowledge Base action retries the full indexing pipeline.
3. **Analysis Overview** — shows totals from saved analysis records: total analyses, violations, security flaw/gap findings, document count, indexed chunks, and recent analysis activity.

The current analysis service stores its second finding group as `missing_requirements`; the Admin Dashboard labels this as **Security Flaws / Gaps** for monitoring. It is a count of saved findings, not a separate security classifier.

### Create the one main admin account

From the backend folder with the virtual environment activated:

```powershell
python create_admin.py
```

Only one administrator account is allowed by this setup script. Public registration creates normal user accounts only.

### Run the backend

```powershell
uvicorn main:app --reload
```

Open the existing frontend with VS Code Live Server. Sign in with the main administrator account to see the Admin Panel.

**Supported knowledge-base uploads in this version:** ASVS Word documents (`.docx`) and OWASP Top 10 Markdown files (`.md`). Additional file types and standards require corresponding ingestion support before they can be uploaded and indexed.
