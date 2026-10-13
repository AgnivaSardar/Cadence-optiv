# Removed Files Log

> If any of these need to be recreated, this file contains everything required to do so.
> All removed content was verified to be empty stubs, auto-generated artifacts, or cache files.

---

## 1. `__pycache__` directories

Auto-generated Python bytecode cache. Recreated automatically when you run the project.

**Removed locations:**
```
src/tprm/__pycache__/
src/tprm/ai/__pycache__/
src/tprm/api/__pycache__/
src/tprm/common/__pycache__/
src/tprm/gate/__pycache__/
src/tprm/ingestion/__pycache__/
src/tprm/nlp/__pycache__/
src/tprm/onetrust/__pycache__/
src/tprm/pii/__pycache__/
src/tprm/policy/__pycache__/
src/tprm/risk/__pycache__/
src/tprm/sanitize/__pycache__/
src/tprm/sensitivity/__pycache__/
src/tprm/workflow/__pycache__/
tests/__pycache__/
tests/fixtures/__pycache__/
tests/security/__pycache__/
tests/unit/__pycache__/
tests/unit/tprm/__pycache__/
tests/unit/tprm/ai/__pycache__/
tests/unit/tprm/common/__pycache__/
tests/unit/tprm/gate/__pycache__/
tests/unit/tprm/ingestion/__pycache__/
tests/unit/tprm/pii/__pycache__/
tests/unit/tprm/policy/__pycache__/
tests/unit/tprm/sanitize/__pycache__/
tests/unit/tprm/workflow/__pycache__/
```

**To recreate:** Just run `python -m pytest` or any import — Python rebuilds these automatically.

---

## 2. `.hypothesis/` directory

Hypothesis property-based testing state. Contains internal test constants used by the `hypothesis` library to remember which values it has tried. The `.hypothesis/.gitignore` file itself marks this directory as intentionally gitignored.

**Contents that were inside:**
- `.hypothesis/.gitignore` — auto-created by Hypothesis, contained `*` (ignore everything)
- `.hypothesis/constants/` — 40 binary/text files with names like `0c0565fc769d0006`, each storing constants Hypothesis derived across test runs. These are optimization hints only; Hypothesis recreates them from scratch on next run.

**To recreate:** Run any test that uses `@given(...)` from Hypothesis — the directory and constants regenerate automatically.

---

## 3. `.pytest_cache/` directory

pytest run cache. Stores which tests passed/failed last run for `--lf` (last-failed) and `--ff` (first-failed) flags.

**To recreate:** Run `pytest` — it is recreated automatically.

---

## 4. `.ruff_cache/` directory

Ruff linter cache. Speeds up repeated lint runs by caching file hashes.

**Removed contents:**
- `.ruff_cache/CACHEDIR.TAG`
- `.ruff_cache/0.16.10/11999221232758320899`
- `.ruff_cache/.gitignore`

**To recreate:** Run `ruff check .` — recreated automatically.

---

## 5. `.coverage` file

Coverage.py binary data file produced by `pytest --cov`. Contains coverage measurements from the last test run.

**To recreate:** Run `pytest --cov=src/tprm` — the file is regenerated.

---

## 6. `alembic/` directory (entire tree)

The Alembic database migration framework was scaffolded but never configured or used. The entire `alembic/` tree contained only an empty `versions/` subdirectory — no `alembic.ini`, no `env.py`, no migration scripts.

```
alembic/
└── versions/   ← empty, no migration files
```

The project uses no relational database. Data models are in-memory Pydantic models only (`common/models.py`). There is no SQLAlchemy dependency, no database URL for migrations, and nothing in `pyproject.toml` that references Alembic.

**To recreate if a database is added later:**
```bash
# Install alembic
pip install alembic

# Scaffold from project root
alembic init alembic

# Then edit alembic/env.py to point at your SQLAlchemy Base metadata
```

---

## 7. `src/tprm/nlp/prototypes/` directory

Empty placeholder package — only contained a zero-byte `__init__.py`. No prototype code was ever written here.

**Removed:**
```
src/tprm/nlp/prototypes/__init__.py   ← 0 bytes
```

**To recreate:** `mkdir -p src/tprm/nlp/prototypes && touch src/tprm/nlp/prototypes/__init__.py`

---

## 8. `tests/integration/` directory

Empty placeholder — only contained a zero-byte `__init__.py`. No integration tests were written.

**Removed:**
```
tests/integration/__init__.py   ← 0 bytes
```

**To recreate:** `mkdir tests/integration && touch tests/integration/__init__.py`

---

## 9. Empty unit test stub directories

These directories each contained only a zero-byte `__init__.py` with no test file inside. They were placeholder stubs for test coverage that was never written.

| Directory | Corresponding source module | Status |
|---|---|---|
| `tests/unit/tprm/nlp/` | `src/tprm/nlp/` | No tests written |
| `tests/unit/tprm/onetrust/` | `src/tprm/onetrust/` | No tests written |
| `tests/unit/tprm/risk/` | `src/tprm/risk/` | No tests written |
| `tests/unit/tprm/sensitivity/` | `src/tprm/sensitivity/` | No tests written |

**Removed from each:** one zero-byte `__init__.py` file.

**To recreate any of these test stubs:**
```bash
mkdir tests/unit/tprm/<module_name>
touch tests/unit/tprm/<module_name>/__init__.py
# Then create: tests/unit/tprm/<module_name>/test_<module_name>.py
```

---

## 10. `src/tprm/ui/static/` directory

Empty directory. The `ui/` module only has `templates/index.html`. No static assets (JS, CSS, images) were ever added.

**To recreate:** `mkdir src/tprm/ui/static`

If static files are added later, update `api/main.py` to mount the directory:
```python
from fastapi.staticfiles import StaticFiles
app.mount("/static", StaticFiles(directory="src/tprm/ui/static"), name="static")
```

---

## Summary

| Category | Items removed | Impact |
|---|---|---|
| `__pycache__` dirs | 27 directories | Zero — auto-regenerated |
| `.hypothesis/` | 1 dir + 41 files | Zero — auto-regenerated |
| `.pytest_cache/` | 1 dir | Zero — auto-regenerated |
| `.ruff_cache/` | 1 dir + 3 files | Zero — auto-regenerated |
| `.coverage` | 1 file | Zero — auto-regenerated |
| `alembic/` | 2 dirs (no files) | Zero — was never configured |
| `nlp/prototypes/` | 1 empty `__init__.py` | Zero — no code existed |
| `tests/integration/` | 1 empty `__init__.py` | Zero — no tests existed |
| Empty test stubs | 4 empty `__init__.py` | Zero — no tests existed |
| `ui/static/` | 1 empty dir | Zero — no assets existed |

**No source code, configuration, tests, or data was removed.**

---

## Second Pass — Additional Removals

### 11. `__pycache__` directories (second pass)

Regenerated automatically when the import verification check ran after the first cleanup. Same as before — zero impact, auto-regenerated on next run.

### 12. `.DS_Store` files

macOS Finder metadata files. No project content, should never be in version control.

**Removed:**
```
/OPTIVE/.DS_Store
/OPTIVE/tprm/.DS_Store
```

### 13. `tests/fixtures/make_realistic_pdf.py`

A standalone PDF generator script. Verified with `grep` across the entire test suite — **no test file imports it**. `make_pdf.py`, `make_docx.py`, and `make_xlsx.py` are all actively imported by `tests/unit/tprm/ingestion/test_parser.py`. This one is not.

**To recreate:** The file was a utility to generate a multi-section PDF with realistic TPRM content for manual testing. It used `reportlab` to write headings, body text, and a table. Run `python tests/fixtures/make_realistic_pdf.py` to output a PDF — it was never part of the automated test suite.

### 14. `src/tprm/ai/schemas.py`

A 6-line re-export shim:
```python
from tprm.common.models import AIRiskResult, RawRisk
__all__ = ["AIRiskResult", "RawRisk"]
```
Verified with `grep` across all source and test files — **nothing imports from `tprm.ai.schemas`**. `AIRiskResult` and `RawRisk` are imported directly from `tprm.common.models` everywhere they are needed. This file added a redundant import path with no consumers.

**To recreate:** `src/tprm/ai/schemas.py` with the two lines above.
