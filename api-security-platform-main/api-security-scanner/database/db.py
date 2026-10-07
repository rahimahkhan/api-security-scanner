"""Database backend dispatcher.

DB_BACKEND=firestore  -> Google Cloud Firestore (NoSQL), via database/firestore_db.py
anything else         -> SQL (SQLite/Postgres/MySQL), via database/sql_db.py

Both backends expose the same function names, so every `from database.db
import ...` keeps working unchanged. Firestore document IDs are strings;
the SQL backend keeps integer IDs.
"""
import os

if os.getenv("DB_BACKEND", "").strip().lower() == "firestore":
    from database.firestore_db import *  # noqa: F401,F403
else:
    from database.sql_db import *  # noqa: F401,F403
