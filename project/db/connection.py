import psycopg2
from psycopg2.extras import RealDictCursor

from config import load_config

_config = load_config()


def get_db_connection():
    return psycopg2.connect(
        _config["DATABASE_URL"],
        cursor_factory=RealDictCursor,
    )
