import os
from dotenv import load_dotenv


def load_config():
    load_dotenv()

    database_url = os.getenv("DATABASE_URL")
    jwt_secret_key = os.getenv("JWT_SECRET_KEY")

    if not database_url:
        raise ValueError("DATABASE_URL is not set in environment variables.")
    if not jwt_secret_key:
        raise ValueError("JWT_SECRET_KEY is not set in environment variables.")

    return {
        "DATABASE_URL": database_url,
        "JWT_SECRET_KEY": jwt_secret_key,
    }
