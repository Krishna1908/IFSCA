from datetime import timedelta
from typing import Optional

from flask_jwt_extended import create_access_token


def generate_access_token(identity: str, expires_delta: Optional[timedelta] = None) -> str:
    return create_access_token(identity=identity, expires_delta=expires_delta)
