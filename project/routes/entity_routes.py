from flask import Blueprint, jsonify, request
import psycopg2

from db.connection import get_db_connection
from utils.jwt_utils import generate_access_token
from utils.password_utils import hash_password, verify_password

entity_bp = Blueprint("entity_routes", __name__)


@entity_bp.route("/entity/register", methods=["POST"])
def register_entity():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username")
    password = payload.get("password")
    role_id = payload.get("role_id", 3)

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO user_master (username, password, email, role, roleid, isactive)
                VALUES (%s, %s, %s, %s, %s, %s);
                """,
                (
                    username,
                    hash_password(password),
                    username,
                    "regulated_entity",
                    role_id,
                    True,
                ),
            )
        conn.commit()
    except psycopg2.Error as exc:
        conn.rollback()
        if getattr(exc, "pgcode", None) == "23505":
            return jsonify({"error": "Username already exists."}), 400
        return jsonify({"error": "Failed to register regulated entity."}), 500
    finally:
        conn.close()

    return jsonify({"message": "Regulated entity registered successfully."}), 201


@entity_bp.route("/entity/login", methods=["POST"])
def login_entity():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username")
    password = payload.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, username, password
                FROM user_master
                WHERE username = %s AND role = 'regulated_entity' AND isactive = TRUE;
                """,
                (username,),
            )
            user = cur.fetchone()

            if not user or not verify_password(password, user["password"]):
                return jsonify({"error": "Invalid credentials"}), 401

            cur.execute(
                "UPDATE user_master SET lastlogin = CURRENT_TIMESTAMP WHERE id = %s;",
                (user["id"],),
            )
        conn.commit()

        token = generate_access_token(identity=user["username"])
        return jsonify({"access_token": token, "username": user["username"]}), 200
    except psycopg2.Error:
        conn.rollback()
        return jsonify({"error": "Failed to login regulated entity."}), 500
    finally:
        conn.close()
