from flask import Blueprint, jsonify, request
import psycopg2

from db.connection import get_db_connection
from utils.jwt_utils import generate_access_token
from utils.password_utils import hash_password, verify_password

regulator_bp = Blueprint("regulator_routes", __name__)


@regulator_bp.route("/regulator/register", methods=["POST"])
def register_regulator():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username")
    password = payload.get("password")
    sector = payload.get("sector")

    if not username or not password or not sector:
        return jsonify({"error": "Username, password, and sector are required."}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO regulator_admin (username, password_hash, email, sector)
                VALUES (%s, %s, %s, %s);
                """,
                (username, hash_password(password), username, sector),
            )
        conn.commit()
    except psycopg2.Error as exc:
        conn.rollback()
        if getattr(exc, "pgcode", None) == "23505":
            return jsonify({"error": "Username already exists."}), 400
        return jsonify({"error": "Failed to register regulator admin."}), 500
    finally:
        conn.close()

    return jsonify({"message": "Regulator admin registered successfully."}), 201


@regulator_bp.route("/regulator/login", methods=["POST"])
def login_regulator():
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
                SELECT rgadmin_id, username, password_hash
                FROM regulator_admin
                WHERE username = %s AND del_flag = 'N';
                """,
                (username,),
            )
            user = cur.fetchone()

        if not user or not verify_password(password, user["password_hash"]):
            return jsonify({"error": "Invalid credentials"}), 401

        token = generate_access_token(identity=user["username"])
        return jsonify({"access_token": token, "username": user["username"]}), 200
    except psycopg2.Error:
        return jsonify({"error": "Failed to login regulator admin."}), 500
    finally:
        conn.close()
