from flask import Blueprint, jsonify, request
import psycopg2

from db.connection import get_db_connection
from utils.jwt_utils import generate_access_token
from utils.password_utils import hash_password, verify_password

admin_bp = Blueprint("admin_routes", __name__)


@admin_bp.route("/admin/register", methods=["POST"])
def register_admin():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username")
    password = payload.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT admin_id FROM admin WHERE del_flag = 'N' LIMIT 1;")
            if cur.fetchone():
                return jsonify({"error": "Admin already exists."}), 400

            password_hash = hash_password(password)
            cur.execute(
                """
                INSERT INTO admin (username, password_hash, email)
                VALUES (%s, %s, %s);
                """,
                (username, password_hash, username),
            )
        conn.commit()
    except psycopg2.Error:
        conn.rollback()
        return jsonify({"error": "Failed to register admin."}), 500
    finally:
        conn.close()

    return jsonify({"message": "Admin registered successfully."}), 201


@admin_bp.route("/admin/login", methods=["POST"])
def login_admin():
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
                SELECT admin_id, username, password_hash
                FROM admin
                WHERE username = %s AND del_flag = 'N';
                """,
                (username,),
            )
            user = cur.fetchone()

        if not user or not verify_password(password, user["password_hash"]):
            return jsonify({"error": "Invalid credentials"}), 401

        access_token = generate_access_token(identity=user["username"])
        return jsonify({"access_token": access_token, "username": user["username"]}), 200
    except psycopg2.Error:
        return jsonify({"error": "Failed to login admin."}), 500
    finally:
        conn.close()
