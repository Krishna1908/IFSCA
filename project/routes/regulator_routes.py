from flask import Blueprint, jsonify, request
import psycopg2

from db.connection import get_db_connection
from utils.jwt_utils import generate_access_token
from utils.password_utils import hash_password, verify_password

regulator_bp = Blueprint("regulator_routes", __name__)


@regulator_bp.route("/regulator/register", methods=["POST"])
def register_regulator():
    """
    Register Regulator Admin
    ---
    tags:
      - Regulator
    summary: Register a regulator admin user
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - username
              - password
            properties:
              username:
                type: string
              password:
                type: string
              role_id:
                type: integer
                description: Optional custom role id (defaults to 2)
    responses:
      201:
        description: Regulator admin registered successfully
      400:
        description: Username already exists or invalid payload
      500:
        description: Server error
    """
    payload = request.get_json(silent=True) or {}
    username = payload.get("username")
    password = payload.get("password")
    role_id = payload.get("role_id", 2)

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
                    "regulator_admin",
                    role_id,
                    True,
                ),
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
    """
    Regulator Admin Login
    ---
    tags:
      - Regulator
    summary: Authenticate regulator admin user and issue JWT
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - username
              - password
            properties:
              username:
                type: string
              password:
                type: string
    responses:
      200:
        description: Login successful
        content:
          application/json:
            schema:
              type: object
              properties:
                access_token:
                  type: string
                username:
                  type: string
      400:
        description: Invalid request payload
      401:
        description: Invalid credentials
      500:
        description: Server error
    """
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
                WHERE username = %s AND role = 'regulator_admin' AND isactive = TRUE;
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
        return jsonify({"error": "Failed to login regulator admin."}), 500
    finally:
        conn.close()
