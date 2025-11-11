from flask import Flask, jsonify
from flask_jwt_extended import JWTManager, get_jwt_identity, jwt_required

from config import load_config
from routes.admin_routes import admin_bp
from routes.entity_routes import entity_bp
from routes.regulator_routes import regulator_bp


def create_app() -> Flask:
    config = load_config()

    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = config["JWT_SECRET_KEY"]

    JWTManager(app)

    app.register_blueprint(admin_bp)
    app.register_blueprint(regulator_bp)
    app.register_blueprint(entity_bp)

    @app.route("/verify-token", methods=["GET"])
    @jwt_required()
    def verify_token():
        current_user = get_jwt_identity()
        return jsonify({"username": current_user}), 200

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok"}), 200

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
