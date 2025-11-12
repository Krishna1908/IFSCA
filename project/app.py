from flask import Flask, jsonify
from flask_jwt_extended import JWTManager, get_jwt_identity, jwt_required
from flasgger import Swagger

from config import load_config
from routes.admin_routes import admin_bp
from routes.entity_routes import entity_bp
from routes.regulator_routes import regulator_bp


def create_app() -> Flask:
    config = load_config()

    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = config["JWT_SECRET_KEY"]
    app.config["SWAGGER"] = {
        "title": "IFSCAPoC Authentication API",
        "uiversion": 3,
    }

    swagger_template = {
        "info": {
            "title": "IFSCAPoC Authentication API",
            "version": "1.0.0",
            "description": "Authentication endpoints for admin, regulator admin, and regulated entities.",
        },
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                }
            }
        },
    }

    JWTManager(app)
    Swagger(app, template=swagger_template)

    app.register_blueprint(admin_bp)
    app.register_blueprint(regulator_bp)
    app.register_blueprint(entity_bp)

    @app.route("/verify-token", methods=["GET"])
    @jwt_required()
    def verify_token():
        """
        Verify Access Token
        ---
        tags:
          - Auth
        security:
          - bearerAuth: []
        responses:
          200:
            description: Token valid
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    username:
                      type: string
          401:
            description: Missing or invalid token
        """
        current_user = get_jwt_identity()
        return jsonify({"username": current_user}), 200

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok"}), 200

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
