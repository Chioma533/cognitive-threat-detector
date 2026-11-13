from collections.abc import Mapping

from flask import Flask, jsonify
from flask_cors import CORS
from werkzeug.exceptions import RequestEntityTooLarge

from app.config import Config
from app.cognition.orchestrator import AssessmentOrchestrator
from app.api.assessments import assessments_blueprint
from app.api.batch_assessments import batch_assessments_blueprint


def create_app(config_overrides: Mapping[str, object] | None = None) -> Flask:
    app = Flask(__name__)

    app.config.from_object(Config)
    if config_overrides is not None:
        app.config.update(config_overrides)

    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": ["https://ct-detector.vercel.app"]
            }
        },
    )

    app.config["MAX_CONTENT_LENGTH"] = 11 * 1024 * 1024

    orchestrator = app.config.get("ASSESSMENT_ORCHESTRATOR")
    if orchestrator is None:
        orchestrator = AssessmentOrchestrator()
    app.extensions["assessment_orchestrator"] = orchestrator

    @app.get("/api/v1/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.errorhandler(RequestEntityTooLarge)
    def request_too_large(_error: RequestEntityTooLarge):
        return (
            jsonify(
                {
                    "error": {
                        "code": "UPLOAD_TOO_LARGE",
                        "message": "Multipart request exceeds the 11 MiB request limit.",
                    }
                }
            ),
            413,
        )

    app.register_blueprint(assessments_blueprint)
    app.register_blueprint(batch_assessments_blueprint)

    return app