"""Placeholder vulnerable web app for local cyber-range experiments.

The implementation is intentionally small and only simulates vulnerable behavior.
It should never be exposed outside a controlled local research environment.

TODO:
- Replace toy behavior with a more realistic intentionally vulnerable app.
- Add structured logging that can be harvested by a telemetry collector.
- Add container/runtime metadata to emitted logs.
"""

from __future__ import annotations

import logging

from flask import Flask, jsonify, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)


@app.route("/")
def index():
    app.logger.info("Index route served.")
    return jsonify({"service": "vulnerable_app", "status": "running"})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    app.logger.warning("Login attempt received for username=%s", username)
    return jsonify({"message": "Placeholder login endpoint"}), 200


@app.route("/search")
def search():
    query = request.args.get("q", "")
    app.logger.info("Search query received: %s", query)

    if "'" in query or " or " in query.lower():
        app.logger.error("Simulated database failure triggered by suspicious query.")
        return jsonify({"error": "Simulated backend exception"}), 500

    return jsonify({"results": [], "query": query}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081, debug=False)
