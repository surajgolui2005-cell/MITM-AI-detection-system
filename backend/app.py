from flask import Flask, jsonify
from flask_cors import CORS
import threading

# Import detector
from detection.detector import start_detection

app = Flask(__name__)
CORS(app)

# System status shared with detector
system_status = {
    "status": "idle",
    "alerts": []
}


@app.route("/")
def home():
    return jsonify({
        "message": "MITM AI Detection Backend Running"
    })


@app.route("/api/status", methods=["GET"])
def status():
    return jsonify(system_status)


@app.route("/api/start-detection", methods=["GET"])
def start_detection_api():

    if system_status["status"] == "running":
        return jsonify({
            "message": "Detection already running"
        })

    system_status["status"] = "running"

    # Run detector in background thread
    thread = threading.Thread(
        target=start_detection,
        args=(system_status,)
    )

    thread.daemon = True
    thread.start()

    return jsonify({
        "message": "Real-time MITM detection started"
    })


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    return jsonify({
        "alerts": system_status["alerts"]
    })


@app.route("/api/reset-alerts", methods=["GET"])
def reset_alerts():

    system_status["alerts"] = []

    return jsonify({
        "message": "Alerts cleared"
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )