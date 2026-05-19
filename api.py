from flask import Flask, jsonify
from flask_cors import CORS
from LiveCapture import LiveCapture
import threading
import time

app= Flask(__name__)
CORS(app)

detector= LiveCapture(filter="inbound")

@app.route("/start", methods=["POST"])
def start():
   if detector._running:
       return jsonify({"status": "already_running"})
   time.sleep(0.2) 
   t= threading.Thread(target=detector.run, daemon=True)
   t.start()
   return jsonify({"status": "started"})

@app.route("/stats", methods=["GET"])
def stats():
    return jsonify(detector.get_stats())

@app.route("/alerts", methods=["GET"])
def alerts():
    return jsonify(detector.get_alerts())

@app.route("/alerts", methods=["DELETE"])
def clear_alerts():
    detector.alerts.clear()
    return jsonify({"status": "cleared"})

@app.route("/stop", methods=["POST"])
def stop():
    detector.stop()
    return jsonify({"status": "stopped"})


if __name__ == "__main__":
    app.run(port=5000, debug=False)
