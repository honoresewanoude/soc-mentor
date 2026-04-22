import json
from flask import Flask, render_template, jsonify, request
from dotenv import load_dotenv
from parser import get_simulated_alerts, get_wazuh_alerts_ssh
from llm_engine import analyze_alert
from config import APP_HOST, APP_PORT

load_dotenv()

app = Flask(__name__)
analysis_cache = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/alerts')
def get_alerts():
    source = request.args.get('source', 'simulated')
    try:
        if source == 'wazuh':
            alerts = get_wazuh_alerts_ssh()
            if not alerts:
                # Fallback sur simulé si Wazuh inaccessible
                alerts = get_simulated_alerts()[:1]
                alerts[0]["rule_description"] = "Alerte simulée (Wazuh inaccessible)"
                alerts[0]["id"] = "WAZUH-KO"
        else:
            alerts = get_simulated_alerts()
        return jsonify({"success": True, "alerts": alerts, "source": source})
    except Exception as e:
        return jsonify({"success": False, "error": str(e), "alerts": []})

@app.route('/api/analyze/<alert_id>', methods=['POST'])
def analyze(alert_id):
    try:
        alert_data = request.get_json()
        if alert_id in analysis_cache:
            return jsonify({"success": True, "result": analysis_cache[alert_id], "cached": True})
        result = analyze_alert(alert_data)
        if result["success"]:
            analysis_cache[alert_id] = result
        return jsonify({"success": result["success"], "result": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/stats')
def stats():
    return jsonify({
        "total_analyzed": len(analysis_cache),
        "cached": list(analysis_cache.keys())
    })

if __name__ == '__main__':
    app.run(host=APP_HOST, port=APP_PORT, debug=False)  # nosec B104
