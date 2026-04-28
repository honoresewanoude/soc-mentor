import json
import logging
from flask import Flask, render_template, jsonify, request
from dotenv import load_dotenv
from parser import get_wazuh_alerts_api, get_simulated_alerts
from llm_engine import analyze_alert
from config import APP_HOST, APP_PORT

# ========================
# CONFIG LOGS
# ========================
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

load_dotenv()

app = Flask(__name__)
analysis_cache = {}


# ========================
# ROUTES
# ========================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/alerts')
def get_alerts():
    source = request.args.get('source', 'simulated')
    logging.debug(f"[API] /api/alerts called with source={source}")

    try:
        if source == 'wazuh':
            logging.debug("[API] Calling get_wazuh_alerts_api()")

            alerts = get_wazuh_alerts_api()

            logging.debug(f"[API] Wazuh returned type={type(alerts)} value={alerts}")

            # ⚠️ IMPORTANT : distinction erreur vs vide
            if alerts is None:
                logging.warning("[API] Wazuh unreachable → fallback simulated")

                alerts = get_simulated_alerts()
                alerts[0]["rule_description"] += " (Wazuh inaccessible — mode simulé)"

                return jsonify({
                    "success": True,
                    "alerts": alerts,
                    "source": "simulated",
                    "warning": "Wazuh unreachable"
                })

        else:
            logging.debug("[API] Using simulated alerts")
            alerts = get_simulated_alerts()

        return jsonify({
            "success": True,
            "alerts": alerts,
            "source": source
        })

    except Exception as e:
        logging.error("[API] Exception while calling Wazuh", exc_info=True)

        alerts = get_simulated_alerts()

        return jsonify({
            "success": True,
            "alerts": alerts,
            "source": "simulated",
            "warning": f"Wazuh error: {str(e)}"
        })


@app.route('/api/analyze/<alert_id>', methods=['POST'])
def analyze(alert_id):
    try:
        alert_data = request.get_json()
        logging.debug(f"[API] Analyze called for alert_id={alert_id}")

        if alert_id in analysis_cache:
            logging.debug("[API] Returning cached analysis")
            return jsonify({
                "success": True,
                "result": analysis_cache[alert_id],
                "cached": True
            })

        result = analyze_alert(alert_data)

        if result.get("success"):
            analysis_cache[alert_id] = result

        return jsonify({
            "success": result.get("success", False),
            "result": result
        })

    except Exception as e:
        logging.error("[API] Analyze error", exc_info=True)
        return jsonify({
            "success": False,
            "error": str(e)
        })


@app.route('/api/stats')
def stats():
    logging.debug("[API] Stats requested")

    return jsonify({
        "total_analyzed": len(analysis_cache),
        "cached": list(analysis_cache.keys())
    })


# ========================
# MAIN
# ========================
if __name__ == '__main__':
    logging.info(f"Starting app on {APP_HOST}:{APP_PORT}")
    app.run(host=APP_HOST, port=APP_PORT, debug=False)  # nosec B104
