from sanic import Blueprint, response
import db
from models import correlate

bp = Blueprint("alerts_routes.py", url_prefix="/alert")

@bp.route("/alerts", methods=["GET"])
async def list_picked_alerts():
    """
    List all picked alerts that can be used for attackflow.
    """
    try:
        alerts = db.database.get_collection("alerts")
        alerts = list(alerts)
        for alert in alerts:
            alert['_id'] = str(alert['_id'])
        return response.json({
            "message": "All alerts retrived successfully",
            "count": len(alerts),
            "alerts": alerts
        })
    except Exception as e:
        return response.json({"error": str(e)}, status=500)

@bp.route("/alerts/<alert_id>", methods=["GET"])
async def get_alert(alert_id):
    """
    Get a specific alert by ID.
    """
    try:
        alert_collection = db.database.get_collection("alerts")
        alert = alert_collection.find_one({"_id": alert_id})
        if not alert:
            return response.json({"error": "Alert not found"}, status=404)
        return response.json({
            "message": "Alert found",
            "alert": alert
        })
    except Exception as e:
        return response.json({"error": str(e)}, status=500)
    
@bp.route("/alerts/<attackflow_id>", methods=["GET"])
async def get_alert(attackflow_id):
    """
    Get alerts related with an attackflow ID.
    """
    try:
        alert_collection = db.database.get_collection("alerts")
        alerts = alert_collection.find({"attackflow_id": attackflow_id})
        if not alerts:
            return response.json({"error": "No alerts found for this attackflow"}, status=404)
        return response.json({
            "message": "Alerts found",
            "alerts": list(alerts)
        })
    except Exception as e:
        return response.json({"error": str(e)}, status=500)

@bp.route("/ingest", methods=["POST"])
async def ingest_alerts(request):
    """
    Ingest alerts for further correlation.
    Successfully correlated alerts will be stored in the database, otherwise discarded.
    """
    try:
        req = request.json
        if not req:
            return response.json({"error": "Empty data provided"}, status=400)
        attackflow_collection = db.database.get_collection("attackflow")
    # one alert or multiple alerts at a time
        alerts = req if isinstance(req, list) else [req]
        for alert in alerts:
            # based on Technique ID to find the attackflow whose first attack action matches the technique ID
            technique_id = alert["rule"]["mitre"]["id"]
            attackflows = await attackflow_collection.find({"objects.technique_id": technique_id}).to_list(length=None)
            if not attackflows:
                return response.json({"error": "No attackflows found for the given technique ID"}, status=404)
            matched_attackflows = correlate.find_attackflows(attackflows, technique_id)
            
            # extract related fields from the alert

    except Exception as e:
        return response.json({"error": str(e)}, status=500)
    
# @bp.route("/correlate", methods=["POST"])
async def correlate_alerts(request):
    """
    Correlate alerts with attackflows and generate 
    """