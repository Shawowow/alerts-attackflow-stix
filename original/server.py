import re

from sanic import Sanic, response
from original.config import *
from correlate import CorrelationEngine
# from db import Neo4jDatabase
import json as json_module
import datetime
import uuid
from sanic import Sanic, response

# Initialize correlation engine and database
correlation_engine = CorrelationEngine(RULES_FILE)
# db = Neo4jDatabase(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)

# In server.py, enhance the wazuh-alerts endpoint:
# Updates to server.py - receive_wazuh_alert function

@app.route("/wazuh-alerts", methods=["POST"])
async def receive_wazuh_alert(request):
    try:
        # Step 1: Web Server gets Wazuh Alert
        logger.info(
            f"Received request at /wazuh-alerts with content type: {request.headers.get('content-type', 'None')}")

        # Parse the request body
        body = request.body
        if not body:
            logger.warning("Empty request body received")
            return response.json({"status": "error", "message": "No data received"}, status=400)

        try:
            alert_data = json_module.loads(body)
            logger.info(f"Successfully parsed JSON body: {str(alert_data)[:100]}...")
        except Exception as parse_error:
            logger.error(f"Failed to parse request body as JSON: {str(parse_error)}")
            return response.json({"status": "error", "message": f"Invalid JSON: {str(parse_error)}"}, status=400)

        # Step 2: Forward Alert to correlation engine
        logger.info("Forwarding alert to correlation engine")

        # Extract technique ID for matching
        technique_id = None
        if 'rule' in alert_data and 'mitre' in alert_data['rule'] and 'id' in alert_data['rule']['mitre']:
            mitre_ids = alert_data['rule']['mitre']['id']
            if mitre_ids and len(mitre_ids) > 0:
                technique_id = mitre_ids[0]

        if not technique_id:
            logger.warning("No MITRE ATT&CK technique ID found in alert")
            return response.json({
                "status": "not_processed",
                "message": "No MITRE ATT&CK technique ID found in alert"
            })

        # Step 3: Correlation engine performs checkTechniqueMatch_req (exactly as in sequence chart)
        logger.info(f"Correlation engine checking technique: {technique_id}")
        technique_check_result = correlation_engine.check_technique_match(technique_id)

        # Continue regardless of whether technique matches rules
        # This aligns with your sequence chart - we're just checking the technique exists
        if not technique_check_result.get("is_valid_technique", False):
            logger.warning(f"Invalid technique ID format: {technique_id}")
            return response.json({
                "status": "invalid_technique",
                "message": f"Invalid technique ID format: {technique_id}",
                "technique_check": technique_check_result
            })

        # Step 4: Forward to Attack Flow for pattern matching
        logger.info("Forwarding to attack flow handler for pattern matching")

        # Step 5: Attack flow performs checkTechnique (exactly as in sequence chart)
        attack_flow_results = attack_flow_handler.process_alert(alert_data)

        # Step 6: If pattern matches, update state
        if attack_flow_results.get("matched_node"):
            logger.info(f"Alert matched attack flow node: {attack_flow_results.get('matched_node')}")
            # State update is handled inside process_alert
        else:
            logger.info("Alert did not match expected next node in attack flow")

        # Step 7: Check if flow is completed
        flow_completed = attack_flow_results.get("sequence_valid", False)
        if flow_completed:
            logger.info("Attack flow sequence is valid")
        else:
            logger.info("Attack flow sequence is broken or incomplete")

        # Step 8: Create final response with info matching the sequence chart
        response_data = {
            "status": "success",
            "correlation_engine": {
                "status": "success",
                "technique_check": technique_check_result
            },
            "attack_flow": attack_flow_results,
            "flow_completed": flow_completed
        }

        # Step 9: Store alerts that match our criteria (optional, not in sequence chart)
        if attack_flow_results.get("has_matching_technique", False):
            # Create a filename with timestamp and unique ID
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            unique_id = str(uuid.uuid4())[:8]
            filename = f"wazuh_alert_{timestamp}_{unique_id}.json"

            # Write the alert data to a JSON file
            with open(filename, 'w') as file:
                json_module.dump({
                    "alert": alert_data,
                    "analysis": response_data
                }, file, indent=4)

            response_data["message"] = "Alert processed and stored successfully"
            response_data["filename"] = filename
        else:
            response_data["message"] = "Alert processed but did not match expected pattern"

        # Step 10: Return response to web server
        return response.json(response_data)

    except Exception as e:
        logger.error(f"Error processing alert: {str(e)}")
        return response.json({
            "status": "error",
            "message": f"Error processing alert: {str(e)}"
        }, status=500)



@app.route("/attack-flow/status", methods=["GET"])
async def get_attack_flow_status(request):
    result = attack_flow_handler.get_status()
    status_code = 200 if result.get("status") == "success" else 404
    return response.json(result, status=status_code)

@app.route("/attack-flow/history", methods=["GET"])
async def get_attack_flow_history(request):
    result = attack_flow_handler.get_history()
    status_code = 200 if result.get("status") == "success" else 404
    return response.json(result, status=status_code)

@app.route("/attack-flow/reset", methods=["POST"])
async def reset_attack_flow(request):
    result = attack_flow_handler.reset()
    status_code = 200 if result.get("status") == "success" else 404
    return response.json(result, status=status_code)
# Add a route to display all routes for debugging


# Run the server
if __name__ == "__main__":
    app.run(
        host="localhost",
        port=8000,
        debug=os.getenv("DEBUG", "False").lower() in ("true", "1", "t")
    )
