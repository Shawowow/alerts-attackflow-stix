from sanic import Blueprint, response
import db
from pymongo.errors import WriteError
from stix2patterns import run_validator

bp = Blueprint("attackflow_routes", url_prefix="/attackflow")

@bp.route("/attackflows", methods=["GET"])
async def list_attackflows():
    """
    List all attackflows.
    """
    try:
        attackflow_collection = db.database.get_collection("attackflow")
        attackflows = list(attackflow_collection)
        for attackflow in attackflows:
            attackflow['_id'] = str(attackflow['_id'])
        return response.json({
            "message": "All attackflows retrived successfully",
            "count": len(attackflows),
            "attackflows": attackflows
        })
    except Exception as e:
        return response.json({"error": str(e)}, status=500)

@bp.route("/attackflows/<attackflow_id>", methods=["GET"])
async def get_attackflow(attackflow_id):
    """
    Get a specific attackflow by ID.
    """
    try:
        attackflow_collection = db.database.get_collection("attackflow")
        attackflow = attackflow_collection.find_one({"_id": attackflow_id})
        if not attackflow:
            return response.json({"error": "Attackflow not found"}, status=404)
        return response.json({
            "message": "Attackflow found",
            "attackflow": attackflow
        })
    except Exception as e:
        return response.json({"error": str(e)}, status=500)

@bp.route("/attackflows/<attackflow_id>", methods=["PUT"])
async def update_attackflow(request, attackflow_id):
    """
    Update a specific attackflow by ID.
    """
    try:
        attackflow = db.database.get_collection("attackflow")
        attackflow_data = request.json
        if not attackflow_data:
            return response.json({"error": "No attackflow data provided"}, status=400)
        try:
            result = attackflow.update_one({"_id": attackflow_data["id"]}, {"$set": attackflow_data})
        except WriteError as e:
            return response.json({"error": str(e)}, status=400)

    except Exception as e:
        return response.json({"error": str(e)}, status=500)

@bp.route("/upload", methods=["POST"])
async def upload_attackflow(request):
    """
    Upload new attackflows.
    Currently, this function only supports uploading single validated attackflow in json format.
    Uploading .afb file is not supported yet.
    """
    try:
        attackflow = db.database.get_collection("attackflow")
        attackflow_data = request.json
        if not attackflow_data:
            return response.json({"error": "No attackflow data provided"}, status=400)
        if attackflow.find_one({"id": attackflow_data["id"]}):
            return response.json({"error": "Attackflow already exists"}, status=400)
        # check if every action node within the attackflow has a attack-condition with valid stix pattern
        attack_actions = [action for action in attackflow_data["objects"] if action["type"] == "attack-action"]
        for action in attack_actions:
            if not action["effect_refs"]:
                return response.json({"error": f"Attack action {action['name']} has no conditions defined."}, status=400)
        attack_conditions = [condition for condition in attackflow_data["object"] if condition["type"] == "attack-condition"]
        for condition in attack_conditions:
            condition["pattern"] = condition["pattern"].replace("\n", "")
            if len(run_validator(condition["pattern"])) > 0:
                return response.json({"error": f"Invalid STIX pattern in attack condition {condition['name']}: {run_validator(condition['pattern'])}"}, status=400)
            
        result = attackflow.insert_one(attackflow_data)
        return response.json({
            "message": "Attackflow uploaded successfully",
            "attackflow_id": str(result.inserted_id)
        })
    except Exception as e:
        return response.json({"error": str(e)}, status=500)

@bp.route("/attackflows/<attackflow_id>", methods=["DELETE"])
async def delete_attackflow(attackflow_id):
    """
    Delete a specific attackflow by ID.i
    """
    try:
        attackflow = db.database.get_collection("attackflow")
        result = attackflow.delete_one({"_id": attackflow_id})
        if result.deleted_count == 0:
            return response.json({"error": "Attackflow not found"}, status=404)
        return response.json({"message": "Attackflow deleted successfully"})

    except Exception as e:
        return response.json({"error": str(e)}, status=500)   
