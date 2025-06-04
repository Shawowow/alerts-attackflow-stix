from sanic import Blueprint, response
import db
from pymongo.errors import WriteError
from stix2patterns import run_validator

bp = Blueprint("correlation_routes", url_prefix="/correlation")

@bp.route("/rules", methods=["GET"])
async def list_rules():
    """
    List all correlation rules.
    """
    try:
        correlation_rule = db.database.get_collection("correlation_rules")
        rules = list(correlation_rule.find())
        for rule in rules:
            rule['_id'] = str(rule['_id'])
        return response.json({
            "message": "All correlation rules retrived successfully",
            "count": len(rules),
            "rules":rules
        })
    except Exception as e:
        return response.json({"error": str(e)}, status=500)
        

@bp.route("/rules/<rule_id>", methods=["GET"])
async def get_rule(rule_id):
    """
    Get a specific correlation rule by ID.
    """
    try:
        correlation_rule = db.database.get_collection("correlation_rules")
        rule = correlation_rule.find_one({"_id": rule_id})
        if not rule:
            return response.json({"error": "Rule not found"}, status=404)
        return response.json({
                "message": "Rule found",
                "rule": rule
            })
    except Exception as e:
        return response.json({"error": str(e)}, status=500)

@bp.route("/rules/<rule_id>", methods=["PUT"])
async def update_rule(request, rule_id):
    """
    Update a specific correlation rule by ID.
    """
    try:
        correlation_rule = db.database.get_collection("correlation_rules")
        rule = correlation_rule.find_one({"_id": rule_id})
        if not rule:
            return response.json({"error": "Rule not found"}, status=404)
        updated_data = request.json
        try:
            correlation_rule.update_one({"_id": rule_id}, {"$set": updated_data})
        except WriteError as e:
            return response.json({"error": str(e)}, status=400)
        return response.json({"message": "Rule updated successfully"})
    except Exception as e:
        return response.json({"error": str(e)}, status=500)

@bp.route("/upload", methods=["POST"])
async def upload_rule(request):
    """
    Upload new correlation rules.
    """
    try:
        req = request.json
        correlation_rule = db.database.get_collection("correlation_rules")

        if not req:
            return response.json(body={"error": "Empty data provided."}, status=400)
        
        rules = req if isinstance(req, list) else [req]
        for rule in rules:
            if "stix_pattern" not in rule:
                return response.json({"error": f"Missing stix_pattern field in rule: {rule["name"]}"}, status=400)
            validation_errors = run_validator(rule["stix_pattern"])
            if len(validation_errors) > 0:
                return response.json({"error": f"Validation failed in rule: {rule["name"]}: {validation_errors}"}, status=400)
            
        
        if len(rules) == 1:
            result = correlation_rule.insert_one(rules[0])
            return response.json({
                "message": "Rule uploaded successfully",
                "inserted_count": 1,
                "inserted_id": str(result.inserted_id)
            })
        else:
            result = correlation_rule.insert_many(rules)
            return response.json({
                "message": f"{len(result.inserted_ids)} rules uploaded successfully",
                "inserted_count": len(result.inserted_ids),
                "inserted_ids": [str(id) for id in result.inserted_ids]
            })
    except Exception as e:
        return response.json({"error": str(e)}, status=500)

@bp.route("/rules/<rule_id>", methods=["DELETE"])
async def delete_rule(rule_id):
    """
    Delete a specific correlation rule by ID.
    """
    try:
        correlation_rule = db.database.get_collection("correlation_rules")
        result = correlation_rule.delete_one({"_id": rule_id})
        if result.deleted_count == 0:
            return response.json({"error": "Correlation rule not found"}, status=404)
        return response.json({"message": "Correlation rule deleted successfully"})
    except Exception as e:
        return response.json({"error": str(e)}, status=500)

