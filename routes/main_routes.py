from sanic import Blueprint, response

bp = Blueprint("main_routes")

@bp.route("/")
async def home(request):
    return response.text("Wazuh Correlation Server - Home Page")

@bp.route("/health", methods=["GET"])
async def health_check(request):
    return response.json({"status": "healthy"})

@bp.route("/routes")
async def list_routes(request):
    routes = []
    for route in request.app.router.routes:
        routes.append({
            "path": route.path,
            "methods": list(route.methods)
        })
    return response.json({"routes": routes})