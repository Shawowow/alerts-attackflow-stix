
from sanic import Sanic
from sanic.response import json
from routes import main_routes, correlation_routes, alerts_routes, attackflow_routes, stix_routes


app = Sanic("RCTI Web Server")

# Register all blueprints (route groups)
app.blueprint(main_routes.bp)
app.blueprint(correlation_routes.bp)
app.blueprint(alerts_routes.bp)
app.blueprint(attackflow_routes.bp)
app.blueprint(stix_routes.bp)

@app.exception(Exception)
async def global_exception_handler(request, exception):
    """Handle all unhandled exceptions"""
    return json({
        "error": "Internal server error",
        "message": str(exception)
    }, status=500)

# Run the application
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)