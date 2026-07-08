"""
Sri Vengamamba Food Court - POS System Backend
Flask API for handling billing, analytics, and inventory management (Restructured)
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_compress import Compress
from flask_jwt_extended import JWTManager
from datetime import timedelta
import os
import logging
import threading
import time
from dotenv import load_dotenv

# Blueprint Imports
from routes.auth import auth_bp
from routes.menu import menu_bp
from routes.billing import billing_bp, cleanup_old_bills
from utils.db import client

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

load_dotenv()

# App setup
app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config['COMPRESS_ALGORITHM'] = 'gzip'
app.config['COMPRESS_MIN_SIZE'] = 500
Compress(app)

app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)
jwt = JWTManager(app)

CORS(app, resources={r"/api/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"]}})

# Register Blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(menu_bp)
app.register_blueprint(billing_bp)

# Error Handlers
@app.errorhandler(404)
def not_found(error):
    if request.path.startswith('/api/'):
        return jsonify({"success": False, "error": "Not Found"}), 404
    try:
        return send_from_directory(".", "index.html")
    except Exception:
        return "<h1>404 - Page Not Found</h1><p>The page you are looking for does not exist.</p>", 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {str(error)}")
    return jsonify({"success": False, "error": "Internal Server Error"}), 500

@app.after_request
def add_header(r):
    if request.path.startswith('/static/'):
        r.headers["Cache-Control"] = "public, max-age=31536000"
    else:
        r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        r.headers["Pragma"] = "no-cache"
        r.headers["Expires"] = "0"
    return r

# Static Routes
@app.route("/")
def home():
    try:
        return send_from_directory(".", "index.html")
    except Exception as e:
        logger.error(f"Error serving index.html: {str(e)}")
        return jsonify({"error": "Could not load POS system"}), 500

@app.route("/sw.js")
def serve_sw():
    return send_from_directory("static", "sw.js")

@app.route("/manifest.json")
def serve_manifest():
    return send_from_directory("static", "manifest.json")

@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    try:
        client.admin.command('ping')
        return jsonify({"success": True, "status": "healthy", "database": "connected"}), 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({"success": False, "status": "unhealthy", "database": "disconnected"}), 500

# Cleanup Tasks
def check_and_cleanup():
    try:
        cleanup_old_bills()
    except Exception as e:
        logger.warning(f"Could not perform automatic cleanup check: {str(e)}")

def daily_cleanup_scheduler():
    while True:
        try:
            time.sleep(86400)
            logger.info("Running daily cleanup scheduler...")
            check_and_cleanup()
        except Exception as e:
            logger.error(f"Error in daily cleanup scheduler: {str(e)}")
            time.sleep(3600)

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug_mode = os.getenv("DEBUG", "True").lower() == "true"

    logger.info(f"🚀 Starting Flask server on port {port} (Debug: {debug_mode})")
    
    check_and_cleanup()

    cleanup_thread = threading.Thread(target=daily_cleanup_scheduler, daemon=True, name="DailyCleanup")
    cleanup_thread.start()
    logger.info("🔄 Daily cleanup scheduler started (runs every 24 hours)")

    app.run(debug=debug_mode, port=port, host="0.0.0.0", use_reloader=False)
