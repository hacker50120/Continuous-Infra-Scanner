#!/usr/bin/env python3
"""
Frontend Configuration Manager
Handles updates to configuration settings via REST API and stores them in MongoDB
"""

import os
import re
import json
from datetime import datetime
from flask import Blueprint, request, jsonify
import logging
from mongo_connection import get_db

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Blueprint for config routes
config_bp = Blueprint('config', __name__)

# MongoDB collection
db = get_db()
config_collection = db["config_settings"]

# Allowed configuration keys with improved regex patterns for validation
ALLOWED_CONFIG = {
    "MAX_WORKERS": r"^([1-9]|[1-9][0-9]|100)$",
    "RISK_SCORE_THRESHOLD": r"^(0|[1-9][0-9]?(\.\d+)?|100(\.0+)?)$",
    "MAX_VULNERABILITIES_THRESHOLD": r"^([1-9]|[1-9][0-9]{1,3}|10000)$",
    "SCAN_TIMEOUT": r"^([1-9][0-9]{1,3}|[1-5][0-9]{4}|60000)$",
    "RATE_LIMIT": r"^([1-9]|[1-9][0-9]|[1-4][0-9]{2}|500)$",
    "SLACK_WEBHOOK_URL": r"^(https://hooks\.slack\.com/services/[A-Z0-9]{9,}/[A-Z0-9]{9,}/[A-Za-z0-9]{24,}|)$",
    "GOOGLE_API_KEY": r"^([A-Za-z0-9_\-]{20,}|)$",
    "NOTIFICATION_ENABLED": r"^(true|false)$",
    "SCHEDULER_DAILY_TIME": r"^([01]\d|2[0-3]):[0-5]\d$",
    "SCHEDULER_WEEKLY_DAYS": r"^(monday|tuesday|wednesday|thursday|friday|saturday|sunday)(,(monday|tuesday|wednesday|thursday|friday|saturday|sunday))*$",
    "SCHEDULER_WEEKLY_TIME": r"^([01]\d|2[0-3]):[0-5]\d$"
}

# Default values with better defaults
DEFAULT_CONFIG = {
    "MAX_WORKERS": 10,
    "RISK_SCORE_THRESHOLD": 50.0,
    "MAX_VULNERABILITIES_THRESHOLD": 100,
    "SCAN_TIMEOUT": 600,
    "RATE_LIMIT": 150,
    "SLACK_WEBHOOK_URL": "",
    "GOOGLE_API_KEY": "",
    "NOTIFICATION_ENABLED": False,
    "SCHEDULER_DAILY_TIME": "02:00",
    "SCHEDULER_WEEKLY_DAYS": "sunday",
    "SCHEDULER_WEEKLY_TIME": "01:00",
    "SCHEDULE_TYPE": "daily"
}

@config_bp.route('/config', methods=['GET'], endpoint='get_config')
def get_config():
    """Retrieve current configuration settings."""
    try:
        config_doc = config_collection.find_one({"type": "global"})
        if not config_doc:
            # Initialize with defaults if no config exists
            config_collection.insert_one({
                "type": "global",
                "settings": DEFAULT_CONFIG,
                "created_at": datetime.utcnow(),
                "last_updated": datetime.utcnow()
            })
            return jsonify(DEFAULT_CONFIG), 200

        config = config_doc.get("settings", {})
        # Ensure all default keys exist
        for key, value in DEFAULT_CONFIG.items():
            if key not in config:
                config[key] = value

        return jsonify(config), 200

    except Exception as e:
        logger.error(f"Error retrieving configuration: {e}")
        return jsonify({"error": f"Failed to retrieve configuration: {str(e)}"}), 500

@config_bp.route('/config', methods=['POST'], endpoint='update_config')
def update_config():
    """Update configuration settings with validation."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Get current config for merging
        current_config_doc = config_collection.find_one({"type": "global"})
        current_config = current_config_doc.get("settings", DEFAULT_CONFIG) if current_config_doc else DEFAULT_CONFIG.copy()

        # Check for unknown keys
        allowed_keys = set(ALLOWED_CONFIG.keys()) | {"SCHEDULE_TYPE"}
        for key in data.keys():
            if key not in allowed_keys:
                return jsonify({"error": f"Invalid configuration key: {key}"}), 400

        # Validate each field using regex
        validated_config = current_config.copy()
        schedule_type = data.get("SCHEDULE_TYPE", current_config.get("SCHEDULE_TYPE", "daily")).lower()

        for key, pattern in ALLOWED_CONFIG.items():
            value = data.get(key)
            if value is None:
                continue

            value_str = str(value).lower() if isinstance(value, bool) else str(value)
            if not re.fullmatch(pattern, value_str):
                return jsonify({"error": f"Invalid value for {key}: {value}"}), 400

            # Convert types where necessary
            if key in ["MAX_WORKERS", "MAX_VULNERABILITIES_THRESHOLD", "SCAN_TIMEOUT", "RATE_LIMIT"]:
                validated_config[key] = int(value)
            elif key == "RISK_SCORE_THRESHOLD":
                validated_config[key] = float(value)
            elif key == "NOTIFICATION_ENABLED":
                validated_config[key] = (value_str == "true")
            else:
                validated_config[key] = value

        # Handle scheduler fields based on schedule type
        if schedule_type == "daily":
            if "SCHEDULER_DAILY_TIME" in data:
                validated_config["SCHEDULER_DAILY_TIME"] = data["SCHEDULER_DAILY_TIME"]
            validated_config.pop("SCHEDULER_WEEKLY_DAYS", None)
            validated_config.pop("SCHEDULER_WEEKLY_TIME", None)
        elif schedule_type == "weekly":
            # Handle multiple selected days
            if request.content_type == 'application/json':
                # From JavaScript/AJAX
                weekly_days = data.get("SCHEDULER_WEEKLY_DAYS", "")
                if isinstance(weekly_days, list):
                    weekly_days = ",".join(weekly_days)
            else:
                # From HTML form
                weekly_days_list = request.form.getlist("SCHEDULER_WEEKLY_DAYS")
                weekly_days = ",".join(weekly_days_list) if weekly_days_list else "sunday"
            
            weekly_time = data.get("SCHEDULER_WEEKLY_TIME", "01:00")
            
            if weekly_days:
                # Validate weekly days
                days = [day.strip().lower() for day in weekly_days.split(',')]
                valid_days = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
                if not all(day in valid_days for day in days):
                    return jsonify({"error": "Invalid weekly days specified"}), 400
                validated_config["SCHEDULER_WEEKLY_DAYS"] = weekly_days.lower()
            
            if weekly_time:
               validated_config["SCHEDULER_WEEKLY_TIME"] = weekly_time
            
            validated_config.pop("SCHEDULER_DAILY_TIME", None)

        validated_config["SCHEDULE_TYPE"] = schedule_type

        # Update MongoDB
        update_result = config_collection.update_one(
            {"type": "global"},
            {
                "$set": {
                    "settings": validated_config,
                    "last_updated": datetime.utcnow()
                },
                "$setOnInsert": {
                    "created_at": datetime.utcnow(),
                    "type": "global"
                }
            },
            upsert=True
        )

        # Update environment variables
        for key, value in validated_config.items():
            os.environ[key] = str(value)

        logger.info(f"Configuration updated successfully: {update_result.modified_count} documents modified")
        return jsonify({
            "message": "Configuration updated successfully",
            "settings": validated_config
        }), 200

    except ValueError as e:
        logger.error(f"Validation error: {e}")
        return jsonify({"error": f"Validation error: {str(e)}"}), 400
    except Exception as e:
        logger.error(f"Error updating configuration: {e}")
        return jsonify({"error": f"Failed to update configuration: {str(e)}"}), 500

def load_config():
    """Load config from MongoDB and update environment variables."""
    try:
        config_doc = config_collection.find_one({"type": "global"})
        if config_doc:
            settings = config_doc.get("settings", {})
            for key, value in settings.items():
                os.environ[key] = str(value)
            logger.info("Configuration loaded from MongoDB")
        else:
            logger.warning("No config found in MongoDB, using defaults")
            # Set defaults if no config exists
            for key, value in DEFAULT_CONFIG.items():
                os.environ[key] = str(value)
            
            # Initialize database with defaults
            config_collection.insert_one({
                "type": "global",
                "settings": DEFAULT_CONFIG,
                "created_at": datetime.utcnow(),
                "last_updated": datetime.utcnow()
            })
            logger.info("Default configuration initialized in MongoDB")

    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        # Fallback to defaults
        for key, value in DEFAULT_CONFIG.items():
            os.environ[key] = str(value)
