#!/usr/bin/env python3
"""
Configuration file for Vulnerability Scanner
Contains settings for Slack, Google, scan thresholds, scheduler, and other parameters
"""

import os
import re
from datetime import datetime

# General Settings
SCAN_PROTOCOL = os.getenv("SCAN_PROTOCOL", "tcp") # Default to tcp
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "10"))
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
RESULTS_DIR = os.getenv("RESULTS_DIR", "logs/nuclei_results")

# Scan Thresholds
RISK_SCORE_THRESHOLD = float(os.getenv("RISK_SCORE_THRESHOLD", "50.0"))
MAX_VULNERABILITIES_THRESHOLD = int(os.getenv("MAX_VULNERABILITIES_THRESHOLD", "100"))
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "600"))
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "150"))

# Integration Settings
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")
NOTIFICATION_ENABLED = os.getenv("NOTIFICATION_ENABLED", "false").lower() == "true"

# MongoDB Settings
MONGO_URI = os.getenv("MONGO_URI", "mongodb://admin:admin123@127.0.0.1:27017/scan_results?authSource=admin")

# Scheduler Settings
SCHEDULE_TYPE = os.getenv("SCHEDULE_TYPE", "daily").lower()
SCHEDULER_DAILY_TIME = os.getenv("SCHEDULER_DAILY_TIME", "02:00")
SCHEDULER_WEEKLY_DAYS = os.getenv("SCHEDULER_WEEKLY_DAYS", "sunday").split(",")
SCHEDULER_WEEKLY_TIME = os.getenv("SCHEDULER_WEEKLY_TIME", "01:00")

# Validation and setup
if not os.path.exists(RESULTS_DIR):
    os.makedirs(RESULTS_DIR)

# Convert time strings to time objects
try:
    SCHEDULER_DAILY_TIME_OBJ = datetime.strptime(SCHEDULER_DAILY_TIME, "%H:%M").time()
    SCHEDULER_WEEKLY_TIME_OBJ = datetime.strptime(SCHEDULER_WEEKLY_TIME, "%H:%M").time()
except ValueError as e:
    raise ValueError(f"Invalid time format in scheduler settings: {e}")

# Additional validation
if SCHEDULE_TYPE not in ["daily", "weekly"]:
    raise ValueError("SCHEDULE_TYPE must be 'daily' or 'weekly'")

if not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", SCHEDULER_DAILY_TIME):
    raise ValueError("SCHEDULER_DAILY_TIME must be in HH:MM format")

if not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", SCHEDULER_WEEKLY_TIME):
    raise ValueError("SCHEDULER_WEEKLY_TIME must be in HH:MM format")

valid_days = {"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}
if not all(day.lower() in valid_days for day in SCHEDULER_WEEKLY_DAYS):
    raise ValueError("SCHEDULER_WEEKLY_DAYS must contain valid day names")

if __name__ == "__main__":
    print(f"SCAN_PROTOCOL: {SCAN_PROTOCOL}")
    print(f"MAX_WORKERS: {MAX_WORKERS}")
    print(f"WEBHOOK_URL: {WEBHOOK_URL}")
    print(f"LOG_LEVEL: {LOG_LEVEL}")
    print(f"RESULTS_DIR: {RESULTS_DIR}")
    print(f"RISK_SCORE_THRESHOLD: {RISK_SCORE_THRESHOLD}")
    print(f"MAX_VULNERABILITIES_THRESHOLD: {MAX_VULNERABILITIES_THRESHOLD}")
    print(f"SCAN_TIMEOUT: {SCAN_TIMEOUT}")
    print(f"RATE_LIMIT: {RATE_LIMIT}")
    print(f"SLACK_WEBHOOK_URL: {SLACK_WEBHOOK_URL}")
    print(f"GOOGLE_API_KEY: {GOOGLE_API_KEY}")
    print(f"NOTIFICATION_ENABLED: {NOTIFICATION_ENABLED}")
    print(f"MONGO_URI: {MONGO_URI}")
    print(f"SCHEDULE_TYPE: {SCHEDULE_TYPE}")
    print(f"SCHEDULER_DAILY_TIME: {SCHEDULER_DAILY_TIME}")
    print(f"SCHEDULER_WEEKLY_DAYS: {SCHEDULER_WEEKLY_DAYS}")
    print(f"SCHEDULER_WEEKLY_TIME: {SCHEDULER_WEEKLY_TIME}")
