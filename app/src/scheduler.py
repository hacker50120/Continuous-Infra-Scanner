#!/usr/bin/env python3
"""
Automated Scanner Scheduler
Runs vulnerability scans at scheduled intervals.
"""

import schedule
import time
import logging
import os
from datetime import datetime
from script import main as run_scan
from dotenv import load_dotenv

# Load .env
load_dotenv()

# Logging
os.makedirs('logs', exist_ok=True)
logging.basicConfig(
    filename='logs/scheduler.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def scheduled_scan():
    """Run a scheduled vulnerability scan."""
    try:
        logging.info("Starting scheduled vulnerability scan")
        print(f"[{datetime.now()}] Starting scheduled scan...")
        run_scan()
        logging.info("Scheduled vulnerability scan completed successfully")
        print(f"[{datetime.now()}] Scheduled scan completed successfully")
    except Exception as e:
        error_msg = f"Error during scheduled scan: {e}"
        logging.error(error_msg)
        print(f"[{datetime.now()}] ERROR: {error_msg}")

def setup_schedule():
    """Setup scanning schedule from env vars."""
    daily_time = os.getenv("SCHEDULER_DAILY_TIME", "02:00")
    weekly_days = os.getenv("SCHEDULER_WEEKLY_DAYS", "").split(',')
    weekly_time = os.getenv("SCHEDULER_WEEKLY_TIME", "01:00")
    schedule_type = os.getenv("SCHEDULE_TYPE", "daily").lower()

    if schedule_type == "daily" and daily_time:
        schedule.every().day.at(daily_time).do(scheduled_scan)
        logging.info(f"Scheduled daily scan at {daily_time}")
    elif schedule_type == "weekly" and weekly_days and weekly_time:
        valid_days = {"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}
        for day in [d.lower() for d in weekly_days if d]:
            if day in valid_days:
                getattr(schedule.every(), day).at(weekly_time).do(scheduled_scan)
                logging.info(f"Scheduled weekly scan on {day} at {weekly_time}")
            else:
                logging.error(f"Invalid weekly day: {day}")
    logging.info("Scheduler setup completed")

def main():
    """Run the scheduler loop."""
    print("Starting InfraScanner Pro Scheduler...")
    logging.info("InfraScanner Pro Scheduler started")
    setup_schedule()
    print("Running initial scan on startup...")
    scheduled_scan()
    while True:
        try:
            schedule.run_pending()
            time.sleep(60)
        except KeyboardInterrupt:
            print("\nScheduler stopped by user")
            logging.info("Scheduler stopped by user")
            break
        except Exception as e:
            error_msg = f"Scheduler error: {e}"
            logging.error(error_msg)
            print(f"ERROR: {error_msg}")
            time.sleep(300)

if __name__ == "__main__":
    main()
