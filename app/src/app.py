#!/usr/bin/env python3
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re
import threading
import subprocess
import signal
from bson import ObjectId
from datetime import datetime, timedelta
import psutil
from pymongo import MongoClient
import logging
from vulnerability_scanner import vuln_scanner
from flask import current_app
from frontend_config import config_bp, load_config
import secrets

app = Flask(
    __name__,
    template_folder="../templates",
    static_folder="../static"
)

# Generate secure secret key
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))

# Register config blueprint with /api prefix
app.register_blueprint(config_bp, url_prefix='/api')

# Load configuration from MongoDB
load_config()

# Set up logging for app
os.makedirs("logs/app_logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("logs/app_logs/app.log"),
        logging.StreamHandler()
    ]
)

# Authentication setup
console_user = os.getenv("CONSOLE_USERNAME", "admin")
console_password = os.getenv("CONSOLE_PASSWORD", "admin123!")  # Better default

if not console_user or not console_password:
    raise ValueError("CONSOLE_USERNAME and CONSOLE_PASSWORD must be set.")

auth = HTTPBasicAuth()
users = {console_user: generate_password_hash(console_password)}

@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username
    return None

# MongoDB connection
from mongo_connection import get_db
try:
    db = get_db()
    nmap_collection = db["nmap_scans"]
    vuln_collection = db["nuclei_vuln"]
    alert_collection = db["alerts"]
    logging.info("MongoDB collections initialized successfully")
except Exception as e:
    logging.error(f"Failed to initialize MongoDB collections: {e}")
    raise

# Global variables
IP_REGEX = re.compile(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
scanner_status = {"running": False, "messages": [], "pid": None}

def run_scanner(scan_type="light"):
    """Enhanced scanner function with proper working directory."""
    global scanner_status
    scanner_status["running"] = True
    scanner_status["messages"] = []
    
    try:
        import sys
        python_cmd = sys.executable
        scan_flags = {"light": "--light", "fast": "--full", "deep": "--deep"}
        
        if scan_type not in scan_flags:
            error_msg = f"Invalid scan type: {scan_type}. Defaulting to light."
            logging.error(error_msg)
            scanner_status["messages"].append(error_msg)
            scan_type = "light"

        # Set working directory to project root (one level up from src/)
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "script.py")
        
        cmd = [python_cmd, script_path, scan_flags[scan_type]]
        log_msg = f"Executing scanner command: {' '.join(cmd)} from directory: {project_root}"
        logging.info(log_msg)
        scanner_status["messages"].append("Vulnerability Scanner started...")

        # Set comprehensive environment variables for the subprocess
        env = os.environ.copy()
        env.update({
            "MONGO_URI": os.getenv("MONGO_URI", "mongodb://admin:admin123@127.0.0.1:27017/scan_results?authSource=admin"),
            "MONGO_HOST": os.getenv("MONGO_HOST", "127.0.0.1"),
            "MONGO_PORT": os.getenv("MONGO_PORT", "27017"),
            "MONGO_USERNAME": os.getenv("MONGO_USERNAME", "admin"),
            "MONGO_PASSWORD": os.getenv("MONGO_PASSWORD", "admin123"),
            "MONGO_DATABASE": os.getenv("MONGO_DATABASE", "scan_results"),
            "MONGO_AUTH_SOURCE": os.getenv("MONGO_AUTH_SOURCE", "admin"),
            "PYTHONPATH": os.environ.get("PYTHONPATH", "")
        })

        # Start subprocess with correct working directory
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=project_root,  # Set working directory to project root
            env=env
        )

        scanner_status["pid"] = process.pid
        logging.info(f"Scanner process started with PID: {process.pid} in directory: {project_root}")
        
        # Read output in real-time
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                line = output.strip()
                logging.info(f"Scanner output: {line}")
                scanner_status["messages"].append(line)
        
        # Get final output and check return code
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            error_msg = f"Scan failed with return code {process.returncode}: {stderr}"
            logging.error(error_msg)
            scanner_status["messages"].append(error_msg)
        else:
            success_msg = f"{scan_type.capitalize()} scan completed successfully"
            logging.info(success_msg)
            scanner_status["messages"].append(success_msg)
            
            # Verify data was saved
            try:
                total_scans_after = nmap_collection.count_documents({})
                logging.info(f"Total scans in database after scan: {total_scans_after}")
                scanner_status["messages"].append(f"Database now contains {total_scans_after} total scans")
            except Exception as e:
                logging.error(f"Error checking database after scan: {e}")

    except Exception as e:
        error_msg = f"Error running scan: {e}"
        logging.error(error_msg)
        scanner_status["messages"].append(error_msg)
    finally:
        scanner_status["running"] = False
        scanner_status["pid"] = None
        logging.info("Scanner process completed")


def run_vulnerability_scan(target_ip):
    """Enhanced vulnerability scan function."""
    global scanner_status
    scanner_status["running"] = True
    scanner_status["messages"] = []
    
    try:
        logging.info(f"Starting vulnerability scan for {target_ip}")
        scanner_status["messages"].append(f"Starting vulnerability scan for {target_ip}")
        
        with app.app_context():
            vuln_result = vuln_scanner.run_vulnerability_scan(target_ip)
            logging.debug(f"Vulnerability scan result for {target_ip}: {vuln_result}")
            
            if "error" not in vuln_result:
                success_msg = f"Vulnerability scan completed for {target_ip} with {vuln_result.get('total_vulns', 0)} vulnerabilities"
                scanner_status["messages"].append(success_msg)
                logging.info(success_msg)
            else:
                error_msg = f"Vulnerability scan failed for {target_ip}: {vuln_result.get('error')}"
                scanner_status["messages"].append(error_msg)
                logging.error(error_msg)
                
    except Exception as e:
        error_msg = f"Error running vulnerability scan: {e}"
        scanner_status["messages"].append(error_msg)
        logging.error(f"Error running vulnerability scan for {target_ip}: {e}")
    finally:
        scanner_status["running"] = False

# Routes
@app.route("/test-db", methods=["GET"])
@auth.login_required
def test_database():
    """Test database connection and show current data."""
    try:
        # Test basic connection
        db_info = db.client.server_info()
        
        # Get collection stats
        nmap_count = nmap_collection.count_documents({})
        alert_count = alert_collection.count_documents({})
        vuln_count = vuln_collection.count_documents({})
        
        # Get recent documents
        recent_scans = list(nmap_collection.find().sort("scanned_date", -1).limit(5))
        
        test_result = {
            "status": "success",
            "mongodb_version": db_info.get("version"),
            "database_name": db.name,
            "collections": db.list_collection_names(),
            "counts": {
                "nmap_scans": nmap_count,
                "alerts": alert_count,
                "vulnerabilities": vuln_count
            },
            "recent_scans": [
                {
                    "ip": scan.get("server_ip"),
                    "date": scan.get("scanned_date"),
                    "ports": len(scan.get("open_port_details", {}))
                } for scan in recent_scans
            ]
        }
        
        return jsonify(test_result), 200
        
    except Exception as e:
        logging.error(f"Database test failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/")
@auth.login_required
def index():
    try:
        # Get basic stats for the dashboard
        total_scans = nmap_collection.count_documents({})
        total_alerts = alert_collection.count_documents({})
        target_ips = len(set(nmap_collection.distinct("server_ip")))
        
        # ✅ FIXED: Proper vulnerability counting with multiple collection checks
        total_vulns = 0
        vulnerability_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        # Check nuclei_vuln collection
        vuln_results = list(vuln_collection.find().sort("timestamp", -1))
        logging.info(f"Found {len(vuln_results)} vulnerability documents in nuclei_vuln collection")
        
        for result in vuln_results:
            # Method 1: Check total_vulns field directly
            if "total_vulns" in result and isinstance(result["total_vulns"], int):
                total_vulns += result["total_vulns"]
                logging.info(f"Added {result['total_vulns']} from total_vulns field for target {result.get('target')}")
            
            # Method 2: Count vulnerabilities array
            vulnerabilities = result.get("vulnerabilities", [])
            if isinstance(vulnerabilities, list) and len(vulnerabilities) > 0:
                vuln_count = len(vulnerabilities)
                total_vulns += vuln_count
                logging.info(f"Added {vuln_count} from vulnerabilities array for target {result.get('target')}")
                
                # Count by severity
                for vuln in vulnerabilities:
                    if isinstance(vuln, dict):
                        # Try multiple severity field paths
                        severity = (
                            vuln.get("info", {}).get("severity") or 
                            vuln.get("severity") or 
                            vuln.get("classification", {}).get("cvss-severity") or
                            "info"
                        )
                        severity = str(severity).lower()
                        if severity in vulnerability_breakdown:
                            vulnerability_breakdown[severity] += 1

        # Also check if any scans are stored in different format
        alt_vuln_collection = db.get_collection("vulnerabilities") if "vulnerabilities" in db.list_collection_names() else None
        if alt_vuln_collection:
            alt_results = list(alt_vuln_collection.find())
            total_vulns += len(alt_results)
            logging.info(f"Found {len(alt_results)} additional vulnerabilities in 'vulnerabilities' collection")

        logging.info(f"Final vulnerability count: {total_vulns}")
        logging.info(f"Vulnerability breakdown: {vulnerability_breakdown}")
        
        # Calculate risk score
        risk_score = min(
            total_alerts * 5 +
            vulnerability_breakdown.get("critical", 0) * 10 +
            vulnerability_breakdown.get("high", 0) * 5 +
            vulnerability_breakdown.get("medium", 0) * 2 +
            vulnerability_breakdown.get("low", 0) * 1,
            100
        )
        
        stats = {
            "total_scans": total_scans,
            "total_alerts": total_alerts,
            "total_vulnerabilities": total_vulns,
            "target_ips": target_ips,
            "risk_score": risk_score,
            "vulnerability_breakdown": vulnerability_breakdown,
        }
        
        return render_template("index.html", scanner_status=scanner_status, stats=stats)
        
    except Exception as e:
        logging.error(f"Error calculating index stats: {e}")
        import traceback
        logging.error(f"Full traceback: {traceback.format_exc()}")
        
        # Return with empty stats on error
        stats = {
            "total_scans": 0,
            "total_alerts": 0,
            "total_vulnerabilities": 0,
            "target_ips": 0,
            "risk_score": 0,
            "vulnerability_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }
        return render_template("index.html", scanner_status=scanner_status, stats=stats)


@app.route("/edit_ips", methods=["GET", "POST"])
@auth.login_required
def edit_ips():
    # Use absolute path for ip.txt in project root
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ip_file_path = os.path.join(project_root, "ip.txt")
    
    if request.method == "POST":
        ip_list = request.form.get("ip_list", "").splitlines()
        valid_ips = []
        invalid_ips = []
        
        for ip in ip_list:
            ip = ip.strip()
            if not ip:
                continue
            if IP_REGEX.match(ip):
                valid_ips.append(ip)
            else:
                invalid_ips.append(ip)
        
        if invalid_ips:
            flash(f"Invalid IP addresses found: {', '.join(invalid_ips)}", "error")
            return redirect(request.url)
        
        try:
            with open(ip_file_path, "w") as f:
                f.write("\n".join(valid_ips))
            flash(f"IP list successfully updated with {len(valid_ips)} addresses", "success")
            logging.info(f"IP list updated at {ip_file_path} with {len(valid_ips)} addresses")
            return redirect(url_for("index"))
        except IOError as e:
            flash(f"Error writing to IP file: {e}", "error")
            return redirect(request.url)
    
    # GET request
    try:
        ip_list = ""
        if os.path.exists(ip_file_path):
            with open(ip_file_path, "r") as f:
                ip_list = f.read()
            logging.info(f"Reading IP list from {ip_file_path}")
        else:
            logging.warning(f"IP file not found at {ip_file_path}")
    except IOError as e:
        flash(f"Error reading IP file: {e}", "error")
        ip_list = ""
    
    return render_template("edit_ips.html", ip_list=ip_list)


@app.route("/start_scan", methods=["POST"])
@auth.login_required
def start_scan():
    scan_type = request.form.get("scan_type", "light").strip().lower()
    
    if scan_type not in ["light", "fast", "deep"]:
        flash(f"Invalid scan type: {scan_type}. Defaulting to light.", "warning")
        scan_type = "light"
    
    if not scanner_status["running"]:
        threading.Thread(target=run_scanner, args=(scan_type,), daemon=True).start()
        flash(f"{scan_type.capitalize()} scan started", "success")
        
        # Clear previous messages
        scanner_status["messages"] = []
    else:
        flash("Scanner is already running, please wait for it to complete", "warning")
    
    return redirect(url_for("index"))

@app.route("/abort_scan", methods=["POST"])
@auth.login_required
def abort_scan():
    if scanner_status["running"] and scanner_status.get("pid"):
        try:
            parent = psutil.Process(scanner_status["pid"])
            for child in parent.children(recursive=True):
                child.terminate()
            parent.terminate()
            
            # Wait for process to terminate gracefully
            try:
                parent.wait(timeout=10)
            except psutil.TimeoutExpired:
                parent.kill()  # Force kill if it doesn't terminate
                
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logging.warning(f"Process termination issue: {e}")
        except Exception as e:
            logging.error(f"Error terminating process: {e}")
            # Fallback for Windows
            if os.name == 'nt':
                try:
                    subprocess.run(["taskkill", "/f", "/t", "/pid", str(scanner_status["pid"])], shell=True)
                except:
                    pass
        
        scanner_status["running"] = False
        scanner_status["pid"] = None
        flash("Scanner aborted successfully", "success")
    else:
        flash("No running scanner to abort", "warning")
    
    return redirect(url_for("index"))

@app.route("/scans", methods=["GET"])
@auth.login_required
def get_scans():
    try:
        # Pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)  # 10 IPs per page
        
        # Validate pagination parameters
        if page < 1:
            page = 1
        if per_page < 5 or per_page > 50:
            per_page = 10
        
        # Get total count and unique IPs first
        total_scans = nmap_collection.count_documents({})
        unique_ips = nmap_collection.distinct("server_ip")
        total_ips = len(unique_ips)
        
        logging.info(f"Found {total_scans} total scans for {total_ips} unique IPs")
        
        # Calculate pagination
        total_pages = (total_ips + per_page - 1) // per_page  # Ceiling division
        offset = (page - 1) * per_page
        
        # Get paginated IPs
        paginated_ips = unique_ips[offset:offset + per_page]
        
        # Fetch scans for paginated IPs only
        scans = list(nmap_collection.find(
            {"server_ip": {"$in": paginated_ips}}
        ).sort("scanned_date", -1))
        
        logging.info(f"Page {page}/{total_pages}: Showing {len(paginated_ips)} IPs")
        
        # Group scans by IP
        scan_dict = {}
        for scan in scans:
            # Ensure open_port_details is a dict
            open_port_details = scan.get("open_port_details", {})
            if isinstance(open_port_details, list):
                # Convert list to dict if needed
                open_port_details = {str(port.get("port", i)): port for i, port in enumerate(open_port_details)}
            
            scan_data = {
                "server_dns": scan.get("server_dns"),
                "scanned_date": scan.get("scanned_date"),
                "open_port_details": open_port_details,
                "ports_http_details": scan.get("ports_http_details", {}),
                "scan_mode": scan.get("scan_mode", "unknown"),
                "scan_protocol": scan.get("scan_protocol", "tcp"),
            }
            
            ip = scan.get("server_ip")
            if ip:
                if ip not in scan_dict:
                    scan_dict[ip] = []
                scan_dict[ip].append(scan_data)
        
        # Ensure paginated IPs maintain order and include empty results
        ordered_scan_dict = {}
        for ip in paginated_ips:
            ordered_scan_dict[ip] = scan_dict.get(ip, [])
        
        # Pagination info
        pagination = {
            'page': page,
            'per_page': per_page,
            'total': total_ips,
            'total_pages': total_pages,
            'has_prev': page > 1,
            'has_next': page < total_pages,
            'prev_num': page - 1 if page > 1 else None,
            'next_num': page + 1 if page < total_pages else None,
            'pages': list(range(1, total_pages + 1)),
            'showing_start': offset + 1,
            'showing_end': min(offset + per_page, total_ips)
        }
        
        return render_template("scans.html", 
                             scans=ordered_scan_dict, 
                             scanned_ips=paginated_ips,
                             pagination=pagination,
                             total_scans=total_scans)
        
    except Exception as e:
        logging.error(f"Error fetching scans: {e}")
        import traceback
        logging.error(f"Full traceback: {traceback.format_exc()}")
        flash(f"Error fetching scan results: {e}", "error")
        
        # Return empty pagination on error
        empty_pagination = {
            'page': 1, 'per_page': 10, 'total': 0, 'total_pages': 0,
            'has_prev': False, 'has_next': False, 'prev_num': None, 'next_num': None,
            'pages': [], 'showing_start': 0, 'showing_end': 0
        }
        return render_template("scans.html", 
                             scans={}, 
                             scanned_ips=[],
                             pagination=empty_pagination,
                             total_scans=0)




@app.route("/alerts", methods=["GET"])
@auth.login_required
def get_alerts():
    try:
        # Get all alerts, sorted by most recent first
        alerts = list(alert_collection.find().sort("alert_timestamp", -1))
        
        # Debug logging
        logging.info(f"Found {len(alerts)} total alerts in database")
        
        # Group alerts by IP
        alerts_by_ip = {}
        total_alerts = 0
        
        for alert in alerts:
            ip = alert.get("server_ip")
            if ip:
                if ip not in alerts_by_ip:
                    alerts_by_ip[ip] = []
                alerts_by_ip[ip].append(alert)
                total_alerts += 1
        
        logging.info(f"Grouped alerts by IP: {len(alerts_by_ip)} unique IPs, {total_alerts} total alerts")
        
        # Pass additional stats
        alert_stats = {
            "total_alerts": total_alerts,
            "unique_ips": len(alerts_by_ip),
            "recent_alerts": len([a for a in alerts if a.get("status") == "new"])
        }
        
        return render_template("alerts.html", 
                             alerts_by_ip=alerts_by_ip, 
                             alert_stats=alert_stats)
        
    except Exception as e:
        logging.error(f"Error fetching alerts: {e}")
        import traceback
        logging.error(f"Full traceback: {traceback.format_exc()}")
        flash(f"Error fetching alerts: {e}", "error")
        return render_template("alerts.html", 
                             alerts_by_ip={}, 
                             alert_stats={"total_alerts": 0, "unique_ips": 0, "recent_alerts": 0})


@app.route("/vulnerabilities", methods=["GET", "POST"])
@auth.login_required
def vulnerabilities():
    try:
        # Get all scanned IPs with better error handling
        scanned_ips = []
        try:
            scanned_ips = list(nmap_collection.distinct("server_ip"))
            logging.info(f"Found {len(scanned_ips)} scanned IPs: {scanned_ips}")
        except Exception as e:
            logging.error(f"Error fetching scanned IPs: {e}")
            flash("Error fetching available targets", "error")

        # Get vulnerability results
        vuln_by_target = {}
        total_vulns = 0
        
        # Handle POST request (start vulnerability scan)
        if request.method == "POST":
            target_ip = request.form.get("target_ip", "").strip()
            logging.info(f"Vulnerability scan requested for: {target_ip}")
            
            if not target_ip:
                flash("Please select a target IP address", "error")
            elif not IP_REGEX.match(target_ip):
                flash("Invalid IP address format", "error")
            elif target_ip not in scanned_ips:
                flash(f"Target {target_ip} not found in scanned hosts. Please run an Nmap scan first.", "error")
            elif scanner_status.get("running"):
                flash("A scan is already in progress, please wait", "warning")
            else:
                def run_scan():
                    run_vulnerability_scan(target_ip)
                
                scan_thread = threading.Thread(target=run_scan, daemon=True)
                scan_thread.start()
                flash(f"Vulnerability scan initiated for {target_ip}", "success")
        
        # Get existing vulnerability results
        try:
            vuln_results = list(vuln_collection.find().sort("timestamp", -1))
            logging.info(f"Found {len(vuln_results)} vulnerability scan results")
            
            for result in vuln_results:
                target = result.get("target")
                if target not in vuln_by_target:
                    vuln_by_target[target] = []
                vuln_by_target[target].append(result)
                total_vulns += result.get("total_vulns", 0)
                
        except Exception as e:
            logging.error(f"Error fetching vulnerability results: {e}")
            flash("Error fetching vulnerability results", "error")

        logging.info(f"Returning vulnerabilities page with {len(scanned_ips)} scanned IPs and {total_vulns} total vulnerabilities")
        
        return render_template(
            "vulnerabilities.html",
            scanned_ips=scanned_ips,
            vuln_by_target=vuln_by_target,
            total_vulns=total_vulns,
        )

    except Exception as e:
        logging.error(f"Error in vulnerabilities route: {e}")
        flash(f"Error loading vulnerabilities page: {e}", "error")
        return render_template("vulnerabilities.html", scanned_ips=[], vuln_by_target={}, total_vulns=0)

@app.route("/start_vulnerability_scan", methods=["POST"])
@auth.login_required
def start_vulnerability_scan():
    target_ip = request.form.get("target_ip", "").strip()
    
    if not target_ip or not IP_REGEX.match(target_ip):
        flash("Invalid or no target IP selected", "error")
        return redirect(url_for("vulnerabilities"))
    
    if not scanner_status["running"]:
        threading.Thread(target=run_vulnerability_scan, args=(target_ip,), daemon=True).start()
        flash(f"Vulnerability scan started for {target_ip}", "success")
    else:
        flash("A scan is already running, please wait", "warning")
    
    return redirect(url_for("vulnerabilities"))

@app.route("/dashboard")
@auth.login_required
def dashboard():
    try:
        total_scans = nmap_collection.count_documents({})
        total_alerts = alert_collection.count_documents({})
        target_ips = len(set(nmap_collection.distinct("server_ip")))
        
        recent_scans = list(nmap_collection.find().sort("scanned_date", -1).limit(5))
        recent_scans_data = [
            {
                "target": scan.get("server_ip", "Unknown"),
                "timestamp": scan.get("scanned_date", "Unknown"),
                "open_ports": len(scan.get("open_port_details", {})),
                "scan_mode": scan.get("scan_mode", "unknown")
            }
            for scan in recent_scans
        ]
        
        recent_alerts = list(alert_collection.find().sort("alert_date", -1).limit(5))
        recent_alerts_data = [
            {
                "target": alert.get("server_ip", "Unknown"),
                "timestamp": alert.get("alert_date", "Unknown"),
                "changes_count": len(alert.get("changes", []))
            }
            for alert in recent_alerts
        ]
        
        vuln_results = list(vuln_collection.find().sort("timestamp", -1).limit(50))
        vulnerability_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for result in vuln_results:
            for vuln in result.get("vulnerabilities", []):
                severity = vuln.get("info", {}).get("severity", "info").lower()
                if severity in vulnerability_breakdown:
                    vulnerability_breakdown[severity] += 1
        
        # Calculate risk score more intelligently
        total_vulns = sum(vulnerability_breakdown.values())
        risk_score = min(
            total_alerts * 5 +
            vulnerability_breakdown.get("critical", 0) * 10 +
            vulnerability_breakdown.get("high", 0) * 5 +
            vulnerability_breakdown.get("medium", 0) * 2 +
            vulnerability_breakdown.get("low", 0) * 1,
            100
        )
        
        stats = {
            "total_scans": total_scans,
            "total_alerts": total_alerts,
            "total_vulnerabilities": total_vulns,
            "target_ips": target_ips,
            "risk_score": risk_score,
            "vulnerability_breakdown": vulnerability_breakdown,
            "recent_scans": recent_scans_data,
            "recent_alerts": recent_alerts_data
        }
        
        return render_template("dashboard.html", stats=stats)
        
    except Exception as e:
        logging.error(f"Error generating dashboard: {e}")
        flash(f"Error generating dashboard: {e}", "error")
        # Return empty stats on error
        stats = {
            "total_scans": 0,
            "total_alerts": 0,
            "total_vulnerabilities": 0,
            "target_ips": 0,
            "risk_score": 0,
            "vulnerability_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "recent_scans": [],
            "recent_alerts": []
        }
        return render_template("dashboard.html", stats=stats)

@app.route("/status", methods=["GET"])
@auth.login_required
def get_status():
    return jsonify({
        "running": scanner_status["running"],
        "messages": scanner_status["messages"],
        "pid": scanner_status.get("pid")
    })

@app.route("/config")
@auth.login_required
def config():
    return render_template("config.html")

@app.route('/api/time')
@auth.login_required
def get_server_time():
    """Return current server time and timezone."""
    try:
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        timezone = datetime.now().astimezone().tzname()
        return jsonify({"time": current_time, "timezone": timezone})
    except Exception as e:
        logging.error(f"Error getting server time: {e}")
        return jsonify({"error": "Failed to get server time"}), 500

@app.route("/api/stats", methods=["GET"])
@auth.login_required
def get_stats():
    """Return current system statistics."""
    try:
        total_scans = nmap_collection.count_documents({})
        total_alerts = alert_collection.count_documents({})
        target_ips = len(set(nmap_collection.distinct("server_ip")))
        
        # Get vulnerability count
        vuln_results = list(vuln_collection.find())
        total_vulnerabilities = sum(result.get("total_vulns", 0) for result in vuln_results)
        
        stats = {
            "total_scans": total_scans,
            "total_alerts": total_alerts,
            "total_vulnerabilities": total_vulnerabilities,
            "target_ips": target_ips
        }
        
        return jsonify(stats)
        
    except Exception as e:
        logging.error(f"Error fetching stats: {e}")
        return jsonify({
            "total_scans": 0,
            "total_alerts": 0,
            "total_vulnerabilities": 0,
            "target_ips": 0
        }), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error_code=500, error_message="Internal server error"), 500

@app.errorhandler(403)
def forbidden(error):
    return render_template('error.html', error_code=403, error_message="Access forbidden"), 403

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=8180, threaded=True)
