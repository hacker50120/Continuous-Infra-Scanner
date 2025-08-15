#!/usr/bin/env python3

import concurrent.futures
import subprocess
import json
import os
import re
import logging
from datetime import datetime
import httpx
from pymongo import MongoClient
from bson import json_util
from vulnerability_scanner import vuln_scanner
from slack_notifier import slack_notifier

# Set up logging with both file and console output
os.makedirs("logs/scan_logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("logs/scan_results.log"),
        logging.StreamHandler()  # Also log to console
    ]
)

# Import configuration
try:
    from config import WEBHOOK_URL, SCAN_PROTOCOL, MAX_WORKERS
    logging.info("Configuration imported successfully")
except ImportError as e:
    logging.error(f"Failed to import configuration: {e}")
    # Fallback values
    WEBHOOK_URL = ""
    SCAN_PROTOCOL = "tcp"
    MAX_WORKERS = 5

# Nmap command with sudo granted access profiles
# SCAN_PROFILES = {
#     "light": {
#         "tcp": "-T4 --top-ports 1000 -sS -Pn",
#         "udp": "-T4 --top-ports 1000 -sU -Pn",
#     },
#     "fast": {
#         "tcp": "-T4 -p- -sS --min-rate 5000 -Pn",
#         "udp": "-T4 -p- -sU --min-rate 2000 -Pn",
#     },
#     "deep": {
#         "tcp": "-T3 -p- -sS --max-retries 3 --max-rtt-timeout 2000ms -Pn",
#         "udp": "-T3 -p- -sU --max-retries 3 --max-rtt-timeout 2000ms -Pn",
#     },
# }

# Nmap command profiles
SCAN_PROFILES = {
    "light": {
        "tcp": "-T4 --top-ports 1000 -Pn",
        "udp": "-T4 --top-ports 1000 -Pn",
    },
    "fast": {
        "tcp": "-T4 -p- --min-rate 5000 -Pn",
        "udp": "-T4 -p- --min-rate 2000 -Pn",
    },
    "deep": {
        "tcp": "-T3 -p- --max-retries 3 --max-rtt-timeout 2000ms -Pn",
        "udp": "-T3 -p- --max-retries 3 --max-rtt-timeout 2000ms -Pn",
    },
}

# Timeout values (seconds) per phase depending on mode
PHASE_TIMEOUTS = {
    "light": {"phase1": 300, "phase2": 900, "phase3": 300},
    "fast": {"phase1": 600, "phase2": 1800, "phase3": 600},
    "deep": {"phase1": 600, "phase2": 2400, "phase3": 900},
}

def check_nmap_installation():
    """Check if nmap is installed and accessible."""
    try:
        result = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            logging.info("Nmap is installed and accessible")
            print("✅ Nmap is installed and accessible")
            return True
        else:
            logging.error("Nmap is not working properly")
            print("❌ Nmap is not working properly")
            return False
    except FileNotFoundError:
        logging.error("Nmap is not installed or not in PATH")
        print("❌ Nmap is not installed or not in PATH")
        return False
    except Exception as e:
        logging.error(f"Error checking nmap installation: {e}")
        print(f"❌ Error checking nmap: {e}")
        return False

def parse_nmap_output(output):
    """Parse nmap output to extract port information."""
    result = {}
    open_port_details = {}
    
    # Improved regex patterns
    dns_pattern = re.compile(r"Nmap scan report for (.+) \((.+)\)")
    ip_pattern = re.compile(r"Nmap scan report for (.+)")
    port_patterns = [
        re.compile(r"(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(.*)"),
        re.compile(r"(\d+)/(tcp|udp)\s+(open)\s*$"),
        re.compile(r"(\d+)\s+(tcp|udp)\s+(open)\s+(.*)"),
    ]

    lines = output.split("\n")
    for line_num, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue

        # Check for DNS and IP patterns
        dns_match = dns_pattern.match(line)
        ip_match = ip_pattern.match(line)

        if dns_match:
            result["server_dns"] = dns_match.group(1)
            result["server_ip"] = dns_match.group(2)
        elif ip_match:
            if "server_ip" not in result:
                result["server_ip"] = ip_match.group(1)

        # Check for port patterns
        for pattern in port_patterns:
            port_match = pattern.match(line)
            if port_match:
                try:
                    port_num = int(port_match.group(1))
                    proto = port_match.group(2) or "tcp"
                    groups = port_match.groups()
                    
                    status = "open"
                    service = "unknown"
                    
                    # Extract status
                    for g in groups:
                        if g in ("open", "filtered", "closed"):
                            status = g
                            break
                    
                    # Extract service if available
                    if len(groups) >= 4 and groups[3]:
                        service = groups[3].strip()

                    if status == "open":
                        port_info = {
                            "port": port_num,
                            "port_status": status,
                            "protocol": proto,
                            "service": service,
                        }
                        open_port_details[str(port_num)] = port_info
                        logging.debug(f"Found open port: {port_num}/{proto} ({service})")
                    break

                except (ValueError, IndexError) as e:
                    logging.error(f"Error parsing line {line_num}: '{line}' - {e}")
                    continue

    result["open_port_details"] = open_port_details
    logging.info(f"Total open ports found for {result.get('server_ip', 'unknown')}: {len(open_port_details)}")
    print(f"📊 Total open ports found: {len(open_port_details)}")
    return result

def run_httpx_scan(ip, ports):
    """Run HTTP/HTTPS checks on discovered ports."""
    http_details = {}
    logging.info(f"Running HTTP checks on {len(ports)} ports for {ip}")
    
    for port in ports:
        for scheme in ['http', 'https']:
            try:
                url = f"{scheme}://{ip}:{port}"
                response = httpx.get(url, timeout=5, verify=False)
                http_details[f"{port}_{scheme}"] = {
                    "url": url,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "title": extract_title(response.text) if response.text else None
                }
                logging.debug(f"HTTP check successful: {url} - {response.status_code}")
                break  # If HTTP works, don't try HTTPS
            except httpx.RequestError as e:
                http_details[f"{port}_{scheme}"] = {"url": url, "error": str(e)}
                continue
    return http_details

def extract_title(html_content):
    """Extract title from HTML content."""
    try:
        title_match = re.search(r'<title>(.*?)</title>', html_content, re.IGNORECASE)
        if title_match:
            return title_match.group(1).strip()
    except Exception:
        pass
    return None

def run_nmap_command(command, timeout_sec):
    # Add sudo prefix for nmap commands
    if command.startswith('nmap '):
        # Run Scan with Sudo priv
        # command = f'sudo {command}'
        # Run Scan without Sudo priv
        command = f'{command}'
    
    print(f"Running: {command}")
    logging.info(f"Running command: {command}")
    
    try:
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        
        output, error = process.communicate(timeout=timeout_sec)
        return process.returncode, output, error
        
    except subprocess.TimeoutExpired:
        process.kill()
        logging.warning(f"Command timed out after {timeout_sec} seconds: {command}")
        print(f"Command timed out after {timeout_sec} seconds")
        return None, "", "Timeout"
    except Exception as e:
        logging.error(f"Error running command {command}: {e}")
        return None, "", str(e)

        
    except subprocess.TimeoutExpired:
        process.kill()
        duration = (datetime.now() - start_time).total_seconds()
        logging.warning(f"Command timed out after {duration:.2f} seconds: {command}")
        print(f"⏰ Command timed out after {duration:.2f} seconds")
        return None, "", "Timeout"
    except Exception as e:
        duration = (datetime.now() - start_time).total_seconds()
        logging.error(f"Error running command after {duration:.2f} seconds: {e}")
        print(f"❌ Error after {duration:.2f} seconds: {e}")
        return None, "", str(e)

def run_comprehensive_scan(ip, protocol="tcp", mode="deep"):
    """Run comprehensive multi-phase nmap scan."""
    all_ports = {}
    protocol = protocol.lower()
    
    if protocol not in ("tcp", "udp"):
        raise ValueError("protocol must be 'tcp' or 'udp'")

    mode = mode.lower()
    if mode not in SCAN_PROFILES:
        raise ValueError("mode must be one of: light, fast, deep")

    timeouts = PHASE_TIMEOUTS.get(mode, PHASE_TIMEOUTS["deep"])

    # Phase 1: Quick scan
    print(f"🚀 Phase 1: Quick {protocol.upper()} scan ({mode}) on {ip}")
    logging.info(f"Starting Phase 1 for {ip} (mode={mode}, protocol={protocol})")

    try:
        profile_cmd = SCAN_PROFILES[mode][protocol]
        quick_command = f"nmap {profile_cmd} {ip}"
        ret, quick_output, error = run_nmap_command(quick_command, timeout_sec=timeouts["phase1"])

        if ret == 0 and quick_output:
            quick_result = parse_nmap_output(quick_output)
            all_ports.update(quick_result.get("open_port_details", {}))
            phase1_count = len(quick_result.get("open_port_details", {}))
            print(f"✅ Phase 1 found {phase1_count} ports")
            logging.info(f"Phase 1 found {phase1_count} ports for {ip}")
        else:
            print(f"⚠️  Phase 1 scan issues: {error}")
            logging.warning(f"Phase 1 scan returned non-zero for {ip}: {error}")
    except Exception as e:
        print(f"❌ Phase 1 scan failed: {e}")
        logging.error(f"Phase 1 scan failed for {ip}: {e}")

    # Phase 2: Comprehensive scan (skip for light mode)
    if mode != "light" and all_ports:  # Only run if Phase 1 found ports
        print(f"🔍 Phase 2: Comprehensive scan ({protocol.upper()}) of all 65535 ports on {ip}")
        logging.info(f"Starting Phase 2 for {ip} (mode={mode}, protocol={protocol})")

        try:
            comprehensive_profile = SCAN_PROFILES[mode][protocol]
            comprehensive_timeout = timeouts["phase2"]
            comprehensive_command = f"nmap {comprehensive_profile} {ip}"
            ret, comp_output, error = run_nmap_command(
                comprehensive_command, timeout_sec=comprehensive_timeout
            )

            if ret == 0 and comp_output:
                comp_result = parse_nmap_output(comp_output)
                all_ports.update(comp_result.get("open_port_details", {}))
                phase2_count = len(comp_result.get("open_port_details", {}))
                print(f"✅ Phase 2 found {phase2_count} total ports")
                logging.info(f"Phase 2 found {phase2_count} ports for {ip}")
            else:
                print(f"⚠️  Phase 2 scan failed or timed out: {error}")
                logging.warning(f"Phase 2 scan failed for {ip}: {error}")
        except Exception as e:
            print(f"❌ Phase 2 scan failed: {e}")
            logging.error(f"Phase 2 scan failed for {ip}: {e}")

    # Phase 3: Service detection
    if all_ports:
        port_list = ",".join(all_ports.keys())
        print(f"🔎 Phase 3: Service detection on {len(all_ports)} found ports for {ip}")
        logging.info(f"Starting Phase 3 for {ip} (mode={mode}, protocol={protocol})")

        try:
            version_command = f"nmap -p{port_list} -sV --version-intensity 5 -Pn {ip}"
            ret, version_output, error = run_nmap_command(
                version_command, timeout_sec=timeouts["phase3"]
            )

            if ret == 0 and version_output:
                version_result = parse_nmap_output(version_output)
                for port, details in version_result.get("open_port_details", {}).items():
                    if port in all_ports:
                        all_ports[port].update({
                            "service": details.get("service", all_ports[port].get("service", "unknown")),
                            "version": details.get("version", "")
                        })
                print(f"✅ Phase 3 completed service detection")
                logging.info(f"Phase 3 completed for {ip}")
            else:
                print(f"⚠️  Phase 3 version detection failed: {error}")
                logging.warning(f"Phase 3 failed for {ip}: {error}")
        except Exception as e:
            print(f"❌ Phase 3 scan failed: {e}")
            logging.error(f"Phase 3 scan failed for {ip}: {e}")

    return all_ports

def run_nmap_scan(ip, protocol="tcp", mode="deep"):
    """Main nmap scan function with comprehensive error handling."""
    try:
        print(f"\n🎯 Starting multi-phase scan for {ip} (protocol={protocol}, mode={mode})")
        logging.info(f"Starting scan for {ip} (protocol={protocol}, mode={mode})")
        
        scan_start_time = datetime.now()

        # Run the comprehensive scan
        all_ports = run_comprehensive_scan(ip, protocol=protocol, mode=mode)

        if not all_ports:
            print(f"ℹ️  No open ports found for {ip}")
            logging.info(f"No open ports found for {ip}")
            return None

        scan_duration = (datetime.now() - scan_start_time).total_seconds()
        print(f"🎉 Total unique ports found for {ip}: {len(all_ports)} (scan took {scan_duration:.2f}s)")
        print(f"📋 Ports: {sorted([int(p) for p in all_ports.keys()])}")
        logging.info(f"Total unique ports found for {ip}: {len(all_ports)}")

        # Create scan result
        nmap_result = {
            "server_ip": ip,
            "open_port_details": all_ports,
            "scanned_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_protocol": protocol,
            "scan_mode": mode,
            "scan_duration_seconds": scan_duration,
            "total_ports_found": len(all_ports)
        }

        # Run HTTP checks
        if all_ports:
            print(f"🌐 Running HTTP/HTTPS checks on {len(all_ports)} ports...")
            try:
                open_ports = [detail["port"] for detail in all_ports.values()]
                nmap_result["ports_http_details"] = run_httpx_scan(ip, open_ports)
                logging.info(f"HTTP checks completed for {ip}")
            except Exception as e:
                nmap_result["ports_http_details"] = {}
                logging.error(f"HTTP checks failed for {ip}: {e}")
                print(f"⚠️  HTTP checks failed: {e}")

        logging.info(f"Scan completed for {ip} - found {len(all_ports)} ports")
        print(f"✅ Scan completed for {ip}")
        return nmap_result

    except Exception as e:
        logging.error(f"Unexpected error in scan for {ip}: {e}")
        print(f"❌ Unexpected error scanning {ip}: {e}")
        return None

def fetch_previous_scan_data(ip, mongo_client):
    """Fetch previous scan data for comparison."""
    try:
        db = mongo_client["scan_results"]
        collection = db["nmap_scans"]
        previous_scan = collection.find_one({"server_ip": ip}, sort=[("scanned_date", -1)])
        logging.info(f"Fetched previous scan for {ip}: {'Found' if previous_scan else 'Not found'}")
        return previous_scan
    except Exception as e:
        logging.error(f"Error fetching previous scan for {ip}: {e}")
        return None

def compare_scans(previous_scan, current_scan):
    """Enhanced scan comparison with better change detection"""
    previous_ports = previous_scan.get("open_port_details", {})
    current_ports = current_scan.get("open_port_details", {})
    changes = []
    
    # Convert to sets for easier comparison
    prev_port_set = set(previous_ports.keys())
    curr_port_set = set(current_ports.keys())
    
    # New ports opened
    new_ports = curr_port_set - prev_port_set
    for port in new_ports:
        service = current_ports[port].get('service', 'unknown')
        changes.append(f"NEW: Port {port}/{current_ports[port].get('protocol', 'tcp')} opened ({service})")
    
    # Ports closed
    closed_ports = prev_port_set - curr_port_set
    for port in closed_ports:
        service = previous_ports[port].get('service', 'unknown')
        changes.append(f"CLOSED: Port {port}/{previous_ports[port].get('protocol', 'tcp')} closed ({service})")
    
    # Service changes on existing ports
    common_ports = prev_port_set & curr_port_set
    for port in common_ports:
        prev_service = previous_ports[port].get('service', 'unknown')
        curr_service = current_ports[port].get('service', 'unknown')
        if prev_service != curr_service:
            changes.append(f"CHANGED: Port {port} service changed from {prev_service} to {curr_service}")
    
    ip = current_scan.get('server_ip', 'unknown')
    logging.info(f"Scan comparison for {ip}: {len(changes)} changes detected")
    
    return changes

def save_alerts_to_mongo(ip, changes, mongo_client):
    """Enhanced alert saving with better error handling"""
    if not changes:
        logging.info(f"No changes to save for {ip}")
        return
        
    try:
        db = mongo_client["scan_results"]
        collection = db["alerts"]
        
        # Create alert document with more details
        alert_data = {
            "server_ip": ip,
            "changes": changes,
            "alert_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "alert_timestamp": datetime.now(),  # For sorting
            "total_changes": len(changes),
            "severity": "high" if len(changes) > 5 else "medium" if len(changes) > 2 else "low",
            "status": "new"
        }
        
        # Insert the alert
        result = collection.insert_one(alert_data)
        
        print(f"✅ Alert saved for {ip}: {len(changes)} changes (ID: {result.inserted_id})")
        logging.info(f"Alert saved for {ip}: {len(changes)} changes (ID: {result.inserted_id})")
        
        # Also log each change for debugging
        for change in changes:
            logging.info(f"  - {change}")
            
        return True
        
    except Exception as e:
        print(f"❌ Error saving alerts for {ip}: {e}")
        logging.error(f"Error saving alerts for {ip}: {e}")
        import traceback
        logging.error(f"Full traceback: {traceback.format_exc()}")
        return False


def send_google_chat_alert(alerts):
    """Send alerts to Google Chat webhook."""
    if not alerts or not WEBHOOK_URL:
        return

    message = format_google_chat_message(alerts)
    headers = {"Content-Type": "application/json; charset=UTF-8"}
    data = {"text": message}

    try:
        response = httpx.post(WEBHOOK_URL, headers=headers, json=data, timeout=10)
        if response.status_code == 200:
            print("📢 Alert sent to Google Chat")
            logging.info("Alert sent to Google Chat")
        else:
            print(f"⚠️  Failed to send alert to Google Chat: {response.status_code}")
            logging.error(f"Failed to send alert to Google Chat: {response.status_code}, {response.text}")
    except Exception as e:
        print(f"❌ Exception occurred while sending alert to Google Chat: {e}")
        logging.error(f"Exception occurred while sending alert to Google Chat: {e}")

def format_google_chat_message(alerts):
    """Format alert message for Google Chat."""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"*Scanner Result: {current_time}*\n\n"
    
    for ip, changes in alerts.items():
        message += f"1. *{ip}*\n"
        for change in changes:
            message += f" - {change}\n"
    
    return message

def save_alerts_to_mongo(ip, changes, mongo_client):
    """Save alert data to MongoDB."""
    try:
        db = mongo_client["scan_results"]
        collection = db["alerts"]
        alert_data = {
            "server_ip": ip,
            "changes": changes,
            "alert_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        result = collection.insert_one(alert_data)
        print(f"🔔 Alerts for {ip} saved successfully (ID: {result.inserted_id})")
        logging.info(f"Alerts for {ip} inserted successfully")
        return True
    except Exception as e:
        print(f"❌ Error saving alerts for {ip} to MongoDB: {e}")
        logging.error(f"Error saving alerts to MongoDB: {e}")
        return False

def save_to_mongo(data, mongo_client):
    """Save scan data to MongoDB with enhanced error handling."""
    if not data:
        logging.error("No data provided to save_to_mongo")
        print("❌ No data provided to save_to_mongo")
        return False

    ip = data.get("server_ip", "Unknown")
    
    try:
        logging.info(f"Attempting to save scan data for {ip}")
        print(f"💾 Saving scan data for {ip}...")
        
        # Get database and collection
        db = mongo_client["scan_results"]
        collection = db["nmap_scans"]
        
        # Validate required fields
        if "server_ip" not in data:
            logging.error("server_ip missing from data")
            print("❌ server_ip missing from data")
            return False
            
        if "scanned_date" not in data:
            data["scanned_date"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
        # Add metadata
        data["saved_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data["scan_version"] = "2.0"
        data["total_ports"] = len(data.get("open_port_details", {}))
        
        # Test MongoDB connection before inserting
        mongo_client.server_info()
        
        # Insert the document
        result = collection.insert_one(data.copy())
        
        if result.inserted_id:
            logging.info(f"✅ Data for {ip} saved successfully with ID: {result.inserted_id}")
            print(f"✅ Data for {ip} saved successfully with ID: {result.inserted_id}")
            
            # Verify the save
            count = collection.count_documents({"server_ip": ip})
            logging.info(f"Total scans for {ip} in database: {count}")
            print(f"📊 Total scans for {ip} in database: {count}")
            
            return True
        else:
            logging.error(f"❌ Failed to save data for {ip} - no insert ID returned")
            print(f"❌ Failed to save data for {ip} - no insert ID returned")
            return False
            
    except Exception as e:
        logging.error(f"❌ Error saving data for {ip} to MongoDB: {e}")
        print(f"❌ Error saving data for {ip} to MongoDB: {e}")
        return False

def main(scan_mode="deep"):
    """Main function to coordinate the scanning process."""
    print("🚀 InfraScanner Pro - Starting Security Scan")
    print("=" * 50)
    
    # Get the correct path to ip.txt (should be in project root)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir) if os.path.basename(script_dir) == 'src' else script_dir
    ip_file_path = os.path.join(project_root, "ip.txt")
    
    print(f"📋 Looking for IP list at: {ip_file_path}")
    logging.info(f"Looking for IP list at: {ip_file_path}")
    
    # Check for target list
    if not os.path.exists(ip_file_path):
        print(f"❌ ip.txt not found at {ip_file_path}. Please create file with one IP per line.")
        logging.error(f"ip.txt not found at {ip_file_path}. Please create file with one IP per line.")
        return

    with open(ip_file_path, "r") as file:
        ips = [line.strip() for line in file.readlines() if line.strip()]

    if not ips:
        print(f"❌ No IP addresses found in {ip_file_path}")
        logging.error(f"No IP addresses found in {ip_file_path}")
        return

    print(f"✅ Found {len(ips)} target IPs in {ip_file_path}")
    print(f"📝 Target IPs: {', '.join(ips)}")
    logging.info(f"Loaded {len(ips)} target IPs from {ip_file_path}: {ips}")
    

    """Main function to coordinate the scanning process."""
    print("🚀 InfraScanner Pro - Starting Security Scan")
    print("=" * 50)
    
    # Check nmap installation
    if not check_nmap_installation():
        print("❌ Cannot proceed without nmap. Please install nmap and ensure it's in your PATH.")
        return

    # Check MongoDB connection
    mongo_conn_str = os.getenv("MONGO_URI")
    if not mongo_conn_str:
        print("❌ MONGO_URI environment variable is not set. Exiting.")
        logging.error("MONGO_URI is not set. Exiting.")
        return

    try:
        print("🔗 Connecting to MongoDB...")
        mongo_client = MongoClient(mongo_conn_str, serverSelectionTimeoutMS=5000)
        mongo_client.server_info()  # Test connection
        logging.info("MongoDB connection successful")
        print("✅ MongoDB connection successful")
    except Exception as e:
        print(f"❌ Failed to connect to MongoDB: {e}")
        logging.error(f"Failed to connect to MongoDB: {e}")
        return

    # Check for target list
    if not os.path.exists("ip.txt"):
        print("❌ ip.txt not found. Please create file with one IP per line.")
        logging.error("ip.txt not found. Please create file with one IP per line.")
        return

    with open("ip.txt", "r") as file:
        ips = [line.strip() for line in file.readlines() if line.strip()]

    if not ips:
        print("❌ No IP addresses found in ip.txt")
        logging.error("No IP addresses found in ip.txt")
        return

    # Configuration
    protocol = os.getenv("SCAN_PROTOCOL", SCAN_PROTOCOL).lower()
    max_workers = min(int(os.getenv("MAX_WORKERS", MAX_WORKERS)), len(ips))
    scan_mode = scan_mode.lower()

    if scan_mode not in ["light", "fast", "deep"]:
        print(f"⚠️  Invalid scan mode: {scan_mode}. Using 'deep' as default.")
        logging.warning(f"Invalid scan mode: {scan_mode}. Using 'deep' as default.")
        scan_mode = "deep"

    print(f"📋 Scan Configuration:")
    print(f"   • Mode: {scan_mode}")
    print(f"   • Protocol: {protocol}")
    print(f"   • Targets: {len(ips)} IPs")
    print(f"   • Max Workers: {max_workers}")
    print(f"   • IPs: {', '.join(ips)}")
    print("=" * 50)

    logging.info(f"Running scan with mode={scan_mode}, protocol={protocol}, IPs={ips}")

    # Initialize result tracking
    results = []
    all_changes = {}
    vulnerability_results = []
    successful_scans = 0
    failed_scans = 0

    # Execute scans
    scan_start_time = datetime.now()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        print(f"🔄 Starting {len(ips)} scan tasks with {max_workers} workers...")
        
        future_to_ip = {
            executor.submit(run_nmap_scan, ip, protocol, scan_mode): ip for ip in ips
        }

        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                current_data = future.result()
                if current_data:
                    successful_scans += 1
                    logging.info(f"Scan successful for {ip}")

                    # Compare with previous scan
                    previous_data = fetch_previous_scan_data(ip, mongo_client)
                    if previous_data:
                        changes = compare_scans(previous_data, current_data)
                        if changes:
                            print(f"🔍 Changes detected for {ip}:")
                            for change in changes:
                                print(f"   • {change}")
                            all_changes[ip] = changes
                            save_alerts_to_mongo(ip, changes, mongo_client)

                    # Run vulnerability scan if HTTP services found
                    if current_data.get("ports_http_details"):
                        print(f"🛡️  Running vulnerability scan for {ip}...")
                        try:
                            vuln_result = vuln_scanner.run_vulnerability_scan(ip)
                            if vuln_result and "error" not in vuln_result:
                                vulnerability_results.append(vuln_result)
                                try:
                                    slack_notifier.send_vulnerability_alert(vuln_result)
                                except Exception as e:
                                    logging.warning(f"Failed to send Slack alert: {e}")
                                print(f"✅ Vulnerability scan completed for {ip}: {vuln_result.get('total_vulns', 0)} vulnerabilities found")
                        except Exception as e:
                            print(f"⚠️  Error running vulnerability scan for {ip}: {e}")
                            logging.error(f"Error running vulnerability scan for {ip}: {e}")

                    # Save to MongoDB
                    if save_to_mongo(current_data, mongo_client):
                        results.append(current_data)
                        print(f"✅ Scan data saved for {ip}")
                        logging.info(f"Scan completed and saved for {ip}")
                    else:
                        print(f"❌ Failed to save scan data for {ip}")
                        logging.error(f"Failed to save scan data for {ip} to MongoDB")
                else:
                    failed_scans += 1
                    print(f"❌ No scan data returned for {ip}")
                    logging.warning(f"No scan data returned for {ip}")

            except Exception as exc:
                failed_scans += 1
                print(f"❌ Error scanning {ip}: {exc}")
                logging.error(f"{ip} generated an exception: {exc}")

    # Send notifications for changes
    if all_changes:
        print(f"📢 Sending notifications for {len(all_changes)} changed targets...")
        try:
            send_google_chat_alert(all_changes)
            slack_notifier.send_infrastructure_change_alert(all_changes)
        except Exception as e:
            logging.error(f"Failed to send notifications: {e}")

    # Save results to files
    total_scan_time = (datetime.now() - scan_start_time).total_seconds()
    date_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    if results:
        output_filename = f"logs/scan_logs/scan_results_{date_str}.json"
        with open(output_filename, "w") as output_file:
            json.dump(results, output_file, indent=4, default=json_util.default)
        print(f"💾 Scan results saved to {output_filename}")

    if vulnerability_results:
        vuln_filename = f"logs/scan_logs/vulnerability_results_{date_str}.json"
        with open(vuln_filename, "w") as vuln_file:
            json.dump(vulnerability_results, vuln_file, indent=4, default=json_util.default)
        print(f"🛡️  Vulnerability results saved to {vuln_filename}")

    # Summary
    print("=" * 50)
    print("📊 SCAN SUMMARY")
    print("=" * 50)
    print(f"✅ Successful scans: {successful_scans}")
    print(f"❌ Failed scans: {failed_scans}")
    print(f"⏱️  Total scan time: {total_scan_time:.2f} seconds")
    print(f"🔍 Infrastructure changes detected: {len(all_changes)}")
    print(f"🛡️  Vulnerability scans completed: {len(vulnerability_results)}")
    print("=" * 50)

    logging.info(f"Scan completed - Success: {successful_scans}, Failed: {failed_scans}, Time: {total_scan_time:.2f}s")

if __name__ == "__main__":
    import sys
    scan_mode = "deep"
    if len(sys.argv) > 1:
        if sys.argv[1] in ["--light", "--full", "--deep"]:
            scan_mode = {"--light": "light", "--full": "fast", "--deep": "deep"}[sys.argv[1]]
    main(scan_mode)
