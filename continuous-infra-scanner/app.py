from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, json
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
import os
import re
import threading
import subprocess
import signal
import requests
from bson import ObjectId
from nessus_auth_data_fetch_to_DB import fetch_nessus_data
from nessus_operations_view import view_port_wise_scan_results, view_ip_wise_scan_results
from nmap_scan_module import run_and_store_nmap_scans, get_ip_wise_scan_data
from datetime import datetime, timedelta


app = Flask(__name__)
app.secret_key = '$up3rs3Cr3tkEy'  # Required for flashing messages
console_user = os.getenv('CONSOLE_USERNAME')
console_password = os.getenv('CONSOLE_PASSWORD')
report_number_id=os.getenv('REPORT_NUMBER_ID')
# Check if the environment variables are set, and raise an error if not
if console_user is None or console_password is None:
    raise ValueError("CONSOLE_USERNAME and CONSOLE_PASSWORD environment variables must be set.")

# Setup basic auth
auth = HTTPBasicAuth()

# Generate a hashed password for the user
users = {
    console_user: generate_password_hash(console_password),
}

@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username

# MongoDB connection string from environment variable
#mongo_conn_str = os.getenv('MONGO_URI')
mongo_conn_str=os.getenv('MONGO_URI')
mongo_client = MongoClient(mongo_conn_str)

db = mongo_client['scan_results']
collection = db['nmap_scans']
alert_collection = db['alerts']
nessus_alerts_collection = db['nessus_alerts'] 

# Regular expression to match a valid IP address
IP_REGEX = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

scanner_status = {"running": False, "pid": None}

def run_scanner():
    global scanner_status
    scanner_status["running"] = True
    try:
        process = subprocess.Popen(["python3", "script.py"], preexec_fn=os.setsid)
        scanner_status["pid"] = process.pid
        process.communicate()
    finally:
        scanner_status["running"] = False
        scanner_status["pid"] = None


@app.route('/')
@auth.login_required
def index():
    return render_template('index.html', scanner_status=scanner_status)

@app.route('/edit_ips', methods=['GET', 'POST'])
@auth.login_required
def edit_ips():
    if request.method == 'POST':
        ip_list = request.form['ip_list'].splitlines()
        valid_ips = [ip for ip in ip_list if IP_REGEX.match(ip)]
        if len(valid_ips) != len(ip_list):
            flash('The list contains invalid IP addresses')
            return redirect(request.url)
        with open('ip.txt', 'w') as f:
            f.write('\n'.join(valid_ips))
        flash('IP list successfully updated')
        return redirect(url_for('index'))
    else:
        if os.path.exists('ip.txt'):
            with open('ip.txt', 'r') as f:
                ip_list = f.read()
        else:
            ip_list = ''
        return render_template('edit_ips.html', ip_list=ip_list)

@app.route('/start_scan', methods=['POST'])
@auth.login_required
def start_scan():
    if not scanner_status["running"]:
        threading.Thread(target=run_scanner).start()
        flash('Scanner started')
    else:
        flash('Scanner is already running, please wait for it to complete')
    return redirect(url_for('index'))

@app.route('/abort_scan', methods=['POST'])
@auth.login_required
def abort_scan():
    if scanner_status["running"] and scanner_status["pid"]:
        os.killpg(os.getpgid(scanner_status["pid"]), signal.SIGTERM)
        scanner_status["running"] = False
        scanner_status["pid"] = None
        flash('Scanner aborted successfully')
    else:
        flash('No running scanner to abort')
    return redirect(url_for('index'))

@app.route('/scans', methods=['GET'])
@auth.login_required
def get_scans():
    scans = collection.find().sort("scanned_date", -1)
    scan_dict = {}
    for scan in scans:
        open_port_details = scan.get("open_port_details", {})
        if isinstance(open_port_details, list):
            open_port_details = {str(port['port']): port for port in open_port_details}
        
        scan_data = {
            "server_dns": scan.get("server_dns"),
            "scanned_date": scan.get("scanned_date"),
            "open_port_details": open_port_details,
            "ports_http_details": scan.get("ports_http_details")
        }
        
        ip = scan.get("server_ip")
        if ip not in scan_dict:
            scan_dict[ip] = []
        scan_dict[ip].append(scan_data)
    
    return render_template('scans.html', scans=scan_dict)

@app.route('/alerts', methods=['GET'])
@auth.login_required
def get_alerts():
    alerts = alert_collection.find().sort("alert_date", -1)
    alerts_by_ip = {}
    for alert in alerts:
        ip = alert.get("server_ip")
        if ip not in alerts_by_ip:
            alerts_by_ip[ip] = []
        alerts_by_ip[ip].append(alert)
    return render_template('alerts.html', alerts_by_ip=alerts_by_ip)

@app.route('/status', methods=['GET'])
@auth.login_required
def get_status():
    return jsonify(scanner_status)

db = mongo_client['scan_results']
nessus_collection = db['nessus_scans']

# Use the JSONEncoder from nessus_auth_data_fetch_to_DB
#app.json_encoder = JSONEncoder


@app.route('/fetch_nessus_data', methods=['GET'])
@auth.login_required
def handle_fetch_nessus_data():
    # Assume fixed values for demonstration
    report_number = report_number_id
    plugins = [10919, 11154, 11219, 22964, 17975, 11153, 10940, 25342, 11765]
    
    # Perform the Nessus data fetch
    return fetch_nessus_data(report_number, plugins)
  
@app.route('/view_port_wise_scan_results', methods=['GET'])
def view_port_wise_scan_results_route():
    return view_port_wise_scan_results()

# @app.route('/view_ip_wise_scan_results', methods=['GET'])
# def view_ip_wise_scan_results_route():
#     return view_ip_wise_scan_results()

@app.route('/view_ip_wise_scan_results', methods=['GET'])
@auth.login_required
def view_ip_wise_scan_results_route():
    return view_ip_wise_scan_results()


@app.route('/nessus_alerts', methods=['GET'])
@auth.login_required
def get_nessus_alerts():
    alerts = nessus_alerts_collection.find().sort("timestamp", -1)
    alerts_by_ip = {}
    for alert in alerts:
        ip = alert.get("ip")
        timestamp_str = alert.get('timestamp')
        try:
            alert['parsed_timestamp'] = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            print(f"Parsed timestamp: {alert['parsed_timestamp']}")
        except (ValueError, TypeError):
            alert['parsed_timestamp'] = None
            print(f"Invalid timestamp: {timestamp_str}")
        if ip not in alerts_by_ip:
            alerts_by_ip[ip] = []
        alerts_by_ip[ip].append(alert)
    return render_template('nessus_alert.html', alerts_by_ip=alerts_by_ip)


@app.route('/start_nessus_process', methods=['GET'])
@auth.login_required
def start_nessus_process():
    fetch_data_url = url_for('handle_fetch_nessus_data', _external=True)
    view_scan_results_url = url_for('view_ip_wise_scan_results_route', _external=True)

    fetch_response = requests.get(fetch_data_url, auth=(console_user, console_password))
    if fetch_response.status_code != 200:
        return jsonify({'status': 'error', 'message': 'Failed to fetch Nessus data'}), fetch_response.status_code
    
    view_response = requests.get(view_scan_results_url, auth=(console_user, console_password))
    if view_response.status_code != 200:
        return jsonify({'status': 'error', 'message': 'Failed to view IP-wise scan results'}), view_response.status_code

    return jsonify({'status': 'success', 'message': 'Nessus data fetched and IP-wise scan results viewed successfully'})


#@app.route('/view_latest_scan_results_ipwise', methods=['GET'])
#def view_latest_scan_results_route():
 #   return render_template('alerts.html', view_latest_scan_results)
    #return view_latest_scan_results()    
    
@app.route('/start_local_scan', methods=['GET'])
@auth.login_required
def start_local_scan():
    ip_wise_data, latest_date = get_ip_wise_scan_data()
    open_ports = run_and_store_nmap_scans(ip_wise_data)
    return render_template('local_scan_results.html', open_ports=open_ports, latest_date=latest_date)

    
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8180)


