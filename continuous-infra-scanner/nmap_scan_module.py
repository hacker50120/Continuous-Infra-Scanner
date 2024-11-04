# nmap_scan_module.py
import subprocess
import json
from datetime import datetime
from pymongo import MongoClient
import os
from datetime import datetime, timedelta

# MongoDB connection string
mongo_conn_str=os.getenv('MONGO_URI')
mongo_client = MongoClient(mongo_conn_str)

db = mongo_client['scan_results']
nmap_collection = db['nmap_scans']
nessus_collection = db['nessus_scans']

def run_nmap_scan(ip, port):
    try:
        print(f"Starting scan for {ip}:{port}")
        command = f"nmap -Pn {ip} -p{port} -oX -"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"Error scanning {ip}:{port} - {e}")
        return None

def parse_nmap_output(xml_output):
    try:
        import xmltodict
        data = xmltodict.parse(xml_output)
        return data
    except Exception as e:
        print(f"Error parsing Nmap output - {e}")
        return None

def store_scan_results(ip, port, scan_data):
    try:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        document = {
            "ip": ip,
            "port": port,
            "scan_data": scan_data,
            "timestamp": timestamp
        }
        nmap_collection.insert_one(document)
        print(f"Scan results for {ip}:{port} stored successfully.")
    except Exception as e:
        print(f"Error storing scan results for {ip}:{port} - {e}")

def run_and_store_nmap_scans(ip_wise_data):
    open_ports = []
    for ip, ports in ip_wise_data.items():
        for port in ports:
            scan_output = run_nmap_scan(ip, port.split()[0])
            if scan_output:
                scan_data = parse_nmap_output(scan_output)
                store_scan_results(ip, port, scan_data)
                open_ports.append((ip, port))
    return open_ports

def get_ip_wise_scan_data():
    # Find the latest entry
    latest_entry = nessus_collection.find_one(sort=[("timestamp", -1)])
    if not latest_entry:
        return jsonify({'status': 'error', 'message': 'No scan data found'}), 404
    
    # Convert timestamp to datetime object
    latest_timestamp = datetime.strptime(latest_entry['timestamp'], '%Y-%m-%d %H:%M:%S')
    latest_date = latest_timestamp.date()
    
    # Find all entries with the latest date
    latest_scans = nessus_collection.find({
        "timestamp": {
            "$gte": latest_date.strftime('%Y-%m-%d'),
            "$lt": (latest_date + timedelta(days=1)).strftime('%Y-%m-%d')
        }
    })

    ip_wise_data = {}
    for scan in latest_scans:
        outputs = scan.get('outputs', [])
        for output in outputs:
            ports = output.get('ports', {})
            for port, hosts in ports.items():
                for host in hosts:
                    hostname = host.get('hostname', '')
                    if hostname not in ip_wise_data:
                        ip_wise_data[hostname] = []
                    ip_wise_data[hostname].append(port)
    
    return ip_wise_data, latest_date