# nmap_scan_module.py
import subprocess
from datetime import datetime, timedelta
from mongo_connection import get_db  # Import from mongo_connection

# Get MongoDB database instance
db = get_db('scan_results')
nmap_collection = db['nmap_scans']
nessus_collection = db['nessus_scans']

def run_nmap_scan(ip, port):
    """Run an Nmap scan on the specified IP and port."""
    try:
        print(f"Starting scan for {ip}:{port}")
        command = f"nmap -Pn {ip} -p{port} -oX -"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"Error scanning {ip}:{port} - {e}")
        return None

def parse_nmap_output(xml_output):
    """Parse Nmap XML output into a dictionary."""
    try:
        import xmltodict
        data = xmltodict.parse(xml_output)
        return data
    except Exception as e:
        print(f"Error parsing Nmap output - {e}")
        return None

def store_scan_results(ip, port, scan_data):
    """Store Nmap scan results in MongoDB."""
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
    """Run Nmap scans and store results for the given IP-wise data."""
    open_ports = []
    for ip, ports in ip_wise_data.items():
        for port in ports:
            scan_output = run_nmap_scan(ip, port.split()[0])  # Extract port number
            if scan_output:
                scan_data = parse_nmap_output(scan_output)
                if scan_data:
                    store_scan_results(ip, port, scan_data)
                    open_ports.append((ip, port))
    return open_ports

def get_ip_wise_scan_data():
    """Fetch IP-wise scan data from the latest Nessus scans."""
    # Find the latest entry
    latest_entry = nessus_collection.find_one(sort=[("timestamp", -1)])
    if not latest_entry:
        # Note: jsonify is imported in your original code but not here; handle error differently if not in Flask context
        print("No scan data found")
        return {}, None
    
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
