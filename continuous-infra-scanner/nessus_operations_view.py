# nessus_operations_view.py
import os
from flask import jsonify, render_template
from datetime import datetime, timedelta
import requests
from mongo_connection import get_db  # Import from mongo_connection

# Google Chat webhook URL
WEBHOOK_URL = os.getenv('WEBHOOK_URL')

# Get MongoDB database instance
db = get_db('scan_results')
nessus_collection = db['nessus_scans']
sorted_collection = db['nessus_sorted_data']
alerts_collection = db['nessus_alerts']  # New collection for Nessus-generated alerts

def get_port_wise_scan_data():
    """Fetches port-wise scan data for the latest date."""
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
    
    all_ports = {}
    for scan in latest_scans:
        outputs = scan.get('outputs', [])
        for output in outputs:
            ports = output.get('ports', {})
            for port, hosts in ports.items():
                for host in hosts:
                    hostname = host.get('hostname', '')
                    if port not in all_ports:
                        all_ports[port] = []
                    all_ports[port].append(hostname)
    
    return all_ports, latest_date

def view_port_wise_scan_results():
    """Renders port-wise scan results."""
    all_ports, latest_date = get_port_wise_scan_data()
    return render_template('nessus_result_port_wise.html', all_ports=all_ports, latest_date=latest_date)

def get_ip_wise_scan_data():
    """Fetches IP-wise scan data for the latest insert_trackRecord."""
    # Fetch the latest entry from the nessus_scans collection
    latest_entry = nessus_collection.find_one(sort=[("insert_trackRecord", -1)])
    if not latest_entry:
        return jsonify({'status': 'error', 'message': 'No scan data found'}), 404

    latest_insert_trackRecord = latest_entry['insert_trackRecord']

    # Find all entries with the latest insert_trackRecord
    latest_scans = nessus_collection.find({
        "insert_trackRecord": latest_insert_trackRecord
    })

    ip_wise_data = {}
    for scan in latest_scans:
        outputs = scan.get('outputs', [])
        if outputs:
            for output in outputs:
                ports = output.get('ports', {})
                for port_description, hosts in ports.items():
                    port_number = int(port_description.split('/')[0].strip())
                    for host in hosts:
                        hostname = host.get('hostname', '')
                        if hostname not in ip_wise_data:
                            ip_wise_data[hostname] = {}
                        ip_wise_data[hostname][port_number] = port_description

    sorted_data = {}
    for ip, ports_dict in ip_wise_data.items():
        sorted_ports = sorted(ports_dict.items())
        ip_wise_data[ip] = [(port, desc) for port, desc in sorted_ports]
        sorted_data[ip] = {'ports': sorted_ports, 'timestamp': datetime.now()}

    # Insert sorted data into MongoDB
    sorted_collection.insert_one({'data': sorted_data, 'timestamp': datetime.now()})

    # Check for new or closed ports and notify
    check_and_notify_new_ports(sorted_data)

    return ip_wise_data, latest_entry['timestamp']

def check_and_notify_new_ports(sorted_data):
    """Checks for new or closed ports and triggers notifications."""
    previous_data = list(sorted_collection.find().sort('timestamp', -1).skip(1).limit(1))  # Get the second last document
    if previous_data:
        previous_data = previous_data[0]['data']
        new_ports = {}
        closed_ports = {}
        for ip, data in sorted_data.items():
            previous_ports = {port[0] for port in previous_data.get(ip, {}).get('ports', [])}
            current_ports = {port[0] for port in data['ports']}

            new_ports_for_ip = current_ports - previous_ports
            closed_ports_for_ip = previous_ports - current_ports

            if new_ports_for_ip:
                new_ports[ip] = new_ports_for_ip
            if closed_ports_for_ip:
                closed_ports[ip] = closed_ports_for_ip

        if new_ports:
            save_alert(new_ports, "New Open Ports Detected")
        if closed_ports:
            save_alert(closed_ports, "New Closed Ports Detected")

def save_alert(port_changes, alert_type):
    """Saves alerts to MongoDB and sends notifications."""
    timestamp = datetime.now()
    for ip, ports in port_changes.items():
        alert = {
            'ip': ip,
            'ports': list(ports),
            'alert_type': alert_type,
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S')  # Store as string for consistency
        }
        alerts_collection.insert_one(alert)
      
        # Notification logic
        message = f"*----::[Nessus] Port Status Changes Detected::---*\n\n{alert_type} for IP {ip}: {', '.join(str(port) for port in ports)}"
        print(message)    
        headers = {'Content-Type': 'application/json'}
        data = {"text": message}
        response = requests.post(WEBHOOK_URL, headers=headers, json=data)
        if response.status_code != 200:
            print(f"Failed to send notification: {response.status_code}, {response.text}")

def view_ip_wise_scan_results():
    """Renders IP-wise scan results."""
    ip_wise_data, latest_date = get_ip_wise_scan_data()
    return render_template('nessus_result_ip_wise.html', ip_wise_data=ip_wise_data, latest_date=latest_date)
    
# def get_ip_wise_scan_data():
#     # Find the latest entry
#     latest_entry = nessus_collection.find_one(sort=[("timestamp", -1)])
#     if not latest_entry:
#         return jsonify({'status': 'error', 'message': 'No scan data found'}), 404
    
#     # Convert timestamp to datetime object
#     latest_timestamp = datetime.strptime(latest_entry['timestamp'], '%Y-%m-%d %H:%M:%S')
#     latest_date = latest_timestamp.date()
    
#     # Find all entries with the latest date
#     latest_scans = nessus_collection.find({
#         "timestamp": {
#             "$gte": latest_date.strftime('%Y-%m-%d'),
#             "$lt": (latest_date + timedelta(days=1)).strftime('%Y-%m-%d')
#         }
#     })

#     ip_wise_data = {}
#     for scan in latest_scans:
#         outputs = scan.get('outputs', [])
#         for output in outputs:
#             ports = output.get('ports', {})
#             for port, hosts in ports.items():
#                 for host in hosts:
#                     hostname = host.get('hostname', '')
#                     if hostname not in ip_wise_data:
#                         ip_wise_data[hostname] = []
#                     ip_wise_data[hostname].append(port)
    
#     return ip_wise_data, latest_date

# def view_ip_wise_scan_results():
#     ip_wise_data, latest_date = get_ip_wise_scan_data()
#     return render_template('nessus_result_ip_wise.html', ip_wise_data=ip_wise_data, latest_date=latest_date)

# def get_ip_wise_scan_data():
#     # Find the latest entry
#     latest_entry = nessus_collection.find_one(sort=[("timestamp", -1)])
#     if not latest_entry:
#         return jsonify({'status': 'error', 'message': 'No scan data found'}), 404
    
#     # Convert timestamp to datetime object
#     latest_timestamp = datetime.strptime(latest_entry['timestamp'], '%Y-%m-%d %H:%M:%S')
#     latest_date = latest_timestamp.date()
    
#     # Find all entries with the latest date
#     latest_scans = nessus_collection.find({
#         "timestamp": {
#             "$gte": latest_date.strftime('%Y-%m-%d'),
#             "$lt": (latest_date + timedelta(days=1)).strftime('%Y-%m-%d')
#         }
#     })

#     ip_wise_data = {}
#     for scan in latest_scans:
#         outputs = scan.get('outputs', [])
#         for output in outputs:
#             ports = output.get('ports', {})
#             for port, hosts in ports.items():
#                 port_number = port.split('/')[0].strip()  # Extract port number
#                 if not port_number.isdigit():
#                     continue  # Skip if not a valid port number
#                 port_number = int(port_number)  # Convert to integer for sorting
#                 for host in hosts:
#                     hostname = host.get('hostname', '')
#                     if hostname not in ip_wise_data:
#                         ip_wise_data[hostname] = set()
#                     ip_wise_data[hostname].add(port_number)

#     # Convert sets to sorted lists
#     for ip in ip_wise_data:
#         ip_wise_data[ip] = sorted(ip_wise_data[ip])

#     return ip_wise_data, latest_date

# def view_ip_wise_scan_results():

# def get_ip_wise_scan_data():
#     # Find the latest entry
#     latest_entry = nessus_collection.find_one(sort=[("timestamp", -1)])
#     if not latest_entry:
#         return jsonify({'status': 'error', 'message': 'No scan data found'}), 404
    
#     # Convert timestamp to datetime object
#     latest_timestamp = datetime.strptime(latest_entry['timestamp'], '%Y-%m-%d %H:%M:%S')
#     latest_date = latest_timestamp.date()
    
#     # Find all entries with the latest date
#     latest_scans = nessus_collection.find({
#         "timestamp": {
#             "$gte": latest_date.strftime('%Y-%m-%d'),
#             "$lt": (latest_date + timedelta(days=1)).strftime('%Y-%m-%d')
#         }
#     })

#     ip_wise_data = {}
#     for scan in latest_scans:
#         outputs = scan.get('outputs', [])
#         for output in outputs:
#             ports = output.get('ports', {})
#             for port_description, hosts in ports.items():
#                 # Extracting port number for sorting
#                 port_number = int(port_description.split('/')[0].strip())
#                 for host in hosts:
#                     hostname = host.get('hostname', '')
#                     if hostname not in ip_wise_data:
#                         ip_wise_data[hostname] = {}
#                     # Store the full port description but ensure uniqueness
#                     ip_wise_data[hostname][port_number] = port_description
    
#     # Convert dictionaries to sorted lists of tuples
#     for ip in ip_wise_data:
#         sorted_ports = sorted(ip_wise_data[ip].items())  # Sorts by port number
#         ip_wise_data[ip] = [(port, desc) for port, desc in sorted_ports]

#     return ip_wise_data, latest_date

# def view_ip_wise_scan_results():

## IP WISE PORT SORTING AND DATA STORING

# def get_ip_wise_scan_data():
#     latest_entry = nessus_collection.find_one(sort=[("timestamp", -1)])
#     if not latest_entry:
#         return jsonify({'status': 'error', 'message': 'No scan data found'}), 404

#     latest_timestamp = datetime.strptime(latest_entry['timestamp'], '%Y-%m-%d %H:%M:%S')
#     latest_date = latest_timestamp.date()

#     latest_scans = nessus_collection.find({
#         "timestamp": {
#             "$gte": latest_date.strftime('%Y-%m-%d'),
#             "$lt": (latest_date + timedelta(days=1)).strftime('%Y-%m-%d')
#         }
#     })
#     print("Latest scan Timestamp:",latest_scans)
#     ip_wise_data = {}
#     for scan in latest_scans:
#         outputs = scan.get('outputs', [])
#         if outputs:
#             for output in outputs:
#                 ports = output.get('ports', {})
#                 for port_description, hosts in ports.items():
#                     port_number = int(port_description.split('/')[0].strip())
#                     for host in hosts:
#                         hostname = host.get('hostname', '')
#                         if hostname not in ip_wise_data:
#                             ip_wise_data[hostname] = {}
#                         ip_wise_data[hostname][port_number] = port_description
#     print("+======== Latest Scan",ip_wise_data[hostname])
#     sorted_data = {}
#     for ip, ports_dict in ip_wise_data.items():
#         sorted_ports = sorted(ports_dict.items())
#         ip_wise_data[ip] = [(port, desc) for port, desc in sorted_ports]
#         sorted_data[ip] = {'ports': sorted_ports, 'timestamp': datetime.now()}

#     # Insert into MongoDB
#     sorted_collection.insert_one({'data': sorted_data, 'timestamp': datetime.now()})
#     print("+=========++++++++++++++",sorted_data)
#     # Check for new ports and notify
#     check_and_notify_new_ports(sorted_data)

#     return ip_wise_data, latest_date
