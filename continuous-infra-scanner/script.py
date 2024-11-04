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

# Set up logging
os.makedirs('logs/scan_logs', exist_ok=True)
logging.basicConfig(filename='logs/scan_results.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Google Chat webhook URL
WEBHOOK_URL = os.getenv('WEBHOOK_URL')
def parse_nmap_output(output):
    result = {}
    open_port_details = {}
    
    dns_pattern = re.compile(r'Nmap scan report for (.+) \((.+)\)')
    ip_pattern = re.compile(r'Nmap scan report for (.+)')
    port_pattern = re.compile(r'(\d+)/tcp\s+(\w+)\s+(.+)')
    
    lines = output.split('\n')
    for line in lines:
        dns_match = dns_pattern.match(line)
        ip_match = ip_pattern.match(line)
        port_match = port_pattern.match(line)
        
        if dns_match:
            result['server_dns'] = dns_match.group(1)
            result['server_ip'] = dns_match.group(2)
        elif ip_match:
            result['server_ip'] = ip_match.group(1)
        
        if port_match:
            port_info = {
                'port': int(port_match.group(1)),
                'port_status': port_match.group(2),
                'protocol': 'tcp',
                'service': port_match.group(3)
            }
            open_port_details[str(port_info['port'])] = port_info
    
    result['open_port_details'] = open_port_details
    return result

def run_httpx_scan(ip, ports):
    http_details = {}
    for port in ports:
        try:
            url = f"http://{ip}:{port}"
            response = httpx.get(url, timeout=5)
            http_details[str(port)] = {
                "status_code": response.status_code,
                "headers": dict(response.headers)
            }
        except httpx.RequestError as e:
            http_details[str(port)] = {"error": str(e)}
    return http_details

def run_nmap_scan(ip):
    try:
        print(f"Starting scan for {ip}")
        # Run the nmap command as a subprocess and capture the output
        command = f"nmap -p- -T3 --max-retries 1 --min-rate 5000 --min-hostgroup 64 --max-hostgroup 128 -sS --host-timeout 4m -Pn {ip}"
        output = subprocess.check_output(command, shell=True, universal_newlines=True)
        logging.info(f"Scan completed for {ip}")
        nmap_result = parse_nmap_output(output)
        open_ports = [detail['port'] for detail in nmap_result.get('open_port_details', {}).values()]
        nmap_result['ports_http_details'] = run_httpx_scan(ip, open_ports)
        nmap_result['scanned_date'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return nmap_result
    except subprocess.CalledProcessError as e:
        logging.error(f"Error scanning {ip}: {e}")
        return None

def fetch_previous_scan_data(ip, mongo_client):
    db = mongo_client['scan_results']
    collection = db['nmap_scans']
    previous_scan = collection.find_one({'server_ip': ip}, sort=[('scanned_date', -1)])
    return previous_scan

def compare_scans(previous_scan, current_scan):
    previous_ports = previous_scan.get('open_port_details', {})
    current_ports = current_scan.get('open_port_details', {})
    changes = []

    # Check for newly opened ports
    for port, details in current_ports.items():
        if port not in previous_ports:
            changes.append(f"Port {port} was closed and is now open.")

    # Check for newly closed ports
    for port in previous_ports:
        if port not in current_ports:
            changes.append(f"Port {port} was open and is now closed.")

    return changes

def format_google_chat_message(alerts):
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"*Scanner Result: {current_time}*\n\n"
    
    for ip, changes in alerts.items():
        message += f"1. *{ip}*\n"
        for change in changes:
            port = change.split(" ")[1]
            message += f"    - [{change}](http://{ip}:{port})\n"
    
    return message

def send_google_chat_alert(alerts):
    if not alerts:
        return
    
    message = format_google_chat_message(alerts)
    
    headers = {'Content-Type': 'application/json; charset=UTF-8'}
    data = {"text": message}
    
    try:
        response = httpx.post(WEBHOOK_URL, headers=headers, json=data)
        if response.status_code == 200:
            print("Alert sent to Google Chat")
        else:
            print(f"Failed to send alert to Google Chat: {response.status_code}, {response.text}")
    except Exception as e:
        print(f"Exception occurred while sending alert to Google Chat: {e}")

def save_alerts_to_mongo(ip, changes, mongo_client):
    try:
        db = mongo_client['scan_results']
        collection = db['alerts']
        alert_data = {
            "server_ip": ip,
            "changes": changes,
            "alert_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        collection.insert_one(alert_data)
        print(f"Alerts for {ip} inserted successfully")
    except Exception as e:
        print(f"Error saving alerts for {ip} to MongoDB: {e}")
        logging.error(f"Error saving alerts to MongoDB: {e}")

def save_to_mongo(data, mongo_client):
    try:
        db = mongo_client['scan_results']
        collection = db['nmap_scans']
        result = collection.insert_one(data)
        data['_id'] = str(result.inserted_id)  # Convert ObjectId to string
        print(f"Data for {data['server_ip']} inserted successfully")
    except Exception as e:
        print(f"Error saving data for {data['server_ip']} to MongoDB: {e}")
        logging.error(f"Error saving data to MongoDB: {e}")

def main():
    # MongoDB connection string
    mongo_conn_str=os.getenv('MONGO_URI')
    mongo_client = MongoClient(mongo_conn_str)
    
    # Read IPs from ip.txt
    with open('ip.txt', 'r') as file:
        ips = [line.strip() for line in file.readlines() if line.strip()]

    if not ips:
        print("No IP addresses found in ip.txt")
        return

    results = []
    all_changes = {}

    # Run Nmap scans concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=7) as executor:
        future_to_ip = {executor.submit(run_nmap_scan, ip): ip for ip in ips}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                current_data = future.result()
                if current_data:
                    previous_data = fetch_previous_scan_data(ip, mongo_client)
                    if previous_data:
                        changes = compare_scans(previous_data, current_data)
                        if changes:
                            print(f"Changes detected for {ip}:")
                            for change in changes:
                                print(change)
                            all_changes[ip] = changes
                            save_alerts_to_mongo(ip, changes, mongo_client)
                    save_to_mongo(current_data, mongo_client)
                    results.append(current_data)
                    logging.info(json.dumps(current_data, indent=4))
                    print(f"Scan completed for {ip}")
            except Exception as exc:
                logging.error(f'{ip} generated an exception: {exc}')

    if all_changes:
        send_google_chat_alert(all_changes)

    # Save results to a file with the current date
    date_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_filename = f"logs/scan_logs/scan_results_{date_str}.json"
    with open(output_filename, 'w') as output_file:
        json.dump(results, output_file, indent=4, default=json_util.default)
    
    print(f"Results saved to {output_filename}")

if __name__ == '__main__':
    main()

