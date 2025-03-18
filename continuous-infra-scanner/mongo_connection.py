# mongo_connection.py
import os
from pymongo import MongoClient
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Singleton MongoClient instance
_mongo_client = None

def get_mongo_client():
    """Returns a singleton MongoClient instance with connection pooling."""
    global _mongo_client
    if _mongo_client is None:
        mongo_conn_str = os.getenv('MONGO_URI')
        if not mongo_conn_str:
            logger.error("MONGO_URI environment variable not set")
            raise ValueError("MONGO_URI environment variable must be set")
        
        try:
            _mongo_client = MongoClient(
                mongo_conn_str,
                maxPoolSize=20,         # Limit the number of connections
                minPoolSize=2,          # Minimum connections to keep alive
                maxIdleTimeMS=30000,    # Close idle connections after 30 seconds
                serverSelectionTimeoutMS=5000,  # Timeout for server selection
                connectTimeoutMS=10000,  # Timeout for establishing connection
                socketTimeoutMS=30000    # Timeout for socket operations
            )
            logger.info("MongoDB connection established")
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise
        
    return _mongo_client

def get_db(database_name='scan_results'):
    """Returns a database instance from the MongoClient."""
    client = get_mongo_client()
    return client[database_name]

def close_mongo_client():
    """Closes the MongoClient connection."""
    global _mongo_client
    if _mongo_client is not None:
        _mongo_client.close()
        _mongo_client = None
        logger.info("MongoDB connection closed")

def save_alert(port_changes, alert_type):
    timestamp = datetime.now()
    for ip, ports in port_changes.items():
        alert = {
            'ip': ip,
            'ports': list(ports),
            'alert_type': alert_type,
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S')
        }
        alerts_collection.insert_one(alert)
        message = f"*----::[Nessus] Port Status Changes Detected::---*\n\n{alert_type} for IP {ip}: {', '.join(str(port) for port in ports)}"
        logger.info(message)
        headers = {'Content-Type': 'application/json'}
        data = {"text": message}
        response = requests.post(WHOOK_URL, headers=headers, json=data)
        if response.status_code != 200:
            logger.error(f"Failed to send notification: {response.status_code}, {response.text}")

def authenticate_nessus():
    auth_url = f'https://{nessus_hostname}/session'
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    data = {
        "username": nessus_username,
        "password": nessus_password
    }
    response = requests.post(auth_url, headers=headers, json=data)
    logger.info(f"Nessus authentication response: {response.json()}")
    if response.status_code == 200:
        return response.json()['token']
    else:
        logger.error(f"Authentication failed: {response.status_code} - {response.text}")
        raise Exception(f'Failed to authenticate with Nessus: {response.status_code} - {response.text}')

def run_nmap_scan(ip, port):
    try:
        logger.info(f"Starting scan for {ip}:{port}")
        command = f"nmap -Pn {ip} -p{port} -oX -"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        logger.error(f"Error scanning {ip}:{port} - {e}")
        return None
        
# Register cleanup on program exit
import atexit
atexit.register(close_mongo_client)
