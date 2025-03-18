# nessus_auth_data_fetch_to_DB.py
import os
import requests
from flask import jsonify
from datetime import datetime
from mongo_connection import get_db  # Import from mongo_connection
from pymongo import ReturnDocument

# Environment variables
nessus_hostname = os.getenv('NESSUS_HOSTNAME')
nessus_username = os.getenv('NESSUS_USERNAME')
nessus_password = os.getenv('NESSUS_PASSWORD')

# Get MongoDB database instance
db = get_db('scan_results')
nessus_collection = db['nessus_scans']
counter_collection = db['counters']

# Initialize the counter if it doesn't exist
if counter_collection.count_documents({"_id": "insert_trackRecord"}) == 0:
    counter_collection.insert_one({"_id": "insert_trackRecord", "seq": 1000})

def get_next_sequence():
    """Get the next sequence number for insert_trackRecord."""
    counter = counter_collection.find_one_and_update(
        {"_id": "insert_trackRecord"},
        {"$inc": {"seq": 1}},
        return_document=ReturnDocument.AFTER
    )
    return counter['seq']

def authenticate_nessus():
    """Authenticate with Nessus and return the token."""
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
    print(response.json())
    if response.status_code == 200:
        return response.json()['token']
    else:
        raise Exception(f'Failed to authenticate with Nessus: {response.status_code} - {response.text}')

def fetch_nessus_data(report_number, plugins):
    """Fetch Nessus data for given report number and plugins."""
    try:
        token = authenticate_nessus()  # Ensure token is refreshed for each call
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

    headers = {
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Content-Type': 'application/json',
        'Pragma': 'no-cache',
        'Referer': f'https://{nessus_hostname}/',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        'X-Cookie': f'token={token}'
    }

    all_data = []
    insert_trackRecord = get_next_sequence()
    for plugin in plugins:
        nessus_endpoint = f'https://{nessus_hostname}/scans/{report_number}/plugins/{plugin}?limit=2500'
        response = requests.get(nessus_endpoint, headers=headers)
        if response.status_code == 200:
            nessus_data = response.json()
            nessus_data['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            nessus_data['report_number'] = report_number
            nessus_data['plugin_id'] = plugin
            nessus_data['insert_trackRecord'] = insert_trackRecord
            all_data.append(nessus_data)
        else:
            return jsonify({
                'status': 'error',
                'message': f'Failed to fetch data for plugin {plugin}: {response.status_code} - {response.text}'
            }), response.status_code

    try:
        result = nessus_collection.insert_many(all_data)
        inserted_ids = [str(id) for id in result.inserted_ids]
        return jsonify({
            'status': 'success',
            'message': 'Nessus data stored successfully',
            'ids': inserted_ids
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Failed to store data in MongoDB: {str(e)}'}), 500
