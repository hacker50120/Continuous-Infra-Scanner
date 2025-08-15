#!/usr/bin/env python3
from mongo_connection import get_db
import logging

logging.basicConfig(level=logging.INFO)

def debug_scans():
    db = get_db()
    nmap_collection = db["nmap_scans"]
    
    print("🔍 Debugging Scan Results")
    print("="*50)
    
    # Check total scans
    total_scans = nmap_collection.count_documents({})
    print(f"📊 Total scans in database: {total_scans}")
    
    if total_scans > 0:
        # Get sample scan
        sample_scan = nmap_collection.find_one()
        print(f"\n📋 Sample scan structure:")
        print(f"   IP: {sample_scan.get('server_ip')}")
        print(f"   Date: {sample_scan.get('scanned_date')}")
        print(f"   Mode: {sample_scan.get('scan_mode')}")
        print(f"   Protocol: {sample_scan.get('scan_protocol')}")
        print(f"   Ports: {len(sample_scan.get('open_port_details', {}))}")
        
        # Show port details structure
        ports = sample_scan.get('open_port_details', {})
        if ports:
            first_port = next(iter(ports))
            port_details = ports[first_port]
            print(f"   Port {first_port} details: {port_details}")
        
        # Check all unique IPs
        unique_ips = nmap_collection.distinct("server_ip")
        print(f"\n🌐 Unique IPs scanned: {unique_ips}")
        
    else:
        print("❌ No scan data found!")
        print("💡 Run a scan first: python3 script.py --light")

if __name__ == "__main__":
    debug_scans()
