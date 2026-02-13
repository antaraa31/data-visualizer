# network_monitor.py
# To run this, you'll need to install a few libraries:
# pip install scapy flask flask-cors requests  <-- NOTE: 'requests' is new
#
# IMPORTANT: This script needs to be run with administrator/sudo privileges
# to access network packets.
# Windows: Open Command Prompt as Administrator and run 'python network_monitor.py'
# MacOS/Linux: Run 'sudo python network_monitor.py'


import time
from collections import Counter
from threading import Thread, Lock
from flask import Flask, jsonify
from flask_cors import CORS
from scapy.all import sniff, IP, TCP, UDP
import requests  #Import the requests library for API calls


#  Data Storage 
data_lock = Lock()
protocol_counts = Counter()
ip_counts = Counter()
network_speed = {"download": 0, "upload": 0}


# A cache to store IP addresses and their resolved Organization names ---
ip_hostname_cache = {}


# Set a default timeout for all web requests (0.5 seconds)
# This prevents the whole script from freezing if an API call is slow
REQUEST_TIMEOUT = 0.5


# Your computer's local IP address
LOCAL_IP = "192.168.29.55"


# --- Packet Sniffing Logic ---
def packet_callback(packet):
   
    global protocol_counts, ip_counts, network_speed
   
    if IP in packet:
        ip_layer = packet[IP]
        packet_size = len(packet)

        with data_lock:
            if ip_layer.src == LOCAL_IP:
                network_speed["upload"] += packet_size
                ip_counts.update([ip_layer.dst])
            else:
                network_speed["download"] += packet_size
                ip_counts.update([ip_layer.src])

            if TCP in packet:
                protocol_counts.update(["TCP"])
            elif UDP in packet:
                protocol_counts.update(["UDP"])
            else:
                protocol_counts.update(["Other"])
def start_sniffing():
   
    sniff(iface="Wi-Fi 2", prn=packet_callback, store=0, stop_filter=lambda p: stop_sniffing)

def resolve_ip_to_org_name(ip):
   
    global ip_hostname_cache
   
    if ip in ip_hostname_cache:
        return ip_hostname_cache[ip]
   
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127."):
        hostname = "Local Network"
        ip_hostname_cache[ip] = hostname
        return hostname

    try:
    
        api_url = f"http://ip-api.com/json/{ip}?fields=org"
        response = requests.get(api_url, timeout=REQUEST_TIMEOUT)
       
        if response.status_code == 200:
            data = response.json()
            # Get the organization name
            hostname = data.get("org", ip) # Use IP if "org" field is missing
            if not hostname: # Handle case where org is ""
                hostname = ip
        else:
            # If API call fails, just use the IP
            hostname = ip
           
    except Exception:
        # If lookup fails (no name, timeout, etc.),
        # just use the IP address as the name
        hostname = ip
   
    # Save the result to the cache (even failures)
    # so we don't try again
    ip_hostname_cache[ip] = hostname
    return hostname




def reset_data_loop():
    """
    This function runs in a separate thread. Every second, it clears
    the collected data and performs Org lookups for the top IPs.
    """
    global protocol_counts, ip_counts, network_speed, last_data
   
    while not stop_sniffing:
        time.sleep(1) # Aggregate data for 1 second
       
        # We need to get the top IPs *before* locking
        # to process them
        top_ips_list = ip_counts.most_common(5)
       
        # --- NEW: Resolve Hostnames to Org Names ---
        # Create a new list for the resolved IPs
        resolved_ips_with_counts = []
        for ip, count in top_ips_list:
            # Get the org name (from cache or new lookup)
            hostname = resolve_ip_to_org_name(ip)
            # Add the (hostname, count) tuple to our new list
            resolved_ips_with_counts.append((hostname, count))


        with data_lock:
            # Store the last second of data to be served by the API
            last_data = {
                "protocols": dict(protocol_counts),
                # --- MODIFIED: Use the new list with org names ---
                "ips": resolved_ips_with_counts,
                "speed": dict(network_speed)
            }
            # Reset the counters for the next second
            protocol_counts.clear()
            ip_counts.clear()
            network_speed = {"download": 0, "upload": 0}




# Web Server (API)
app = Flask(__name__)
CORS(app) # Enable Cross-Origin Resource Sharing


last_data = {}


@app.route('/data')
def get_data():
    """
    The API endpoint that our HTML frontend will call to get the data.
    """
    with data_lock:
        # Send the last_data snapshot, which now contains org names
        return jsonify(last_data)


# Main Execution
if __name__ == '__main__':
    stop_sniffing = False


    print("Starting packet sniffer...")
    sniffer_thread = Thread(target=start_sniffing, daemon=True)
    sniffer_thread.start()


    print("Starting data aggregation loop...")
    reset_thread = Thread(target=reset_data_loop, daemon=True)
    reset_thread.start()


    print("Starting Flask server on http://127.0.0.1:5000")
    app.run(port=5000)


    stop_sniffing = True
    sniffer_thread.join(timeout=2)
    reset_thread.join(timeout=2)
    print("Server stopped.")