from scapy.all import get_if_list, conf

print("Available network interfaces:")
# We use conf.ifaces to get more detailed info
for iface_name in get_if_list():
    iface_details = conf.ifaces.get(iface_name)
    if iface_details:
        # Display name and IP address if available
        print(f"- {iface_details.name} ({iface_details.description}) - IP: {iface_details.ip}")