from scapy.all import ARP, Ether, srp

def arp_scan(target_ip):
    # CIDR notation
    print(f"IP Range: {target_ip}")
    
    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")  
    arp_request_broadcast = broadcast / arp_request
    
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    print(f"Received {len(answered_list)} responses")
    
    devices = []
    for element in answered_list:
        device_info = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        devices.append(device_info)
    
    return devices

def print_results(devices):
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")

# Use ipconfig to find your IP + subnet mask
target_ip = "192.168.0.1/24"  
devices = arp_scan(target_ip)
print_results(devices)

# Ensure the program waits for Enter key
while True:
    exit_prompt = input("Press Enter to exit the program...").strip()
    if exit_prompt == "":
        break  # Exit only when Enter is pressed
