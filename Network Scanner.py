import dearpygui.dearpygui as dpg
from scapy.all import ARP, Ether, srp

def ip_to_cidr(ip, mask):
    cidr = sum(bin(int(o)).count("1") for o in mask.split('.'))
    return f"{ip}/{cidr}"

def scan(ip_range):
    print(f"IP Range: {ip_range}")
    arp_req = ARP(pdst=ip_range)
    broad = Ether(dst="ff:ff:ff:ff:ff:ff")
    req_broad = broad / arp_req
    ans = srp(req_broad, timeout=2, verbose=False)[0]
    print(f"Received {len(ans)} responses")
    
    devices = []
    for e in ans:
        devices.append({"ip": e[1].psrc, "mac": e[1].hwsrc})
    
    return devices

def show_results(devices):
    for dev in devices:
        with dpg.table_row(parent="results_table"):
            dpg.add_text(dev['ip'])
            dpg.add_text(dev['mac'])

def get_cidr():
    ip = dpg.get_value("ip_input")
    mask = dpg.get_value("subnet_input")
    if ip and mask:
        return ip_to_cidr(ip, mask)
    return None

def start_scan(sender, app_data):
    target = get_cidr()
    if target:
        devices = scan(target)
        show_results(devices)
    else:
        dpg.add_text("Invalid input.", parent=dpg.last_item())

dpg.create_context()

with dpg.handler_registry():
    dpg.add_key_press_handler(dpg.mvKey_Escape, callback=lambda: dpg.stop())

with dpg.window(label="Scanner", width=500, height=400):
    dpg.add_text("Enter IP and Mask:")
    dpg.add_input_text(label="IP", tag="ip_input", default_value="192.168.0.39")
    dpg.add_input_text(label="Subnet", tag="subnet_input", default_value="255.255.255.0")
    dpg.add_button(label="Scan", callback=start_scan)
    dpg.add_text("Results:")
    with dpg.child_window(width=480, height=200, tag="results_container", autosize_x=False, autosize_y=False, no_scrollbar=False):
        pass

with dpg.table(header_row=True, tag="results_table", parent="results_container"):
    dpg.add_table_column(label="IP Address")
    dpg.add_table_column(label="MAC Address")

dpg.create_viewport(title="Lucas Sigma", width=500, height=400)
dpg.setup_dearpygui()
dpg.show_viewport()

dpg.start_dearpygui()

dpg.destroy_context()
