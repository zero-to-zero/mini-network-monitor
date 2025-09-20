from flask import Flask, render_template, jsonify
import socket
import ipaddress
import platform
import subprocess
import concurrent.futures
from scapy.all import ARP, Ether, srp
from zeroconf import ServiceBrowser, Zeroconf, ServiceListener
import threading
import time
from datetime import datetime
import json
import os

app = Flask(__name__)

live_devices = {}
device_history = {}
last_seen = {}

def load_history():
    global device_history, last_seen
    try:
        if os.path.exists('device_history.json'):
            with open('device_history.json', 'r') as f:
                data = json.load(f)
                device_history = data.get('device_history', {})
                last_seen = data.get('last_seen', {})
    except Exception:
        device_history = {}
        last_seen = {}

def save_history():
    try:
        with open('device_history.json', 'w') as f:
            json.dump({
                'device_history': device_history,
                'last_seen': last_seen
            }, f)
    except Exception:
        pass

load_history()

def get_network():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return str(ipaddress.ip_network(ip + "/24", strict=False))
    except Exception:
        return "192.168.1.0/24"

def ping(ip, timeout=500):
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(timeout // 1000, 1)), ip]
    return subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def arp_scan(network):
    try:
        net = ipaddress.ip_network(network, strict=False)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp = ARP(pdst=str(net))
        packet = ether / arp
        result = srp(packet, timeout=2, verbose=False)[0]
        devices = {}
        for sent, received in result:
            devices[received.psrc] = {"mac": received.hwsrc, "name": "<unknown>", "status": "online"}
        return devices
    except Exception:
        return {}

def reverse_dns(devices):
    for ip in devices:
        try:
            devices[ip]["name"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            if ip in device_history:
                devices[ip]["name"] = device_history[ip].get("name", "<unknown>")
            else:
                devices[ip]["name"] = "<unknown>"
    return devices

def ping_sweep(devices, network):
    try:
        net = ipaddress.ip_network(network, strict=False)
        with concurrent.futures.ThreadPoolExecutor(max_workers=128) as ex:
            futures = {ex.submit(ping, str(ip)): str(ip) for ip in net.hosts()}
            for f in concurrent.futures.as_completed(futures):
                ip = futures[f]
                if f.result() and ip not in devices:
                    devices[ip] = {"mac": "<unknown>", "name": "<unknown>", "status": "online"}
        return devices
    except Exception:
        return devices

def mdns_scan(devices):
    class MyListener(ServiceListener):
        def add_service(self, zc, type, name):
            try:
                info = zc.get_service_info(type, name)
                if info and info.addresses:
                    ip = socket.inet_ntoa(info.addresses[0])
                    devices[ip] = {"mac": "<unknown>", "name": info.server.rstrip('.'), "status": "online"}
            except Exception:
                pass
        def remove_service(self, zc, type, name):
            pass
        def update_service(self, zc, type, name):
            pass
    try:
        zc = Zeroconf()
        services = ["_http._tcp.local.", "_ipp._tcp.local.", "_ssh._tcp.local.", "_workstation._tcp.local."]
        for s in services:
            ServiceBrowser(zc, s, MyListener())
        time.sleep(3)
        zc.close()
    except Exception:
        pass
    return devices

def scan_network():
    net = get_network()
    devices = arp_scan(net)
    devices = ping_sweep(devices, net)
    devices = reverse_dns(devices)
    devices = mdns_scan(devices)
    current_time = datetime.now().isoformat()
    for ip, info in devices.items():
        if ip not in device_history:
            device_history[ip] = {
                "name": info["name"],
                "mac": info["mac"],
                "first_seen": current_time
            }
        last_seen[ip] = current_time
    return devices

def background_scan():
    global live_devices
    while True:
        try:
            devices = scan_network()
            for ip in device_history:
                if ip in devices:
                    devices[ip]["status"] = "online"
                else:
                    if ip not in live_devices or live_devices[ip].get("status") == "online":
                        devices[ip] = device_history[ip].copy()
                        devices[ip]["status"] = "offline"
            live_devices = devices
            save_history()
        except Exception:
            pass
        time.sleep(10)

threading.Thread(target=background_scan, daemon=True).start()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/devices")
def get_devices():
    devices_with_times = {}
    for ip, info in live_devices.items():
        device_data = info.copy()
        device_data["last_seen"] = last_seen.get(ip, "Unknown")
        device_data["first_seen"] = device_history.get(ip, {}).get("first_seen", "Unknown")
        devices_with_times[ip] = device_data
    return jsonify(devices_with_times)

@app.route("/device/<ip>/refresh")
def refresh_device(ip):
    try:
        if ping(ip):
            current_time = datetime.now().isoformat()
            try:
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
                if ans:
                    mac = ans[0][1].hwsrc
                else:
                    mac = "<unknown>"
            except Exception:
                mac = "<unknown>"
            try:
                name = socket.gethostbyaddr(ip)[0]
            except Exception:
                name = device_history.get(ip, {}).get("name", "<unknown>")
            live_devices[ip] = {
                "mac": mac,
                "name": name,
                "status": "online"
            }
            if ip not in device_history:
                device_history[ip] = {
                    "name": name,
                    "mac": mac,
                    "first_seen": current_time
                }
            last_seen[ip] = current_time
            save_history()
            return jsonify({"success": True, "message": f"Device {ip} is online"})
        else:
            return jsonify({"success": False, "message": f"Device {ip} is offline"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
