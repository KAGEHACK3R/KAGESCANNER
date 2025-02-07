#!/usr/bin/env python3
"""
KAGESCANNER Ultimate
Auteur       : GUY KOUAKOU
Pseudo       : KAGEH@CK3R
Description  : Scanner de ports avancé intégrant :
    - Banner grabbing pour détecter la version des services
    - Plugins extensibles
    - Interface graphique (Tkinter) et API REST (Flask)
    - Scan de sous-réseaux avec découverte d’hôtes
    - Scanning asynchrone (asyncio) et multithreading
    - Export détaillé (CSV, JSON, HTML, XML)
    - Notifications par e-mail
    - Personnalisation avancée (timeouts, threads, mode furtif, etc.)
    - Support IPv4 et IPv6
    - Tests unitaires intégrés
"""

import socket
import asyncio
import concurrent.futures
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import queue
import random
import time
import ipaddress
import subprocess
import csv
import json
import xml.etree.ElementTree as ET
import smtplib
from email.mime.text import MIMEText
import logging
from flask import Flask, request, jsonify
import sys
import unittest

# --- Configuration de la journalisation et de l'application ---
log_queue = queue.Queue()

class QueueHandler(logging.Handler):
    """Handler de logging qui envoie les messages dans une file (pour l'affichage dans l'interface)."""
    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue
    def emit(self, record):
        self.log_queue.put(self.format(record))

logging.basicConfig(level=logging.DEBUG,
                    filename='kagescanner_ultimate.log',
                    filemode='a',
                    format='%(asctime)s - %(levelname)s - %(message)s')
# Ajout du handler personnalisé pour les logs GUI
queue_handler = QueueHandler(log_queue)
queue_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.getLogger().addHandler(queue_handler)

# --- Configuration avancée ---
CONFIG = {
    'timeout': 0.5,
    'max_threads': 100,
    'stealth_mode': False,
    'stealth_delay_range': (0.1, 0.5),  # délais aléatoires en mode furtif
    'smtp_server': 'smtp.example.com',
    'smtp_port': 587,
    'smtp_username': 'your_email@example.com',
    'smtp_password': 'password',
    'notify_email': 'notify@example.com',
    'api_key': 'mysecretapikey'  # Clé API requise pour l'accès à l'API REST
}

# Variables globales pour suivi et annulation
tasks_done = 0
total_tasks = 0
tasks_lock = threading.Lock()
cancel_event = threading.Event()
result_queue = queue.Queue()
results_list = []  # Stocke les résultats du scan

# --- Système de plugins ---
plugins = []

def register_plugin(plugin_func):
    plugins.append(plugin_func)

def log_open_port_plugin(protocol, ip, port, service, banner, status):
    if status == "Open":
        logging.info(f"Plugin: {protocol} {ip}:{port} est ouvert (banner: {banner})")
register_plugin(log_open_port_plugin)

# --- Fonctions utilitaires ---
def is_ipv6(address):
    try:
        ip_obj = ipaddress.ip_address(address)
        return ip_obj.version == 6
    except ValueError:
        return False

def grab_banner(s):
    """Tente de récupérer la bannière d'un service de façon robuste."""
    s.settimeout(CONFIG['timeout'])
    try:
        banner = s.recv(1024).decode(errors='ignore').strip()
        return banner
    except Exception as e:
        logging.debug(f"Grab banner exception: {e}")
        return ""

# --- Fonctions de scan TCP et UDP (synchrones) ---
def scan_tcp(ip, port):
    """Scanne un port TCP avec banner grabbing."""
    if cancel_event.is_set():
        return None
    family = socket.AF_INET6 if is_ipv6(ip) else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(CONFIG['timeout'])
    banner = ""
    try:
        result = s.connect_ex((ip, port))
        if result == 0:
            try:
                service = socket.getservbyport(port, 'tcp')
            except Exception:
                service = "Unknown"
            try:
                banner = grab_banner(s)
            except Exception as e:
                logging.debug(f"Banner grabbing failed on {ip}:{port} - {e}")
                banner = ""
            status = "Open"
        else:
            service = ""
            status = "Closed"
    except Exception as e:
        logging.error(f"TCP error sur {ip}:{port} – {e}")
        service = ""
        status = "Error"
    finally:
        s.close()
    for plugin in plugins:
        try:
            plugin("TCP", ip, port, service, banner, status)
        except Exception as e:
            logging.error(f"Erreur plugin : {e}")
    return ("TCP", ip, port, service, banner, status)

def scan_udp(ip, port):
    """Scanne un port UDP de manière basique."""
    if cancel_event.is_set():
        return None
    family = socket.AF_INET6 if is_ipv6(ip) else socket.AF_INET
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(CONFIG['timeout'])
    banner = ""
    try:
        s.sendto(b'', (ip, port))
        try:
            data, _ = s.recvfrom(1024)
            banner = data.decode(errors='ignore').strip() if data else ""
            status = "Open"
        except socket.timeout:
            status = "Open|Filtered"
        try:
            service = socket.getservbyport(port, 'udp')
        except Exception:
            service = "Unknown"
    except Exception as e:
        logging.error(f"UDP error sur {ip}:{port} – {e}")
        service = ""
        status = "Error"
    finally:
        s.close()
    for plugin in plugins:
        try:
            plugin("UDP", ip, port, service, banner, status)
        except Exception as e:
            logging.error(f"Erreur plugin : {e}")
    return ("UDP", ip, port, service, banner, status)

# --- Scan asynchrone TCP avec asyncio ---
async def async_scan_tcp(ip, port):
    if cancel_event.is_set():
        return None
    family = socket.AF_INET6 if is_ipv6(ip) else socket.AF_INET
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port, family=family), timeout=CONFIG['timeout'])
        try:
            service = socket.getservbyport(port, 'tcp')
        except Exception:
            service = "Unknown"
        try:
            banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=CONFIG['timeout'])
            banner = banner_bytes.decode(errors='ignore').strip() if banner_bytes else ""
        except Exception:
            banner = ""
        status = "Open"
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        service = ""
        banner = ""
        status = "Closed"
    for plugin in plugins:
        try:
            plugin("TCP", ip, port, service, banner, status)
        except Exception as e:
            logging.error(f"Erreur plugin : {e}")
    return ("TCP", ip, port, service, banner, status)

# --- Découverte d’hôtes (ping sweep) avec parallélisation ---
def ping_host(ip_str):
    param = '-n' if sys.platform.startswith('win') else '-c'
    command = ['ping', param, '1', ip_str] if sys.platform.startswith('win') else ['ping', param, '1', '-W', '1', ip_str]
    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            return ip_str
    except Exception as e:
        logging.error(f"Erreur ping sur {ip_str} : {e}")
    return None

def discover_hosts(subnet):
    active_hosts = []
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except Exception as e:
        logging.error(f"Subnet invalide : {subnet} – {e}")
        return active_hosts
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(ping_host, str(ip)): ip for ip in network.hosts()}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                active_hosts.append(result)
    return active_hosts

# --- Notification par e-mail ---
def send_notification(subject, body):
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = CONFIG['smtp_username']
        msg['To'] = CONFIG['notify_email']
        server = smtplib.SMTP(CONFIG['smtp_server'], CONFIG['smtp_port'])
        server.starttls()
        server.login(CONFIG['smtp_username'], CONFIG['smtp_password'])
        server.sendmail(CONFIG['smtp_username'], [CONFIG['notify_email']], msg.as_string())
        server.quit()
        logging.info("Notification envoyée par e-mail.")
    except Exception as e:
        logging.error(f"Échec de l’envoi d’e-mail : {e}")

# --- Fonctions d’export avancé ---
def export_csv(filepath, results):
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Protocol", "IP", "Port", "Service", "Banner", "Status"])
        for r in results:
            writer.writerow(r)

def export_json(filepath, results):
    data = [{"protocol": r[0], "ip": r[1], "port": r[2], "service": r[3], "banner": r[4], "status": r[5]} for r in results]
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

def export_xml(filepath, results):
    root_xml = ET.Element("ScanResults")
    for r in results:
        entry = ET.SubElement(root_xml, "Result")
        ET.SubElement(entry, "Protocol").text = r[0]
        ET.SubElement(entry, "IP").text = r[1]
        ET.SubElement(entry, "Port").text = str(r[2])
        ET.SubElement(entry, "Service").text = r[3]
        ET.SubElement(entry, "Banner").text = r[4]
        ET.SubElement(entry, "Status").text = r[5]
    tree = ET.ElementTree(root_xml)
    tree.write(filepath, encoding='utf-8', xml_declaration=True)

def export_html(filepath, results):
    html_content = "<html><head><meta charset='utf-8'><title>Scan Results</title></head><body>"
    html_content += "<h1>Scan Results</h1><table border='1'><tr><th>Protocol</th><th>IP</th><th>Port</th><th>Service</th><th>Banner</th><th>Status</th></tr>"
    for r in results:
        html_content += f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td><td>{r[3]}</td><td>{r[4]}</td><td>{r[5]}</td></tr>"
    html_content += "</table></body></html>"
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html_content)

# --- API REST avec Flask (contrôlée par API Key) ---
app = Flask(__name__)

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """
    Reçoit du JSON avec :
      - ip : cible (IP ou sous-réseau si network_scan est True)
      - start_port, end_port
      - protocols : liste (ex. ["TCP", "UDP"])
      - network_scan : booléen
      - api_key : clé API pour autorisation
    """
    data = request.json
    if not data or 'ip' not in data or 'api_key' not in data:
        return jsonify({"error": "Cible ou API key manquante"}), 400
    if data.get('api_key') != CONFIG['api_key']:
        return jsonify({"error": "Unauthorized"}), 401
    ip_target = data['ip']
    start_port = data.get('start_port', 1)
    end_port = data.get('end_port', 1000)
    protocols = data.get('protocols', ["TCP"])
    network_scan = data.get('network_scan', False)
    results = []
    if network_scan:
        hosts = discover_hosts(ip_target)
    else:
        hosts = [ip_target]
    for host in hosts:
        for port in range(start_port, end_port + 1):
            if "TCP" in protocols:
                r = scan_tcp(host, port)
                if r and r[5] == "Open":
                    results.append(r)
            if "UDP" in protocols:
                r = scan_udp(host, port)
                if r and r[5].startswith("Open"):
                    results.append(r)
    return jsonify({"results": [{"protocol": r[0], "ip": r[1], "port": r[2], "service": r[3], "banner": r[4], "status": r[5]} for r in results]})

def run_flask():
    app.run(port=5000)

# --- Exécution du scan via ThreadPoolExecutor ou asyncio ---
def process_result_future(future):
    global tasks_done
    result = future.result()
    if result is not None:
        result_queue.put(result)
        results_list.append(result)
    with tasks_lock:
        tasks_done += 1

def run_scan_tasks(ip, start_port, end_port, scan_tcp_enabled, scan_udp_enabled, use_async):
    global total_tasks, tasks_done, results_list
    tasks_done = 0
    results_list = []
    protocols = 0
    if scan_tcp_enabled: protocols += 1
    if scan_udp_enabled: protocols += 1
    total_tasks = (end_port - start_port + 1) * protocols
    if use_async:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        tasks = []
        for port in range(start_port, end_port + 1):
            if cancel_event.is_set():
                break
            if scan_tcp_enabled:
                tasks.append(async_scan_tcp(ip, port))
        results_async = loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
        for r in results_async:
            if r is not None:
                result_queue.put(r)
                results_list.append(r)
            with tasks_lock:
                tasks_done += 1
        loop.close()
        if scan_udp_enabled:
            with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['max_threads']) as executor:
                for port in range(start_port, end_port + 1):
                    if cancel_event.is_set():
                        break
                    fut = executor.submit(scan_udp, ip, port)
                    fut.add_done_callback(process_result_future)
                    if CONFIG['stealth_mode']:
                        time.sleep(random.uniform(*CONFIG['stealth_delay_range']))
                executor.shutdown(wait=True)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['max_threads']) as executor:
            for port in range(start_port, end_port + 1):
                if cancel_event.is_set():
                    break
                if scan_tcp_enabled:
                    fut = executor.submit(scan_tcp, ip, port)
                    fut.add_done_callback(process_result_future)
                if scan_udp_enabled:
                    fut = executor.submit(scan_udp, ip, port)
                    fut.add_done_callback(process_result_future)
                if CONFIG['stealth_mode']:
                    time.sleep(random.uniform(*CONFIG['stealth_delay_range']))
            executor.shutdown(wait=True)
    result_queue.put("FINISHED")

# --- Interface Graphique (Tkinter) ---
root = tk.Tk()
root.title("KAGESCANNER Ultimate")

# Cadre principal et onglets
main_frame = ttk.Frame(root, padding=10)
main_frame.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
tab_control = ttk.Notebook(main_frame)
tab_scan = ttk.Frame(tab_control)
tab_network = ttk.Frame(tab_control)
tab_settings = ttk.Frame(tab_control)
tab_api = ttk.Frame(tab_control)
tab_logs = ttk.Frame(tab_control)  # Nouvel onglet pour les logs
tab_control.add(tab_scan, text="Scan")
tab_control.add(tab_network, text="Network Discovery")
tab_control.add(tab_settings, text="Advanced Settings")
tab_control.add(tab_api, text="API Control")
tab_control.add(tab_logs, text="Logs")
tab_control.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))

# --- Onglet Scan ---
ttk.Label(tab_scan, text="Target IP:").grid(row=0, column=0, sticky=tk.W)
ip_entry = ttk.Entry(tab_scan, width=20)
ip_entry.grid(row=0, column=1, sticky=tk.W)
ip_entry.insert(0, "127.0.0.1")

ttk.Label(tab_scan, text="Start Port:").grid(row=1, column=0, sticky=tk.W)
start_port_entry = ttk.Entry(tab_scan, width=10)
start_port_entry.grid(row=1, column=1, sticky=tk.W)
start_port_entry.insert(0, "1")
ttk.Label(tab_scan, text="End Port:").grid(row=2, column=0, sticky=tk.W)
end_port_entry = ttk.Entry(tab_scan, width=10)
end_port_entry.grid(row=2, column=1, sticky=tk.W)
end_port_entry.insert(0, "1000")

tcp_var = tk.BooleanVar(value=True)
udp_var = tk.BooleanVar(value=False)
ttk.Checkbutton(tab_scan, text="TCP", variable=tcp_var).grid(row=3, column=0, sticky=tk.W)
ttk.Checkbutton(tab_scan, text="UDP", variable=udp_var).grid(row=3, column=1, sticky=tk.W)

async_var = tk.BooleanVar(value=False)
ttk.Checkbutton(tab_scan, text="Use Async Scan (TCP only)", variable=async_var).grid(row=4, column=0, columnspan=2, sticky=tk.W)

start_button = ttk.Button(tab_scan, text="Start Scan")
start_button.grid(row=5, column=0, pady=5)
cancel_button = ttk.Button(tab_scan, text="Cancel Scan", state=tk.DISABLED)
cancel_button.grid(row=5, column=1, pady=5)
export_button = ttk.Button(tab_scan, text="Export Results", state=tk.DISABLED)
export_button.grid(row=5, column=2, pady=5)

progress_bar = ttk.Progressbar(tab_scan, mode="determinate", maximum=100, value=0)
progress_bar.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
status_label = ttk.Label(tab_scan, text="Ready")
status_label.grid(row=7, column=0, columnspan=3, sticky=tk.W)

columns = ("Protocol", "IP", "Port", "Service", "Banner", "Status")
result_tree = ttk.Treeview(tab_scan, columns=columns, show="headings", height=15)
for col in columns:
    result_tree.heading(col, text=col)
    result_tree.column(col, width=100)
result_tree.grid(row=8, column=0, columnspan=3, sticky=(tk.N, tk.S, tk.E, tk.W))
scrollbar = ttk.Scrollbar(tab_scan, orient=tk.VERTICAL, command=result_tree.yview)
result_tree.configure(yscroll=scrollbar.set)
scrollbar.grid(row=8, column=3, sticky=(tk.N, tk.S))

# --- Onglet Network Discovery ---
ttk.Label(tab_network, text="Subnet (ex: 192.168.1.0/24):").grid(row=0, column=0, sticky=tk.W)
subnet_entry = ttk.Entry(tab_network, width=20)
subnet_entry.grid(row=0, column=1, sticky=tk.W)
subnet_entry.insert(0, "192.168.1.0/24")
discover_button = ttk.Button(tab_network, text="Discover Hosts")
discover_button.grid(row=1, column=0, pady=5)
discovery_tree = ttk.Treeview(tab_network, columns=("Host", "Status"), show="headings", height=10)
discovery_tree.heading("Host", text="Host")
discovery_tree.heading("Status", text="Status")
discovery_tree.column("Host", width=150)
discovery_tree.column("Status", width=100)
discovery_tree.grid(row=2, column=0, columnspan=2, sticky=(tk.N, tk.S, tk.E, tk.W))
disc_scrollbar = ttk.Scrollbar(tab_network, orient=tk.VERTICAL, command=discovery_tree.yview)
discovery_tree.configure(yscroll=disc_scrollbar.set)
disc_scrollbar.grid(row=2, column=2, sticky=(tk.N, tk.S))

# --- Onglet Advanced Settings ---
ttk.Label(tab_settings, text="Timeout (sec):").grid(row=0, column=0, sticky=tk.W)
timeout_entry = ttk.Entry(tab_settings, width=10)
timeout_entry.grid(row=0, column=1, sticky=tk.W)
timeout_entry.insert(0, str(CONFIG['timeout']))
ttk.Label(tab_settings, text="Max Threads:").grid(row=1, column=0, sticky=tk.W)
threads_entry = ttk.Entry(tab_settings, width=10)
threads_entry.grid(row=1, column=1, sticky=tk.W)
threads_entry.insert(0, str(CONFIG['max_threads']))
stealth_var = tk.BooleanVar(value=CONFIG['stealth_mode'])
ttk.Checkbutton(tab_settings, text="Stealth Mode", variable=stealth_var).grid(row=2, column=0, sticky=tk.W)
ttk.Label(tab_settings, text="SMTP Server:").grid(row=3, column=0, sticky=tk.W)
smtp_server_entry = ttk.Entry(tab_settings, width=20)
smtp_server_entry.grid(row=3, column=1, sticky=tk.W)
smtp_server_entry.insert(0, CONFIG['smtp_server'])
ttk.Label(tab_settings, text="SMTP Port:").grid(row=4, column=0, sticky=tk.W)
smtp_port_entry = ttk.Entry(tab_settings, width=10)
smtp_port_entry.grid(row=4, column=1, sticky=tk.W)
smtp_port_entry.insert(0, str(CONFIG['smtp_port']))
ttk.Label(tab_settings, text="SMTP Username:").grid(row=5, column=0, sticky=tk.W)
smtp_user_entry = ttk.Entry(tab_settings, width=20)
smtp_user_entry.grid(row=5, column=1, sticky=tk.W)
smtp_user_entry.insert(0, CONFIG['smtp_username'])
ttk.Label(tab_settings, text="SMTP Password:").grid(row=6, column=0, sticky=tk.W)
smtp_pass_entry = ttk.Entry(tab_settings, width=20, show="*")
smtp_pass_entry.grid(row=6, column=1, sticky=tk.W)
smtp_pass_entry.insert(0, CONFIG['smtp_password'])
ttk.Label(tab_settings, text="Notification Email:").grid(row=7, column=0, sticky=tk.W)
notify_email_entry = ttk.Entry(tab_settings, width=20)
notify_email_entry.grid(row=7, column=1, sticky=tk.W)
notify_email_entry.insert(0, CONFIG['notify_email'])
save_settings_button = ttk.Button(tab_settings, text="Save Settings")
save_settings_button.grid(row=8, column=0, pady=5)

# --- Onglet API Control ---
ttk.Label(tab_api, text="Flask API est accessible sur http://localhost:5000/api/scan").grid(row=0, column=0, sticky=tk.W)
ttk.Label(tab_api, text="(N'oubliez pas d'inclure 'api_key':'mysecretapikey' dans vos requêtes)").grid(row=1, column=0, sticky=tk.W)
start_api_button = ttk.Button(tab_api, text="Start API Server")
start_api_button.grid(row=2, column=0, pady=5)

# --- Onglet Logs ---
log_text = tk.Text(tab_logs, height=20, width=100)
log_text.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
log_scrollbar = ttk.Scrollbar(tab_logs, orient=tk.VERTICAL, command=log_text.yview)
log_text.configure(yscroll=log_scrollbar.set)
log_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

def update_logs():
    try:
        while True:
            msg = log_queue.get_nowait()
            log_text.insert(tk.END, msg + "\n")
            log_text.see(tk.END)
    except queue.Empty:
        pass
    root.after(100, update_logs)

update_logs()  # Démarre la mise à jour des logs dans l'onglet Logs

# --- Fonctions de contrôle de l'interface ---
def update_settings():
    try:
        CONFIG['timeout'] = float(timeout_entry.get())
        CONFIG['max_threads'] = int(threads_entry.get())
        CONFIG['stealth_mode'] = stealth_var.get()
        CONFIG['smtp_server'] = smtp_server_entry.get()
        CONFIG['smtp_port'] = int(smtp_port_entry.get())
        CONFIG['smtp_username'] = smtp_user_entry.get()
        CONFIG['smtp_password'] = smtp_pass_entry.get()
        CONFIG['notify_email'] = notify_email_entry.get()
        messagebox.showinfo("Settings", "Settings saved successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save settings: {e}")

save_settings_button.config(command=update_settings)

def start_api_server():
    threading.Thread(target=run_flask, daemon=True).start()
    messagebox.showinfo("API Server", "Flask API server started on port 5000.")

start_api_button.config(command=start_api_server)

def start_scan():
    target_ip = ip_entry.get().strip()
    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        messagebox.showerror("Error", "Invalid target IP address.")
        return
    try:
        sp = int(start_port_entry.get())
        ep = int(end_port_entry.get())
        if sp < 1 or ep > 65535 or sp > ep:
            raise ValueError
    except:
        messagebox.showerror("Error", "Invalid port range.")
        return
    if not messagebox.askokcancel("Warning", "Assurez-vous d'avoir l'autorisation de scanner cette cible.\nContinuer ?"):
        return
    cancel_event.clear()
    global tasks_done, total_tasks, results_list
    tasks_done = 0
    total_tasks = 0
    results_list = []
    for item in result_tree.get_children():
        result_tree.delete(item)
    while not result_queue.empty():
        try:
            result_queue.get_nowait()
        except queue.Empty:
            break
    start_button.config(state=tk.DISABLED)
    cancel_button.config(state=tk.NORMAL)
    export_button.config(state=tk.DISABLED)
    status_label.config(text="Scan in progress...")
    progress_bar.config(value=0)
    use_async = async_var.get()
    threading.Thread(target=run_scan_tasks, args=(target_ip, sp, ep, tcp_var.get(), udp_var.get(), use_async), daemon=True).start()
    root.after(100, update_progress)

def update_progress():
    if total_tasks > 0:
        progress = int((tasks_done / total_tasks) * 100)
        progress_bar.config(value=progress)
    try:
        while True:
            item = result_queue.get_nowait()
            if item == "FINISHED":
                status_label.config(text="Scan completed.")
                start_button.config(state=tk.NORMAL)
                cancel_button.config(state=tk.DISABLED)
                export_button.config(state=tk.NORMAL)
                open_ports = [r for r in results_list if r[5] == "Open"]
                if open_ports:
                    send_notification("Scan Completed - Open Ports Found", f"Open ports: {open_ports}")
            else:
                result_tree.insert("", tk.END, values=item)
    except queue.Empty:
        pass
    if start_button['state'] == tk.DISABLED:
        root.after(100, update_progress)

def cancel_scan():
    cancel_event.set()
    status_label.config(text="Scan cancelled.")
    start_button.config(state=tk.NORMAL)
    cancel_button.config(state=tk.DISABLED)
    export_button.config(state=tk.NORMAL)

start_button.config(command=start_scan)
cancel_button.config(command=cancel_scan)

def export_results():
    filetypes = [("CSV", "*.csv"), ("JSON", "*.json"), ("XML", "*.xml"), ("HTML", "*.html")]
    filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=filetypes)
    if not filepath:
        return
    try:
        if filepath.endswith(".csv"):
            export_csv(filepath, results_list)
        elif filepath.endswith(".json"):
            export_json(filepath, results_list)
        elif filepath.endswith(".xml"):
            export_xml(filepath, results_list)
        elif filepath.endswith(".html"):
            export_html(filepath, results_list)
        messagebox.showinfo("Export", "Results exported successfully.")
    except Exception as e:
        messagebox.showerror("Export Error", str(e))

export_button.config(command=export_results)

def discover_hosts_gui():
    subnet = subnet_entry.get().strip()
    if not subnet:
        messagebox.showerror("Error", "Please enter a subnet.")
        return
    for item in discovery_tree.get_children():
        discovery_tree.delete(item)
    discovery_tree.insert("", tk.END, values=("...", "Discovering..."))
    def do_discovery():
        hosts = discover_hosts(subnet)
        discovery_tree.delete(*discovery_tree.get_children())
        for host in hosts:
            discovery_tree.insert("", tk.END, values=(host, "Active"))
    threading.Thread(target=do_discovery, daemon=True).start()

discover_button.config(command=discover_hosts_gui)

# --- Tests Unitaires ---
class TestKageScanner(unittest.TestCase):
    def test_ipv4(self):
        self.assertFalse(is_ipv6("127.0.0.1"))
    def test_ipv6(self):
        self.assertTrue(is_ipv6("::1"))
    def test_scan_tcp_closed(self):
        result = scan_tcp("127.0.0.1", 0)
        self.assertIn(result[5], ["Closed", "Error"])
    def test_discover_hosts_invalid(self):
        hosts = discover_hosts("invalid_subnet")
        self.assertEqual(hosts, [])

def run_tests():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestKageScanner)
    unittest.TextTestRunner(verbosity=2).run(suite)

run_tests_button = ttk.Button(tab_settings, text="Run Unit Tests", command=run_tests)
run_tests_button.grid(row=9, column=0, pady=5)

# --- Configuration de redimensionnement ---
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)
main_frame.columnconfigure(0, weight=1)
main_frame.rowconfigure(0, weight=1)

root.mainloop()

