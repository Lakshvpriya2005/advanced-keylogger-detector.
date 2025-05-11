import psutil
import time
import schedule
from datetime import datetime

suspicious_keywords = ['keylogger', 'logger', 'spy', 'hook', 'record', 'capture']

def log_to_file(content):
    with open("keylogger_report.txt", "a") as file:
        file.write(content + "\n")

def detect_keylogger():
    detected = False
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[{timestamp}] Scanning processes...\n")
    log_to_file(f"\n[{timestamp}] Scan started.")

    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            pname = proc.info['name'].lower()
            ppath = proc.info['exe'] or ""

            for keyword in suspicious_keywords:
                if keyword in pname or 'temp' in ppath.lower() or 'AppData' in ppath:
                    message = f"[!] Suspicious: {pname} (PID: {proc.info['pid']}) Path: {ppath}"
                    print(message)
                    log_to_file(message)
                    detected = True
        except:
            pass

    if not detected:
        print("No suspicious processes found.")
        log_to_file("No suspicious processes found.")

def check_network_activity():
    print("Checking network connections...\n")
    for conn in psutil.net_connections(kind='inet'):
        try:
            pid = conn.pid
            proc = psutil.Process(pid)
            pname = proc.name().lower()
            if any(keyword in pname for keyword in suspicious_keywords):
                message = f"[!] Network Alert: {pname} (PID: {pid}) connected to {conn.raddr}"
                print(message)
                log_to_file(message)
        except:
            pass

def run_scan():
    detect_keylogger()
    check_network_activity()

if __name__ == "__main__":
    # Run scan every 10 minutes
    schedule.every(10).minutes.do(run_scan)
    run_scan()  # Run once on start
    while True:
        schedule.run_pending()
        time.sleep(1)