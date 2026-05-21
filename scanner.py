import socket
import requests
from datetime import datetime

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP"
}

OUTDATED_SOFTWARE = {
    "Apache/2.2": "Outdated Apache version detected",
    "Apache/2.4.49": "Apache vulnerable to path traversal",
    "nginx/1.10": "Old Nginx version detected",
    "OpenSSH_5": "Old OpenSSH version detected"
}

report = []

def scan_ports(target):

    print(f"\nScanning Target: {target}\n")

    open_ports = []

    for port, service in COMMON_PORTS.items():

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sock.settimeout(1)

        result = sock.connect_ex((target, port))

        if result == 0:

            print(f"[OPEN] Port {port} ({service})")

            open_ports.append((port, service))

            report.append(f"[OPEN PORT] {port} ({service})")

        sock.close()

    return open_ports


def check_http_server(target):

    try:

        url = f"http://{target}"

        response = requests.get(url, timeout=3)

        server = response.headers.get("Server", "Unknown")

        print(f"\n[SERVER] {server}")

        report.append(f"[SERVER] {server}")

        for version in OUTDATED_SOFTWARE:

            if version in server:

                warning = OUTDATED_SOFTWARE[version]

                print(f"[WARNING] {warning}")

                report.append(f"[WARNING] {warning}")

    except Exception as e:

        print(f"[ERROR] HTTP Scan Failed: {e}")

        report.append(f"[ERROR] HTTP Scan Failed")


def detect_weak_configs(open_ports):

    print("\nChecking Weak Configurations...\n")

    for port, service in open_ports:

        if port == 23:

            msg = "Telnet enabled (insecure remote login)"

            print(f"[WARNING] {msg}")

            report.append(f"[WARNING] {msg}")

        if port == 21:

            msg = "FTP enabled (credentials may be unencrypted)"

            print(f"[WARNING] {msg}")

            report.append(f"[WARNING] {msg}")

        if port == 80:

            msg = "HTTP detected without HTTPS enforcement"

            print(f"[WARNING] {msg}")

            report.append(f"[WARNING] {msg}")


def generate_report(target):

    filename = "vulnerability_report.txt"

    with open(filename, "w") as file:

        file.write("====================================\n")

        file.write("     Vulnerability Scan Report\n")

        file.write("====================================\n\n")

        file.write(f"Target: {target}\n")

        file.write(f"Scan Time: {datetime.now()}\n\n")

        for item in report:

            file.write(item + "\n")

    print(f"\n[+] Report Saved: {filename}")


def main():

    print("===================================")

    print("   MINI VULNERABILITY SCANNER")

    print("===================================")

    target = input("\nEnter Target IP or Domain: ")

    open_ports = scan_ports(target)

    ports_only = [p[0] for p in open_ports]

    if 80 in ports_only:

        check_http_server(target)

    detect_weak_configs(open_ports)

    generate_report(target)

    print("\nScan Completed Successfully")


if __name__ == "__main__":

    main()