import subprocess
import shutil
import argparse
import sys
import re
import os
import ftplib
import requests


def GetUserInput():
    parser = argparse.ArgumentParser(
        description="Search.py - Works with Host and optional parameters"
    )

    parser.add_argument("host", type=str, help="Host to search")

    parser.add_argument("-t", "--test", type=str, help="Test message", default=None)

    parser.add_argument("-y", action="store_true", help="Enable aggressive mode")

    args = parser.parse_args()

    return {"host": args.host, "testMessage": args.test, "aggressiveMode": args.y}


def checkAndInstall():
    if not os.path.exists("./results"):
        print("Create results dir")
        os.makedirs("./results")

    packages = ["nmap", "dirsearch"]
    download_packages = ["sudo", "apt", "install", "-y"]
    for pack in packages:
        if not shutil.which(pack):
            download_packages.append(pack)
            print(f"Download {pack}")

    if len(download_packages) > 4:
        update_args = ["sudo", "apt", "update"]
        print("Update apt")
        subprocess.run(update_args)
        print("Packs are download")
        subprocess.run(download_packages)
        print("Please restart tool")
        sys.exit(0)


class PortScan:
    def __init__(self, host, agressiveMode=False):
        self.log = "\n\n***************HOST SCAN***************\n\n"
        self.host = host
        self.agressiveMode = agressiveMode
        self.ports = ""
        self.port_services = ""

    def portScan(self):

        self.log += "==========PORTSCAN==========\n"
        print("==========PORTSCAN==========\n")
        if not self.host:
            self.log += "---NOTIFICATION---"
            print("---NOTIFICATION---")
            self.log += "Please enter Host"
            print("Please enter Host")
            return
        args = [
            "sudo",
            "nmap",
            self.host,
            "-T5",
            "-oN",
            "./results/nmapScan.txt",
            "-vv",
        ]
        scan = subprocess.run(args, capture_output=True, check=True, text=True)

        if scan.stderr:
            self.log += "---NOTIFICATION---"
            print("---NOTIFICATION---")
            self.log += scan.stderr + "\n"
            print(scan.stderr + "\n")

        port_pattern = r"(\d+)/(udp|tcp)"
        ports_with_protocol = re.findall(port_pattern, scan.stdout)

        if not ports_with_protocol:
            self.log += "No open Port\n"
            print("No open Port")
            return ""

        ports_num = list(set(port[0] for port in ports_with_protocol))
        ports = ",".join(ports_num)
        self.log += f"[+] Finded ports: {ports}\n\n"
        print(f"[+] Finded ports: {ports}\n\n")
        self.ports = ports

    def agressiveScan(self):
        self.log += "==========AGRESIVE SCAN==========\n"
        print("==========AGRESIVE SCAN==========\n")

        continue_agresive_scan = "y"
        if self.agressiveMode == False:
            continue_agresive_scan = input("Do you Want a Agresive scan? [y/N] ")
            self.log += f"Do you Want a Agresive scan? [y/N] {continue_agresive_scan}\n"

        if continue_agresive_scan.lower() != "y":
            self.log += "Pass the agresive Scan\n"
            print("Pass the agresive Scan\n")
            return

        if not self.host or not self.ports:
            self.log += "---NOTIFICATION---\n"
            print("---NOTIFICATION---\n")
            self.log += "Please enter Ports or Host\n"
            print("Please enter Ports or Host\n")
            return
        args = [
            "sudo",
            "nmap",
            self.host,
            "-T5",
            "-A",
            "-oN",
            "./results/agresiveScan.txt",
            "-vv",
            "-p",
            self.ports,
        ]
        scan = subprocess.run(args, capture_output=True, check=True, text=True)

        if scan.stderr:
            self.log += "---NOTIFICATION---\n"
            print("---NOTIFICATION--\n-")
            self.log += scan.stderr + "\n"
            print(scan.stderr + "\n")

        self.log += "If You want see result go ./results/agresiveScan.txt\n"
        print("If You want see result go ./results/agresiveScan.txt\n")

    def checkServices(self):

        self.log += "==========SERVICES==========\n"
        print("==========SERVICES==========\n")
        if not self.host or not self.ports:
            self.log += "---NOTIFICATION---"
            print("---NOTIFICATION---")
            self.log += "Please enter Ports or Host"
            print("Please enter Ports or Host")
            return
        args = [
            "sudo",
            "nmap",
            self.host,
            "-T5",
            "-oN",
            "./results/serviceScan.txt",
            "-vv",
            "-p",
            self.ports,
        ]
        scan = subprocess.run(args, capture_output=True, check=True, text=True)

        if scan.stderr:
            self.log += "---NOTIFICATION---"
            print("---NOTIFICATION---")
            self.log += scan.stderr + "\n"
            print(scan.stderr + "\n")

        services = scan.stdout.split("\n\n")[1]
        self.log += services + "\n\n"
        print(services + "\n\n")

        pattern = re.compile(r"^(\d+)/(?:tcp|udp)\s+\w+\s+(\S+)", re.MULTILINE)

        matches = pattern.findall(scan.stdout)

        port_services = {service: port for port, service in matches}
        self.port_services = port_services


class Ftp:
    def __init__(self, host, port=21, local_dir="results/ftp", timeout=10):
        self.log = "\n\n***************FTP SCAN***************\n\n"
        self.port = int(port)
        self.host = host
        self.timeout = timeout
        self.local_dir = local_dir
        self.user = "anonymous"
        self.passwd = "anonymous"
        self.anonymousLogin = False

    def checkAnonymousFtp(self):
        try:
            self.log += "==========ANONYMOUS LOGIN==========\n"
            print("==========ANONYMOUS LOGIN==========\n")
            ftp = ftplib.FTP()
            ftp.set_pasv(True)
            ftp.connect(host=self.host, port=self.port, timeout=self.timeout)

            ftp.login(user=self.user, passwd=self.passwd)
            self.log += f"[+] Anonymous FTP login successful on {self.host}!\n"
            print(f"[+] Anonymous FTP login successful on {self.host}!\n")
            ftp.quit()
            self.anonymousLogin = True
            return True
        except ftplib.all_errors as e:
            print(f"[-] Anonymous FTP login not open {self.host}: {e}")
            return False

    def downloadDir(self, ftp, remote_dir):
        try:
            items = []
            ftp.dir(lambda x: items.append(x))

            for item in items:
                parts = item.split()
                name = parts[-1]
                is_dir = item.startswith("d")

                if name in (".", ".."):
                    continue

                remote_path = (
                    f"{remote_dir}/{name}" if remote_dir != "/" else f"/{name}"
                )
                local_path = os.path.join(self.local_dir, name)

                if is_dir:
                    if not os.path.exists(local_path):
                        os.makedirs(local_path)
                    print(f"[+] Created local directory: {local_path}")

                    try:
                        ftp.cwd(remote_path)
                        self.downloadDir(ftp, remote_path)
                        ftp.cwd("..")
                    except ftplib.error_perm as e:
                        print(f"[-] Cannot access directory {remote_path}: {e}\n")
                        self.log += f"[-] Cannot access directory {remote_path}: {e}\n"
                else:
                    try:
                        with open(local_path, "wb") as local_file:
                            print(
                                f"[+] Downloading file: {remote_path} to {local_path}\n"
                            )
                            self.log += (
                                f"[+] Downloading file: {remote_path} to {local_path}\n"
                            )
                            ftp.retrbinary(f"RETR {name}", local_file.write)
                    except ftplib.error_perm as e:
                        print(f"[-] Failed to download {remote_path}: {e}\n")
                        self.log += f"[-] Failed to download {remote_path}: {e}\n"

        except ftplib.all_errors as e:
            print(f"[-] Error in directory {remote_dir}: {e}\n")
            self.log += f"[-] Error in directory {remote_dir}: {e}\n"

    def getFiles(self):
        try:
            if self.anonymousLogin == False:
                print("[-] Anonymous login false, Can't download files")
                self.log += "[-] Anonymous login false, Can't download files"
                return

            ftp = ftplib.FTP()
            ftp.set_pasv(True)
            ftp.connect(host=self.host, port=self.port, timeout=self.timeout)
            ftp.login(user=self.user, passwd=self.passwd)

            if not os.path.exists(self.local_dir):
                os.makedirs(self.local_dir)

            self.downloadDir(ftp, "/")

            ftp.quit()
            print("[+] Download completed!\n")
            self.log += "[+] Download completed!\n"
            return True

        except ftplib.all_errors as e:
            print(f"[-] Error: {e}")
            return False


class Http:
    def __init__(self, host, port=80):
        self.log = "***************HTTP SCAN***************\n"
        self.host = host
        self.port = port

    # curl ip:port
    # curl -L ip:port
    # curl -I ip:port
    # curl http://target/robots.txt


class Https(Http):
    def __init__(self):
        pass

    # echo | openssl s_client -connect ip:port 2>/dev/null | openssl x509 -noout -text


class Services:
    def __init__(self):
        self.service_map = {}

    def portScan(self):
        inputs = GetUserInput()
        print("***************HOST SCAN***************\n")
        scan = PortScan(inputs["host"], inputs["aggressiveMode"])
        scan.portScan()
        scan.checkServices()
        scan.agressiveScan()
        self.service_map = scan.port_services
        return (scan.log, scan.port_services)

    def ftpScan(self, port):
        print("***************FTP SCAN***************\n")
        inputs = GetUserInput()
        ftp = Ftp(inputs["host"], port)
        ftp.checkAnonymousFtp()
        ftp.getFiles()
        return ftp.log

    def httpScan(self, port):
        print("***************HTTP SCAN***************\n")
        inputs = GetUserInput()
        http = Http(inputs["host"], port)
        return http.log

    def services(self):
        services_log = ""
        try:
            if "ftp" in self.service_map:
                services_log += self.ftpScan(self.service_map["ftp"])
            if "http" in self.service_map:
                services_log += self.httpScan(self.service_map["http"])
            if "https" in self.service_map:
                pass
        except KeyError as e:
            print(f"[-] Error: Service {e} not found in self.services")
            services_log += f"[-] Error: Service {e} not found in self.services\n"
        except Exception as e:
            print(f"[-] Error in services method: {e}")
            services_log += f"[-] Error in services method: {e}\n"
        return services_log


def main():
    log = ""
    checkAndInstall()
    services_scan = Services()
    port_scan = services_scan.portScan()
    log += port_scan[0]
    services_log = services_scan.services()
    log += services_log
    with open("results/mainLogs.log", "w") as file:
        file.write(log)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nEXIT...\n\n")
        sys.exit(1)
