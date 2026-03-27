"""
Author: Mohamed Amine OUATAR
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

# Import the required modules (Step ii)
import socket
import threading
import sqlite3
import os
import platform
import datetime


# Print Python version and OS name (Step iii)
print("Python Version:", platform.python_version())
print("Operating System:", os.name)

# Create the common_ports dictionary (Step iv)
# Dictionnary that maps common port numbers to their corresponding service names

common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

# Create the NetworkTool parent class (Step v)
class NetworkTool:
    # Constructor that initializes the target
    def __init__(self, target):
        self.__target = target 

    # Getter for target
    @property
    def target(self):
        return self.__target

    # Setter for target with validation
    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else: 
            self.__target = value
    
    # Destructor
    def __del__(self):
        print("NetworkTool instance destroyed")


# Q3: What is the benefit of using @property and @target.setter?
# @property allows controlled access to private attributes while keeping a simple syntax like accessing a variable
# the setter adds validation logic when modifying the value, preventing invalid data such as empty string 

# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from Networktool, which allows it to reuse its attributes and methods
# It automatically gets access to the target property without rewriting the code

# Create the PortScanner child class that inherits from NetworkTool (Step vi)
# Class that scans ports on a target machine
class PortScanner(NetworkTool):

    # Constructor
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    # Destructor
    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    #Method to scan a single port
    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            result = sock.connect_ex((self.target, port))

            if result == 0:
                status = "Open"
            else:
                status = "Closed"

            service_name = common_ports.get(port, "Unknown")

            #Thread-safe access to share list
            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()

        except socket.error as e:
            print(f"Error scanning port {port}: {e}")

        finally:
            sock.close()

        # Method to scan a range of ports using threads
        def scan_range(self, start_port, end_port):
            threads = []

            for port in range(start_port, end_port + 1):
                thread = threading.Thread(target=self.scan_port, args=(port,))

            # Start all threads
            for thread in threads:
                thread.start()

            # Join all threads
            for thread in threads:
                thread.join()

#     Q4: What would happen without try-except here?
# Without try-except , any socket error would crash the program immediately
# Using try-except allows the scanner to handle errors, continue scanning other ports and print messages

#     Q2: Why do we use threading instead of scanning one port at a time?
# Threading allows multiple ports to be scanned at the same time 
# Speeds up the scanning process

# Create save_results(target, results) function (Step vii)
def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        # Create table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXIST scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT
            )
        """)
        
        # Insert each result into the table 
        for port, status, service in results:
            scan_date = str(datetime.datetime.now())
            cursor.execute("""
                INSERT INTO scans (target, port, status, service, scan_date)
                VALUES (?, ?, ?, ?, ?)
            """, (target, port, status, service, scan_date))

        # Commit changes and close connection
        conn.commit()
        conn.close()

    except sqlite3.Error as e:
        print(f"Database error: {e}")


# Create load_past_scans() function (Step viii)
def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        #Try to select all rows from the table
        cursor.execute("SELECT target, port, status, service, scan_date FROM scans")
        rows = cursor.fetchall()

        if not rows:
            print("No past scans found.")
        else:
            for target, port, status, service, scan_date in rows:
                print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")

            conn.close()

    except sqlite3.Error:
        print("No past scans found.")




# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    
    # Get user input with try-except (Step ix)
    # Get target IP
    target = input("Enter target IP (default 127.0.0.1): ")
    if target == "":
        target = "127.0.0.1"

    try:
        # Get start port 
        start_port = int(input("Enter start port (1-1024): "))

        # Get end port
        end_port = int(input("Enter end port (1-1024): "))

        # Validate port range 
        if start_port < 1 or end_port > 1024:
            print ("Port must be between 1 and 1024.")
        elif end_port < start_port:
            print("End port must be greater than or equal to start port.")
        else:
            valid_input = True

    except ValueError:
        print("Invalid input. Please enter a valid integer.")
        valid_input = False

    # After valid input (Step x)
    if valid_input:
            scanner = PortScanner(target)

            print(f"Scanning {target} from port {start_port} to {end_port}... ")

            scanner.scan_range(start_port, end_port)

            open_ports = scanner.get_open_ports()

            print("\n--- Scan Results for {target} ---")
            for port, status, service in open_ports:
                print(f"Port {port} ({service}) - {status}")

            print("------")
            print(f"Total open ports found: {len(open_ports)}")

            # Save results 
            save_results(target, scanner.scan_results)

            # Ask for history
            choice = input("Would you like to see past scan history? (yes/no): ").lower()
            if choice == "yes":
                load_past_scans()

# Q5: New Feature Proposal
# I would add a feature that filters and displays only ports associated with specific services 
# This could be implemented using a list comprehension to select results that match a given service name entred by the user
# This would make the scanner more useful by allowing users to quickly focus on relevant services
