import socket
import threading
import time
from queue import Queue
import sys
import os
from datetime import datetime

# Clear the screen
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# Banner for the application
def print_banner():
    try:
        banner = """
    ╔═══════════════════════════════════════════╗
    ║                                           ║
    ║           NETWORK PORT SCANNER            ║
    ║                                           ║
    ╚═══════════════════════════════════════════╝
    """
        print(banner)
    except UnicodeEncodeError:
        # Fallback to ASCII if Unicode fails
        banner = """
    +---------------------------------------+
    |                                       |
    |           NETWORK PORT SCANNER        |
    |                                       |
    +---------------------------------------+
    """
        print(banner)

# Function to scan a single port
def scan_port(target, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            return port, True, service
        sock.close()
        return port, False, None
    except socket.error:
        return port, False, None

# Worker function for threading
def worker(target, port_queue, results, timeout):
    while not port_queue.empty():
        port = port_queue.get()
        port, status, service = scan_port(target, port, timeout)
        if status:
            results.append((port, service))
        port_queue.task_done()

# Main scanning function
def scan_ports(target, start_port, end_port, num_threads=100, timeout=1):
    clear_screen()
    print_banner()
    
    try:
        target_ip = socket.gethostbyname(target)
        print(f"\n[*] Target: {target} ({target_ip})")
        print(f"[*] Scanning ports {start_port} to {end_port}")
        print(f"[*] Using {num_threads} threads")
        print("\n[*] Scan started at:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        start_time = time.time()
        
        port_queue = Queue()
        results = []
        
        # Fill the queue with ports to scan
        for port in range(start_port, end_port + 1):
            port_queue.put(port)
        
        # Create and start threads
        threads = []
        for _ in range(min(num_threads, end_port - start_port + 1)):
            thread = threading.Thread(target=worker, args=(target_ip, port_queue, results, timeout))
            thread.daemon = True
            threads.append(thread)
            thread.start()
        
        # Progress indicator
        total_ports = end_port - start_port + 1
        while not port_queue.empty():
            remaining = port_queue.qsize()
            scanned = total_ports - remaining
            percent = (scanned / total_ports) * 100
            sys.stdout.write(f"\r[*] Progress: {scanned}/{total_ports} ports scanned ({percent:.1f}%)")
            sys.stdout.flush()
            time.sleep(0.5)
        
        # Wait for all threads to complete
        port_queue.join()
        
        # Sort results by port number
        results.sort(key=lambda x: x[0])
        
        # Display results
        print("\n\n[+] Scan completed in {:.2f} seconds".format(time.time() - start_time))
        print(f"[+] Found {len(results)} open ports\n")
        
        if results:
            try:
                print("╔═══════╦═══════════════════════╗")
                print("║ PORT  ║ SERVICE               ║")
                print("╠═══════╬═══════════════════════╣")
                for port, service in results:
                    print(f"║ {port:<5} ║ {service:<21} ║")
                print("╚═══════╩═══════════════════════╝")
            except UnicodeEncodeError:
                # Fallback to ASCII if Unicode fails
                print("+-------+---------------------+")
                print("| PORT  | SERVICE             |")
                print("+-------+---------------------+")
                for port, service in results:
                    print(f"| {port:<5} | {service:<19} |")
                print("+-------+---------------------+")
        else:
            print("[!] No open ports found.")
        # Display results
            print("\n\n[+] Scan completed")
            print(f"[+] Found {len(results)} open ports\n")
            
            if results:
                try:
                    print("╔═══════╦═══════════════════════╗")
                    print("║ PORT  ║ SERVICE               ║")
                    print("╠═══════╬═══════════════════════╣")
                    for port, service in sorted(results, key=lambda x: x[0]):
                        print(f"║ {port:<5} ║ {service:<21} ║")
                    print("╚═══════╩═══════════════════════╝")
                except UnicodeEncodeError:
                    # Fallback to ASCII if Unicode fails
                    print("+-------+---------------------+")
                    print("| PORT  | SERVICE             |")
                    print("+-------+---------------------+")
                    for port, service in sorted(results, key=lambda x: x[0]):
                        print(f"| {port:<5} | {service:<19} |")
                    print("+-------+---------------------+")
            else:
                print("[!] No open ports found.")
        
        return results
    
    except socket.gaierror:
        print("\n[!] Hostname could not be resolved.")
        return []
    except socket.error:
        print("\n[!] Could not connect to server.")
        return []
    except KeyboardInterrupt:
        print("\n[!] Scan canceled by user.")
        return []

# Save scan results to a file
def save_results(target, results, filename=None):
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_{target.replace('.', '_')}_{timestamp}.txt"
    
    filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports", filename)
    
    # Create reports directory if it doesn't exist
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    with open(filepath, 'w') as f:
        f.write(f"Port Scan Results for {target}\n")
        f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        if results:
            f.write("Open Ports:\n")
            f.write("===========\n")
            for port, service in results:
                f.write(f"Port {port}: {service}\n")
        else:
            f.write("No open ports found.\n")
    
    print(f"\n[+] Results saved to {filepath}")
    return filepath

# Main function to run the port scanner
def main():
    clear_screen()
    print_banner()
    
    while True:
        print("\nOptions:")
        print("1. Quick Scan (Common ports)")
        print("2. Full Scan (All ports)")
        print("3. Custom Scan")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ")
        
        if choice == '4':
            print("\nExiting program. Goodbye!")
            break
        
        if choice not in ['1', '2', '3']:
            print("\n[!] Invalid choice. Please try again.")
            continue
        
        target = input("\nEnter target IP or hostname: ")
        
        if choice == '1':
            # Common ports: HTTP, HTTPS, FTP, SSH, Telnet, SMTP, DNS, etc.
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]
            results = []
            
            print(f"\n[*] Scanning {len(common_ports)} common ports on {target}...")
            
            for port in common_ports:
                port, status, service = scan_port(target, port)
                if status:
                    results.append((port, service))
                sys.stdout.write(f"\r[*] Progress: {common_ports.index(port) + 1}/{len(common_ports)}")
                sys.stdout.flush()
            
            # Display results
            print("\n\n[+] Scan completed")
            print(f"[+] Found {len(results)} open ports\n")
            
            if results:
                print("╔═══════╦═══════════════════════╗")
                print("║ PORT  ║ SERVICE               ║")
                print("╠═══════╬═══════════════════════╣")
                for port, service in sorted(results, key=lambda x: x[0]):
                    print(f"║ {port:<5} ║ {service:<21} ║")
                print("╚═══════╩═══════════════════════╝")
            else:
                print("[!] No open ports found.")
        
        elif choice == '2':
            # Full scan (1-65535)
            results = scan_ports(target, 1, 65535)
        
        elif choice == '3':
            # Custom scan
            try:
                start_port = int(input("Enter start port (1-65535): "))
                end_port = int(input("Enter end port (1-65535): "))
                threads = int(input("Enter number of threads (1-500, default 100): ") or "100")
                
                if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
                    print("[!] Port range must be between 1 and 65535")
                    continue
                
                if start_port > end_port:
                    start_port, end_port = end_port, start_port
                
                threads = max(1, min(500, threads))
                
                results = scan_ports(target, start_port, end_port, threads)
            except ValueError:
                print("[!] Invalid input. Please enter valid numbers.")
                continue
        
        # Ask if user wants to save results
        if 'results' in locals() and results:
            save_option = input("\nDo you want to save the results? (y/n): ")
            if save_option.lower() == 'y':
                save_results(target, results)
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Program terminated by user.")