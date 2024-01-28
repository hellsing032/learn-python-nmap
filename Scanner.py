import nmap

scanner = nmap.PortScanner()

print("Welcome to this simple Nmap automation tool");
print("<-------------------------------------------------->");

url_addr = input("Please enter the address you want to scan:");
print("The URL address you entered is: ", url_addr);
type(url_addr);

resp = input(""" \nPlease enter the type of scan you want to run
                1)SYN Ack Scan
                2)UDP Scan
                3)Comprehensive Scan \n""");
print("You have selected option: ", resp);

if resp == '1':
    print("Nmap Version: ", scanner.nmap_version());
    scanner.scan(url_addr, '1-1024', '-v -sS');
    print(scanner.scaninfo());
    print("Ip Status: ", scanner[url_addr].state());
    print(scanner[url_addr].all_protocols());
    print("Open Ports: ", scanner[url_addr]['tcp'].keys());
elif resp == '2':
    print("Nmap Version: ", scanner.nmap_version());
    scanner.scan(url_addr, '1-1024', '-v -sU');
    print(scanner.scaninfo());
    print("Ip Status: ", scanner[url_addr].state());
    print(scanner[url_addr].all_protocols());
    print("Open Ports: ", scanner[url_addr]['udp'].keys());
elif resp == '3':
    print("Nmap Version: ", scanner.nmap_version());
    scanner.scan(url_addr, '1-1024', '-v -sS -sV -sC -A -O');
    print(scanner.scaninfo());
    print("Ip Status: ", scanner[url_addr].state());
    print(scanner[url_addr].all_protocols());
    print("Open Ports: ", scanner[url_addr]['tcp'].keys());
elif resp >= '4':
    print("Please enter a valid option!!!");