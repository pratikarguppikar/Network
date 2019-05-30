import nmap
ip = str(input("Enter the ip:"))
nm=nmap.PortScanner()
nm.scan(ip, '22-443')
nm.command_line()
nm.scaninfo()
nm.all_hosts()
nm[ip].hostname()
print('----------------------------------------------------')
print('Host : %s (%s)' % (ip, nm[ip].hostname()))
print('State : %s' % nm[ip].state())
proto = nm[ip].all_protocols()
for i in range(len(proto)):
    all_port = nm[ip][proto[i]]
    for port in all_port:
        print('port : %s\t protocol : %s\t state : %s' % (port, proto[i], nm[ip][proto[i]][port]['state']))


