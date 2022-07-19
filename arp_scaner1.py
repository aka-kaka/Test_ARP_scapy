
import threading
import scapy.all as sc
from scapy.config import conf
import click


conf.verb = 0

OUT_LIST=[]

@click.command()
@click.option('-s', multiple=False)
@click.option('-e', multiple=False)
def scan_local_network(**kwargs):
    if kwargs:
        ip_strt, ip_end=[kwargs[i] for i in kwargs]
    
    if not ip_end or ip_end==ip_strt:
        scan(ip_strt)
    ip_end=ip_end.split('.')[-1]
    if ip_end.isdigit():
        ip_strt=[i for i in ip_strt.split('.')]
        tuple_scan_addr=list()
        for i in range(int(ip_strt[-1]),int(ip_end)+1):
            tuple_scan_addr.append(f'{".".join(ip_strt[0:3])}.{i}')
        else:
            procs = [threading.Thread(target=scan, args=(i,)) for i in tuple_scan_addr] # создаем столько процессов, сколько имеем функций
            for proc in procs:
                proc.start()

                
            for proc in procs:
                proc.join()
    print(OUT_LIST)


def scan(ip):
    ether_layer = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_layer = sc.ARP(pdst=ip)
    arp_request = ether_layer / arp_layer
    if sc.srp(arp_request, timeout=0.5)[0]:
        OUT_LIST.append(f'{ip}| {sc.getmacbyip(ip)}')

        
        
if __name__ == "__main__":
    scan_local_network()
    
