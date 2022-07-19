#TODO
    ###############################################################
    #  
    # !!!сделать проверку на корректность введенных данных!!!
    # !!!реализовать возможность получения маски в коротком виде!!!
    # !!!разобраться с 'сlick'
    #
    ###############################################################

import threading

import scapy.all as sc
from scapy.config import conf
import click


conf.verb = 0
OUT_LIST=[]


@click.command()
@click.option('-s', multiple=False, help='начальный ip адрес')
@click.option('-e', multiple=False,help='конечный ip адрес')
def get_parr_adr(**kwargs):
    """
    отправляет широковещательный запрос по пулу из указанных адресов\n
    принимает в качестве аргументов:\n
    "-s" начальный адрес\n
    "-e" конечный адрес или 4-й октет конечного ip адреса\n
    при вызове без аргументов отправляет запросы по всем адресам с 1 по 255\n
    при отсутствии начального адреса начинает с первого адреса, сетевого интерфейса по умолчанию\n
    при отсутствии конечного отправляет только введенный адрес\n
    """
    
    ip_strt = kwargs['s']
    ip_end = kwargs['e']
    del(kwargs)


    if not ip_strt:
        ip_strt='{0}.{1}'.format(
                '.'.join(sc.get_if_addr(sc.conf.iface).split(".")),
                '1')
        if not ip_end: ip_end='255'
    
    tuple_scan_addr=list()
    ip_strt=ip_strt.split('.')
    if not ip_end:
        scan(".".join(ip_strt))
    else:
        ip_end=ip_end.split('.')[-1]
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
        OUT_LIST.append(f'{ip} | {sc.getmacbyip(ip)}')


if __name__== "__main__":
    get_parr_adr()
