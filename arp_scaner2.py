#TODO
    ###############################################################
    #  
    # !!!сделать проверку на корректность введенных данных!!!
    # !!!реализовать возможность получения маски в коротком виде!!!
    # !!!разобраться с 'сlick'
    #
    ###############################################################

from multiprocessing.dummy import Pool as mp

import scapy.all as sc
from scapy.config import conf
import click


class AsinTest():
    def __init__(self, time_out=0.5) -> None:
        '''
        инициализация
        создается ARP запрос 
        '''
        self.ether_layer = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
        self.time_out = time_out

    def _get_amswer_arp(self, ip_adress):
        '''
        возвращает ip и mac
        '''
        arp_layer = sc.ARP(pdst=ip_adress)
        arp_request = self.ether_layer / arp_layer
        answered = sc.srp(arp_request, timeout=self.time_out)
        if answered[0]:
            return f'{ip_adress} | {sc.getmacbyip(ip_adress)}' 
    
    def send_request(self, ip_strt, ip_end):

        if not ip_end:
            return list((self._get_amswer_arp(ip_strt),))
        
        ip_strt = [i for i in ip_strt.split('.')]
        ip_end = ip_end.split('.')[-1]
        if ip_end == ip_strt[-1]:
            return list((self._get_amswer_arp(ip_strt),))
        

        elif int(ip_end) > int(ip_strt[-1]):

            func_lmbda = lambda x: self._get_amswer_arp(x)
            tuple_scan_addr = [f'{".".join(ip_strt[0:3])}.{i}'
                for i in range(int(ip_strt[-1]),int(ip_end)+1)]
            pool = mp(len(tuple_scan_addr))
            procs = pool.map(func_lmbda, tuple_scan_addr)
            pool.close()
            pool.join()
            return ([i for i in procs if i])
        else: 
            return None
            

conf.verb = 0
OUTPUT=[]


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

    res=AsinTest().send_request(ip_strt,ip_end)
    OUTPUT.extend(res) if res else print("None")        
    print(OUTPUT)


if __name__== "__main__":
    get_parr_adr()