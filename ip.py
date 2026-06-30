import struct
from iputils import *


class IP:
    def __init__(self, enlace):
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela = []

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            next_hop = self._next_hop(dst_addr)
            ttl -= 1
            if ttl == 0:
                icmp_data = struct.pack('!BBHI', 11, 0, 0, 0) + datagrama[:28]
                checksum = calc_checksum(icmp_data)
                icmp_data = struct.pack('!BBH', 11, 0, checksum) + b'\x00\x00\x00\x00' + datagrama[:28]
                self._enviar_raw(icmp_data, src_addr, IPPROTO_ICMP)
                return
            datagrama = bytearray(datagrama)
            ihl = (datagrama[0] & 0xf) * 4
            datagrama[8] = ttl
            datagrama[10] = 0
            datagrama[11] = 0
            struct.pack_into('!H', datagrama, 10, calc_checksum(bytes(datagrama[:ihl])))
            self.enlace.enviar(bytes(datagrama), next_hop)

    def _enviar_raw(self, payload, dest_addr, proto):
        next_hop = self._next_hop(dest_addr)
        src = self.meu_endereco or '0.0.0.0'
        total_len = 20 + len(payload)
        header = struct.pack('!BBHHHBBH', 0x45, 0, total_len, 0, 0, 64, proto, 0) + \
                 str2addr(src) + str2addr(dest_addr)
        checksum = calc_checksum(header)
        header = struct.pack('!BBHHHBBH', 0x45, 0, total_len, 0, 0, 64, proto, checksum) + \
                 str2addr(src) + str2addr(dest_addr)
        self.enlace.enviar(header + payload, next_hop)

    def _next_hop(self, dest_addr):
        dest_int = struct.unpack('!I', str2addr(dest_addr))[0]
        best_hop = None
        best_len = -1
        for cidr, next_hop in self.tabela:
            network, prefix_len = cidr.split('/')
            prefix_len = int(prefix_len)
            mask = (0xffffffff << (32 - prefix_len)) & 0xffffffff if prefix_len else 0
            network_int = struct.unpack('!I', str2addr(network))[0]
            if (dest_int & mask) == (network_int & mask) and prefix_len > best_len:
                best_len = prefix_len
                best_hop = next_hop
        return best_hop

    def definir_endereco_host(self, meu_endereco):
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        self.tabela = tabela

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        next_hop = self._next_hop(dest_addr)
        src = self.meu_endereco or '0.0.0.0'
        total_len = 20 + len(segmento)
        header = struct.pack('!BBHHHBBH', 0x45, 0, total_len, 0, 0, 64, IPPROTO_TCP, 0) + \
                 str2addr(src) + str2addr(dest_addr)
        checksum = calc_checksum(header)
        header = struct.pack('!BBHHHBBH', 0x45, 0, total_len, 0, 0, 64, IPPROTO_TCP, checksum) + \
                 str2addr(src) + str2addr(dest_addr)
        datagrama = header + segmento
        self.enlace.enviar(datagrama, next_hop)