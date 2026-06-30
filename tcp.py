import asyncio
import random
import time
from tcputils import *


class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no)
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, seq_no_cliente):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None

        src_addr, src_port, dst_addr, dst_port = id_conexao

        self.ack_no = seq_no_cliente + 1
        self.seq_no = random.randint(0, 0xffffffff)

        segmento = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_SYN | FLAGS_ACK)
        segmento = fix_checksum(segmento, src_addr, dst_addr)
        self.servidor.rede.enviar(segmento, src_addr)

        self.seq_no += 1
        self.fechada = False

        self.nao_confirmados = []
        self.timer = None
        self.timeout_interval = 0.5
        self.estimated_rtt = None
        self.dev_rtt = None
        self.cwnd = MSS
        self.bytes_confirmados_na_janela = 0
        self.buffer = b''

    def _update_rtt(self, sample_rtt):
        if self.estimated_rtt is None:
            self.estimated_rtt = sample_rtt
            self.dev_rtt = sample_rtt / 2
        else:
            self.dev_rtt = 0.75 * self.dev_rtt + 0.25 * abs(sample_rtt - self.estimated_rtt)
            self.estimated_rtt = 0.875 * self.estimated_rtt + 0.125 * sample_rtt
        self.timeout_interval = self.estimated_rtt + 4 * self.dev_rtt

    def _flush(self):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        in_flight = sum(len(d) for _, d, _ in self.nao_confirmados)
        while self.buffer and in_flight < self.cwnd:
            chunk = self.buffer[:MSS]
            self.buffer = self.buffer[MSS:]
            segmento = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK) + chunk
            segmento = fix_checksum(segmento, src_addr, dst_addr)
            self.servidor.rede.enviar(segmento, src_addr)
            self.nao_confirmados.append([self.seq_no, chunk, time.time()])
            if self.timer is None:
                self.timer = asyncio.get_event_loop().call_later(
                    self.timeout_interval, self._timer)
            self.seq_no += len(chunk)
            in_flight += len(chunk)

    def _timer(self):
        self.timer = None
        if not self.nao_confirmados:
            return

        self.cwnd = max(MSS, (self.cwnd // MSS // 2) * MSS)
        self.bytes_confirmados_na_janela = 0
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        entry = self.nao_confirmados[0]
        seq, chunk, _ = entry
        entry[2] = None  # marca como retransmitido;
        segmento = make_header(dst_port, src_port, seq, self.ack_no, FLAGS_ACK) + chunk
        segmento = fix_checksum(segmento, src_addr, dst_addr)
        self.servidor.rede.enviar(segmento, src_addr)
        self.timer = asyncio.get_event_loop().call_later(self.timeout_interval, self._timer)

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        if self.fechada:
            return

        if (flags & FLAGS_ACK) == FLAGS_ACK:
            agora = time.time()
            novos = []
            rtt_medido = False
            for entry in self.nao_confirmados:
                s, d, t = entry
                if s + len(d) <= ack_no:
                    if t is not None and not rtt_medido:
                        self._update_rtt(agora - t)
                        rtt_medido = True
                    self.bytes_confirmados_na_janela += len(d)
                else:
                    novos.append(entry)
            if len(novos) < len(self.nao_confirmados):
                self.nao_confirmados = novos
                if self.bytes_confirmados_na_janela >= self.cwnd:
                    self.cwnd += MSS
                    self.bytes_confirmados_na_janela = 0
                if self.timer:
                    self.timer.cancel()
                    self.timer = None
                if self.nao_confirmados:
                    self.timer = asyncio.get_event_loop().call_later(
                        self.timeout_interval, self._timer)
                self._flush()

        if seq_no != self.ack_no:
            return

        if (flags & FLAGS_FIN) == FLAGS_FIN:
            self.ack_no += 1
            segmento = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK)
            segmento = fix_checksum(segmento, src_addr, dst_addr)
            self.servidor.rede.enviar(segmento, src_addr)
            if self.callback:
                self.callback(self, b'')
            self.fechada = True
            return

        if payload:
            self.ack_no += len(payload)
            if self.callback:
                self.callback(self, payload)
            segmento = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK)
            segmento = fix_checksum(segmento, src_addr, dst_addr)
            self.servidor.rede.enviar(segmento, src_addr)

    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        if not dados:
            return
        self.buffer += dados
        self._flush()

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        segmento = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_FIN | FLAGS_ACK)
        segmento = fix_checksum(segmento, src_addr, dst_addr)
        self.servidor.rede.enviar(segmento, src_addr)
        self.seq_no += 1