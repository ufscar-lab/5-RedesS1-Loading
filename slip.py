END = 0xC0
ESC = 0xDB
ESC_END = 0xDC
ESC_ESC = 0xDD


class CamadaEnlace:
    ignore_checksum = False

    def __init__(self, linhas_seriais):
        """
        Inicia uma camada de enlace com um ou mais enlaces, cada um conectado
        a uma linha serial distinta. O argumento linhas_seriais é um dicionário
        no formato {ip_outra_ponta: linha_serial}. O ip_outra_ponta é o IP do
        host ou roteador que se encontra na outra ponta do enlace, escrito como
        uma string no formato 'x.y.z.w'. A linha_serial é um objeto da classe
        PTY (vide camadafisica.py) ou de outra classe que implemente os métodos
        registrar_recebedor e enviar.
        """
        self.enlaces = {}
        self.callback = None
        # Constrói um Enlace para cada linha serial
        for ip_outra_ponta, linha_serial in linhas_seriais.items():
            enlace = Enlace(linha_serial)
            self.enlaces[ip_outra_ponta] = enlace
            enlace.registrar_recebedor(self._callback)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de enlace
        """
        self.callback = callback

    def enviar(self, datagrama, next_hop):
        """
        Envia datagrama para next_hop, onde next_hop é um endereço IPv4
        fornecido como string (no formato x.y.z.w). A camada de enlace se
        responsabilizará por encontrar em qual enlace se encontra o next_hop.
        """
        # Encontra o Enlace capaz de alcançar next_hop e envia por ele
        self.enlaces[next_hop].enviar(datagrama)

    def _callback(self, datagrama):
        if self.callback:
            self.callback(datagrama)


class Enlace:
    def __init__(self, linha_serial):
        self.linha_serial = linha_serial
        self.linha_serial.registrar_recebedor(self.__raw_recv)
        self.__buffer = b''
        self.__escapando = False

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, datagrama):
        # Escapa 0xDB antes de 0xC0 para evitar ambiguidade
        datagrama = datagrama.replace(bytes([ESC]), bytes([ESC, ESC_ESC]))
        datagrama = datagrama.replace(bytes([END]), bytes([ESC, ESC_END]))
        self.linha_serial.enviar(bytes([END]) + datagrama + bytes([END]))

    def __raw_recv(self, dados):
        for byte in dados:
            if self.__escapando:
                self.__escapando = False
                if byte == ESC_END:
                    self.__buffer += bytes([END])
                elif byte == ESC_ESC:
                    self.__buffer += bytes([ESC])
                # bytes inválidos após ESC são ignorados
            elif byte == ESC:
                self.__escapando = True
            elif byte == END:
                datagrama = self.__buffer
                self.__buffer = b''
                if len(datagrama) == 0:
                    continue
                try:
                    self.callback(datagrama)
                except:
                    import traceback
                    traceback.print_exc()
                finally:
                    self.__buffer = b''
                    self.__escapando = False
            else:
                self.__buffer += bytes([byte])
