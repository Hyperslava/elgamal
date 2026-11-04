from crypto.elgamal import sign, verify
from communication.packet import encode_packet, decode_packet


class Sender:
    def __init__(self, transport):
        self.transport = transport

    def sign_message(self, message: bytes, private_key):
        return sign(message, private_key)

    def send_signed(self, message: bytes, signature):
        self.transport.send(encode_packet(message, signature))

    def send(self, message: bytes, private_key):
        signature, log = self.sign_message(message, private_key)
        self.send_signed(message, signature)
        return signature, log


class Receiver:
    def __init__(self, transport):
        self.transport = transport

    def receive(self):
        packet = self.transport.receive_nowait()
        if packet is None:
            return None
        message, signature, key_id, message_hash = decode_packet(packet)
        if key_id != 'A-default':
            raise ValueError('Неизвестный идентификатор ключа')
        return message, signature, message_hash

    def poll(self, public_key):
        received = self.receive()
        if received is None:
            return None
        message, signature, _ = received
        valid, log = verify(message, signature, public_key)
        return message, signature, valid, log
