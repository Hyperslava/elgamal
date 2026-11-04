"""Формат транспортного пакета: байты UTF-8 JSON, числа строками."""
import base64
import json
from crypto.elgamal import Signature, hash_bytes


def encode_packet(message: bytes, signature: Signature, key_id: str = 'A-default') -> bytes:
    _, message_hash = hash_bytes(message)
    obj = {'version': 1, 'sender': 'A', 'recipient': 'B', 'key_id': key_id,
           'message_b64': base64.b64encode(message).decode('ascii'),
           'message_hash': message_hash,
           'signature': {'a': str(signature.a), 'b': str(signature.b)}}
    return json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def decode_packet(packet: bytes):
    if len(packet) > 10_000_000:
        raise ValueError('Слишком большой пакет')
    obj = json.loads(packet.decode('utf-8'))
    if obj['version'] != 1 or obj['recipient'] != 'B':
        raise ValueError('Неподдерживаемая версия или адресат')
    message = base64.b64decode(obj['message_b64'], validate=True)
    sig = Signature(int(obj['signature']['a']), int(obj['signature']['b']))
    message_hash = obj['message_hash']
    if not isinstance(message_hash, str) or len(message_hash) != 64:
        raise ValueError('Некорректный хеш сообщения')
    int(message_hash, 16)
    return message, sig, obj['key_id'], message_hash
