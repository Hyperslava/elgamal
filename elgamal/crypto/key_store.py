"""Файлы ключей сохраняются раздельно. Закрытый ключ не шифруется (учебный режим)."""
import json
from pathlib import Path
from .elgamal import PublicKey, PrivateKey


def save_keys(public, private, folder='keys'):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    (folder/'public.json').write_text(json.dumps({'p':str(public.p),'A':str(public.A),'y':str(public.y)}, indent=2), encoding='utf-8')
    (folder/'private.json').write_text(json.dumps({'p':str(private.p),'A':str(private.A),'y':str(private.y),'xi':str(private.xi)}, indent=2), encoding='utf-8')


def load_keys(folder='keys'):
    folder = Path(folder)
    pub = json.loads((folder/'public.json').read_text(encoding='utf-8'))
    priv = json.loads((folder/'private.json').read_text(encoding='utf-8'))
    return PublicKey(**{k:int(v) for k,v in pub.items()}), PrivateKey(**{k:int(v) for k,v in priv.items()})
