import base64
import json
import struct
import time
import logging
import imaplib
import re

import hmac
import hashlib


logger = logging.getLogger('__main__')


def load_steam_guard(steam_guard: str) -> dict:
    with open(steam_guard, 'r') as f:
        return json.loads(f.read())


def generate_one_time_code(shared_secret: str, timestamp: int) -> str:
    time_buffer = struct.pack('>Q', timestamp // 30)  # pack as Big endian, uint64
    time_hmac = hmac.new(base64.b64decode(shared_secret), time_buffer, digestmod=hashlib.sha1).digest()
    begin = ord(time_hmac[19:20]) & 0xf
    full_code = struct.unpack('>I', time_hmac[begin:begin + 4])[0] & 0x7fffffff  # unpack as Big endian uint32
    chars = '23456789BCDFGHJKMNPQRTVWXY'
    code = ''

    for _ in range(5):
        full_code, i = divmod(full_code, len(chars))
        code += chars[i]

    return code


def generate_confirmation_key(identity_secret: str, tag: str, timestamp: int = int(time.time())) -> bytes:
    buffer = struct.pack('>Q', timestamp) + tag.encode('ascii')
    return base64.b64encode(hmac.new(base64.b64decode(identity_secret), buffer, digestmod=hashlib.sha1).digest())


# It works, however it's different that one generated from mobile app
def generate_device_id(steam_id: str) -> str:
    hexed_steam_id = hashlib.sha1(steam_id.encode('ascii')).hexdigest()
    return 'android:' + '-'.join([hexed_steam_id[:8],
                                  hexed_steam_id[8:12],
                                  hexed_steam_id[12:16],
                                  hexed_steam_id[16:20],
                                  hexed_steam_id[20:32]])


def fetch_emailauth(email, email_password, imap_host):
    server = imaplib.IMAP4_SSL(imap_host)
    server.login(email, email_password)
    server.select()
    result, data = server.uid("search", None, '(HEADER Subject "Access from new web or mobile device")')
    uid = str(data[1][0].split()[-1])
    result, data = server.uid("fetch", uid, '(UID BODY[TEXT])')
    mail = data[1][0][1].decode('utf-8')
    emailauth = re.search(r'Here is the Steam Guard code you need to login to account .+:\s+(\w{5})\s', mail).group(1)
    logger.info("EMAILAUTH: %s", emailauth)

    return emailauth
