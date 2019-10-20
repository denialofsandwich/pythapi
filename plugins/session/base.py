#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base
import core.casting
from . import header

from Crypto.Hash import HMAC
from Crypto.Cipher import AES
import Crypto.Random
import base64
import datetime
import json


@core.plugin_base.external(header.plugin)
def set_cookie(robj, name, data, signed=True, encrypted=False, expires=None):
    config = core.plugin_base.config[header.plugin.name]

    if type(expires) is datetime.datetime:
        expire_time = expires
    else:
        expire_time = datetime.datetime.now() + datetime.timedelta(0, expires or config['default_expiration_time'])

    message_obj = {
        "h": {
            "t": header.plugin.encode_type[type(data)],
        },
    }

    if encrypted or signed:
        message_obj['h']["e"] = expire_time.strftime('%Y-%m-%dT%H:%M:%SZ')

    if expires is None:
        expire_time = None

    data = core.casting.reinterpret(data, **{
            "type": str,
            "sort_keys": True,
        }).encode('utf8')

    if encrypted:
        c = AES.new(header.crypt_key, AES.MODE_GCM)
        c.update(name.encode('utf8'))
        c.update(core.casting.reinterpret(message_obj['h'], **{
            "type": str,
            "sort_keys": True,
        }).encode('utf8'))
        ciphertext, signature = c.encrypt_and_digest(data)

        message_obj['d'] = base64.b64encode(ciphertext).decode('utf8')
        message_obj['n'] = base64.b64encode(c.nonce).decode('utf8')
        message_obj['s'] = base64.b64encode(signature).decode('utf8')

    elif signed:
        h = HMAC.new(header.secret)
        h.update(name.encode('utf8'))
        h.update(core.casting.reinterpret(message_obj['h'], **{
            "type": str,
            "sort_keys": True,
        }).encode('utf8'))
        h.update(data)

        message_obj['d'] = base64.b64encode(data).decode('utf8')
        message_obj['s'] = base64.b64encode(h.digest()).decode('utf8')

    else:
        message_obj['d'] = base64.b64encode(data).decode('utf8')

    robj.set_cookie(name, base64.b64encode(json.dumps(message_obj).encode('utf8')), expires=expire_time)


@core.plugin_base.external(header.plugin)
def get_cookie(robj, name, signed=True, encrypted=False):
    try:
         message_obj = json.loads(base64.b64decode(robj.get_cookie(name)).decode('utf8'))
    except Exception:
        return None

    if 'n' in message_obj and encrypted is True:
        nonce = base64.b64decode(message_obj['n'])
        ciphertext = base64.b64decode(message_obj['d'])
        signature = base64.b64decode(message_obj['s'])
        serialized_header = core.casting.reinterpret(message_obj['h'], **{
            "type": str,
            "sort_keys": True,
        }).encode('utf8')

        c = AES.new(header.crypt_key, AES.MODE_GCM, nonce=nonce)
        c.update(name.encode('utf8'))
        c.update(serialized_header)

        try:
            data = c.decrypt_and_verify(ciphertext, signature)
        except ValueError:
            return None

    elif 's' in message_obj and signed is True:
        data = base64.b64decode(message_obj['d'])
        signature = base64.b64decode(message_obj['s'])
        serialized_header = core.casting.reinterpret(message_obj['h'], **{
            "type": str,
            "sort_keys": True,
        }).encode('utf8')

        h = HMAC.new(header.secret)
        h.update(name.encode('utf8'))
        h.update(serialized_header)
        h.update(data)

        try:
            h.verify(signature)
        except ValueError:
            return None
    elif not signed and not encrypted:
        if 'h' not in message_obj or 't' not in message_obj['h']:
            return None

        try:
            data = base64.b64decode(message_obj['d']).decode('utf8')
        except Exception:
            return None
    else:
        # Expected a diffrent type
        return None

    if 's' in message_obj:
        expire_time = datetime.datetime.strptime(message_obj['h']['e'], '%Y-%m-%dT%H:%M:%SZ')

        if expire_time <= datetime.datetime.now():
            return None

    return core.casting.reinterpret(data, header.plugin.decode_type[message_obj['h']['t']])


@core.plugin_base.external(header.plugin)
def get_session_id(robj):
    config = core.plugin_base.config[header.plugin.name]

    raw_cookie = robj.get_cookie(config['session_cookie_name'])
    if raw_cookie is not None:
        return base64.b64decode(raw_cookie)
    else:
        return None


@core.plugin_base.external(header.plugin)
def create_session(robj, reset=False, expires=None):
    session_id = get_session_id(robj)

    if reset:
        destroy_session(robj)
        robj.env['session'].clear()

    if session_id not in header.session_table:
        config = core.plugin_base.config[header.plugin.name]

        if type(expires) is datetime.datetime:
            expire_time = expires
        else:
            expire_time = datetime.datetime.now() + datetime.timedelta(0, expires or config['default_expiration_time'])

        session_id = Crypto.Random.get_random_bytes(32)

        header.session_table[session_id] = {
            "expires": expire_time,
            "data": robj.env['session'],
        }
        robj.set_cookie(config['session_cookie_name'], base64.b64encode(session_id), expires=expire_time)


@core.plugin_base.external(header.plugin)
def destroy_session(robj):
    session_id = get_session_id(robj)
    if session_id in header.session_table:
        del header.session_table[session_id]
