#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base
import core.casting
from . import header

from Crypto.Hash import HMAC, SHA256


@core.plugin_base.external(header.plugin)
def set_cookie(robj, name, data, signed=True, encrypted=False, expires=None):
    config = core.plugin_base.config[header.plugin.name]
    print(config['secret'])
    # TODO: parse_conf wirft keinen Fehler, wenn der Parameter fehlt.
    h = HMAC.new(config['secret'], digestmod=SHA256)

    print(data)
    h.update(data)

    raw_data = (core.casting.reinterpret(data, **{
            "type": str,
        }) + h.hexdigest()).encode('utf8')

    robj.set_cookie(name, raw_data)


@core.plugin_base.external(header.plugin)
def create_session(robj, expires=None):
    robj.set_cookie("name", "data")
