#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base
from . import header
from . import base

import datetime

from Crypto.Hash import SHA256


@core.plugin_base.event(header.plugin, 'core.load')
def load():
    config = core.plugin_base.config[header.plugin.name]

    header.secret = config['secret']
    header.crypt_key = SHA256.new(header.secret).digest()[0:config['cipher_length']]


@core.plugin_base.event(header.plugin, 'web.pre_request', {
    "priority": 2
})
def setup_session(env, event_data):
    robj = env['request_obj']

    session_id = base.get_session_id(robj)
    if session_id in header.session_table:
        session = header.session_table[session_id]

        if session['expires'] <= datetime.datetime.now():
            base.destroy_session(robj)
            env['session'] = {}
        else:
            env['session'] = session['data']
    else:
        env['session'] = {}
