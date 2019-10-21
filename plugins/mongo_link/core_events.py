#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base
import core.casting

from . import header
from mongoengine import *

plugin = header.plugin

@core.plugin_base.event(plugin, 'core.load', {})
def load():
    global log
    log = core.plugin_base.log

    host = core.plugin_base.config[plugin.name]['host']
    port = core.plugin_base.config[plugin.name]['port']
    use_auth = False
    try:
        username = core.plugin_base.config[plugin.name]['username']
        password = core.plugin_base.config[plugin.name]['password']
        auth_source = core.plugin_base.config[plugin.name]['auth_source']
        use_auth = True
        log.info("Connecting to MongoDB using authentication.")
    except KeyError:
        log.info("Connecting to MongoDB without authentication.")

    # Ohne Auth
    if use_auth:
        try:
            connect('pythapi', host=host, port=port, username=username, password=password, authentication_source=auth_source)
        except Exception as e:
            log.error("Error connecting to MongoDB.", exc_info=e)
            return False
    else:
        try:
            connect('pythapi', host=host, port=port)
        except Exception as e:
            log.error("Fehler bei Aufbau der DB-Verbindung.", exc_info=e)
            return False

@core.plugin_base.event(plugin, 'core.terminate')
def terminate():
    disconnect()

@core.plugin_base.external(plugin)
def insert(model, data):
    try:
        return model(**data).save()
    except errors.FieldDoesNotExist as e:
        log.debug(str(e.args))
        log.debug(str(e.with_traceback))
        raise web.WebRequestException("FIELD_DOES_NOT_EXIST", 400, str(e))
    except Exception as e:
        log.debug("Generischer Fehler bei Mongo Insert")
        log.error(e)
