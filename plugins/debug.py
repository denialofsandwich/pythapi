#!/usr/bin/python

import sys
sys.path.append("..")
from api_plugin import *
import logging

plugin = api_plugin()
plugin.name = "debug"

@api_action(plugin, {
    'path': 'read/*/*',
    'method': 'POST'
})
def extract_value_test(reqHandler, p, body):
    return {
        'data1': p[0],
        'data2': p[1]
    }

@api_action(plugin, {
    'path': 'test',
    'method': 'GET'
})
def test(reqHandler, p, body):
    return {
        'data': str(logging.Logger.manager.loggerDict)
    }
