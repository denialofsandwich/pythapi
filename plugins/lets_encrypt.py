#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: lets_encrypt.py
# Author:      Rene Fa
# Date:        22.06.2018
# Version:     0.1
#
# Copyright:   Copyright (C) 2018  Rene Fa
#
#              This program is free software: you can redistribute it and/or modify
#              it under the terms of the GNU Affero General Public License as published by
#              the Free Software Foundation, either version 3 of the License, or any later version.
#
#              This program is distributed in the hope that it will be useful,
#              but WITHOUT ANY WARRANTY; without even the implied warranty of
#              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#              GNU Affero General Public License for more details.
#
#              You should have received a copy of the GNU Affero General Public License
#              along with this program.  If not, see https://www.gnu.org/licenses/agpl-3.0.de.html.
#

import sys
sys.path.append("..")
#import MySQLdb # MySQL
from api_plugin import * # Essential Plugin

plugin = api_plugin()
plugin.name = "lets_encrypt"
plugin.version = "0.1"
plugin.essential = False
plugin.info['f_name'] = {
    'EN': 'Let\'s Encrypt'
}

plugin.info['f_description'] = {
    'EN': 'This plugin is to request certificates from Let\'s Encrypt.',
    'DE': 'Dieses Plugin ermöglicht Let\'s Encrypt Zertifikate anzufordern.'
}

plugin.depends = [
    {
        'name': 'auth',
        'required': True
    }
]

plugin.config_defaults = {}
plugin.translation_dict = {}

@api_external_function(plugin)
def e_list_available_certificates():
    
    
    
    
    return 1

@api_event(plugin, 'install')
def install():
    return 1

@api_event(plugin, 'uninstall')
def uninstall():
    return 1

@api_event(plugin, 'load')
def load():
    return 1

@api_action(plugin, {
    'path': 'cert/list',
    'method': 'GET',
    'f_name': {
        'EN': 'List available certificates',
        'DE': 'Zeige verfügbare Zertifikate'
    },

    'f_description': {
        'EN': 'Returns a list of all currently available certificates.',
        'DE': 'Gibt eine Liste mit allen zurzeit verfügbaren Zertifiaten zurück.'
    }
})
def list_available_certificates(reqHandler, p, args, body):
    return {
        'data': "Nothing there."
    }
