#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: dynamic_language.py
# Author:      Rene Fa
# Date:        26.04.2018
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
from api_plugin import * # Essential Plugin
import json

plugin = api_plugin()
plugin.name = "dlanguage"
plugin.version = "1.0"
plugin.essential = False
plugin.info['f_name'] = {
    'EN': 'Dynamic language',
    'DE': 'Dynamische Sprachwahl'
}

plugin.info['f_description'] = {
    'EN': 'This Plugin allow the user to set the language by themself.',
    'DE': 'Dieses Plugin ermöglicht es, dass jeder Benutzer selbst seine Sprache auswählen kann.'
}

plugin.depends = [
    {
        'name': 'auth',
        'required': True
    }
]

plugin.config_defaults = {}

@api_event(plugin, 'global_preexecution_hook')
def global_preexecution_hook(reqHandler, action):

    try:
        acc_lang = reqHandler.request.headers.get('Accept-Language', None)
        api_environment_variables()['language'] = acc_lang.split(',')[0].split(';')[0].upper()
    except: pass

    return 1










