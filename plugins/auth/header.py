#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: auth
# Author:      Rene Fa
# Date:        03.01.2019
# Version:     1.6
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
from api_plugin import *

import hashlib
import base64
import json
import string
import random

cookie_length = 64
session_clean_threshold = 1000

plugin = api_plugin()
plugin.name = "auth"
plugin.version = "1.6"
plugin.essential = True
plugin.info['f_name'] = {
    'EN': 'Authentification',
    'DE': 'Authentifikation'
}

plugin.info['f_description'] = {
    'EN': 'This plugin implements authentification. You can create accounts and grant permissions to them.',
    'DE': 'Dieses Plugin implementiert Authentifikation. Es können Accounts erstellt und diesem Rechte zugewiesen werden.'
}

plugin.depends = []

plugin.config_defaults = {
    plugin.name: {
        'sec_salt': 'generatea64characterrandomstring',
        'bf_basic_auth_delay': 0.5,
        'bf_temporary_ban_enabled': True,
        'session_expiration_time': 604800,
        'session_create_limit': 1000,
        'first_user_password': ""
    }
}

plugin.translation_dict = {
    'AUTH_USER_NOT_FOUND': {
        'EN': 'User not found.',
        'DE': 'Benutzer nicht gefunden.'
    },
    
    'AUTH_USER_EXISTS': {
        'EN': 'User already exists.',
        'DE': 'Benutzer existiert bereits.'
    },
    
    'AUTH_ROLE_NOT_FOUND': {
        'EN': 'Role not found.',
        'DE': 'Rolle nicht gefunden.'
    },
    
    'AUTH_ROLE_EXISTS': {
        'EN': 'Role already exists.',
        'DE': 'Rolle existiert bereits.'
    },
    
    'AUTH_SESSION_LIMIT_EXCEEDED': {
        'EN': 'Session limit exceeded.',
        'DE': 'Session Limit erreicht.'
    },
    
    'AUTH_SESSION_ID_NOT_FOUND': {
        'EN': 'Session ID doesn\'t exist.',
        'DE': 'Session ID nicht gefunden.'
    },
    
    'AUTH_SESSION_EXPIRED': {
        'EN': 'Session expired.',
        'DE': 'Session abgelaufen.'
    },
    
    'AUTH_TOKEN_NOT_FOUND': {
        'EN': 'Token doesn\'t exist.',
        'DE': 'Token nicht gefunden.'
    },
    
    'AUTH_TOKEN_EXISTS': {
        'EN': 'Token name already exists.',
        'DE': 'Tokenname existiert bereits.'
    },
    
    'AUTH_USER_IS_MEMBER': {
        'EN': 'User is already a member of this Role.',
        'DE': 'Benutzer ist bereits ein Mitglied dieser Rolle.'
    },
    
    'AUTH_USER_IS_NOT_MEMBER': {
        'EN': 'User is not a member of this Role.',
        'DE': 'Benutzer ist kein Mitglied dieser Rolle.'
    },
    
    'AUTH_PERMISSIONS_DENIED': {
        'EN': 'Permissions denied.',
        'DE': 'Zugriff verweigert.'
    },
    
    'AUTH_TOO_MANY_LOGIN_FAILS': {
        'EN': 'Too many failed login attempts.',
        'DE': 'Zu viele fehlerhafte Loginversuche.'
    },
    
    'AUTH_WRONG_PASSWORD_OR_USERNAME': {
        'EN': 'Invalid username or password.',
        'DE': 'Falscher Benutzername oder Passwort.'
    },
    
    'AUTH_INVALID_USER_TOKEN': {
        'EN': 'Invalid API token.',
        'DE': 'Ungültiges API Token.'
    },
    
    'AUTH_INVALID_CSRF_TOKEN': {
        'EN': 'Invalid CSRF token.',
        'DE': 'Ungültiges CSRF Token.'
    },
    
    'AUTH_SESSION_EXPIRED': {
        'EN': 'Session expired.',
        'DE': 'Session abgelaufen.'
    },
    
    'AUTH_PASSWORD_MISSING': {
        'EN': 'Password missing.',
        'DE': 'Passwort leer.'
    },
    
    'AUTH_USERNAME_MISSING': {
        'EN': 'Username missing.',
        'DE': 'Username leer.'
    },
    
    'AUTH_ROLE_MISSING': {
        'EN': 'Role missing.',
        'DE': 'Rollenname leer.'
    },
    
    'AUTH_SYNTAX_ERROR_1': {
        'EN': 'Auth: Syntax error in role {}: {}',
        'DE': 'Auth: Syntaxfehler in der Rolle {}: {}'
    },
    
    'AUTH_SYNTAX_ERROR_2': {
        'EN': 'Auth: Error in role {}: Plugin {} not found.',
        'DE': 'Auth: Fehler in der Rolle {}: Plugin {} nicht gefunden.'
    },
    
    'AUTH_SYNTAX_ERROR_3': {
        'EN': 'Auth: Error in role {}: Action {} not found.',
        'DE': 'Auth: Fehler in der Rolle {}: Action {} nicht gefunden.'
    },

    'AUTH_SESSION_NOT_FOUND': {
        'EN': 'Session not found or already closed.',
        'DE': 'Session nicht gefunden oder bereits beendet.'
    },

    'AUTH_EXECUTION_DENIED': {
        'EN': 'The execution of this request was denied.',
        'DE': 'Die Ausführung der Anfrage wurde verweigert.'
    }
}

class auth_globals:
    current_user = "anonymous"
    auth_type = "none"
    current_token = None
    users_dict = {}
    user_token_dict = {}
    session_dict = {}
    roles_dict = {}
    write_through_cache_enabled = False
    bf_blacklist = {}
    bf_basic_auth_delay = 0
    bf_temporary_ban_enabled = True
    session_counter = 0
    permission_reduce_handlers = []
    subset_intersection_handlers = []
    plugin = plugin

@api_external_function(plugin)
def e_generate_random_string(size=6, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

@api_external_function(plugin)
def e_hash_password(username, password):
    h = hashlib.sha256()
    h.update(username.encode('utf-8'))
    h.update(password.encode('utf-8')) 
    h.update(api_config()[plugin.name]['sec_salt'].encode('utf-8'))
    h_password = h.hexdigest()
    return h_password

