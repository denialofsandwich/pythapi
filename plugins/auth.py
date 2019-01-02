#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: _auth.py
# Author:      Rene Fa
# Date:        26.09.2018
# Version:     0.8
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
import MySQLdb # MySQL
from api_plugin import * # Essential Plugin
import tornado # For POST Body decoding
import hashlib
import base64
import time
import json
import string
import random
import math
import getpass
import copy

cookie_length = 64
session_clean_threshold = 1000

plugin = api_plugin()
plugin.name = "auth"
plugin.version = "0.8"
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

current_user = "anonymous"
auth_type = "none"
current_token = None
used_tables = ["user","user_token","role","role_member"]
users_dict = {}
user_token_dict = {}
session_dict = {}
roles_dict = {}
write_trough_cache_enabled = False
bf_blacklist = {}
bf_basic_auth_delay = 0
bf_temporary_ban_enabled = True
session_counter = 0
permission_reduce_handlers = []
subset_intersection_handlers = []

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

@api_external_function(plugin)
def i_default_permission_validator(ruleset, rule_section, target_rule):
    
    if not rule_section in ruleset:
        return 0
    
    if '*' in ruleset[rule_section]:
        return 1
    
    if target_rule.split('.')[0] in ruleset[rule_section]:
        return 1
    
    if target_rule in ruleset[rule_section]:
        return 1
    
    return 0

def ir_check_custom_permissions(role_name, rule_section, target_rule, f, depth = 0):
    
    if depth > len(roles_dict):
        raise WebRequestException(400, 'error', 'GENERAL_RECURSIVE_LOOP')
    
    if f(roles_dict[role_name]['ruleset'], rule_section, target_rule):
        return 1
    
    if 'inherit' in roles_dict[role_name]['ruleset']:
        parents = roles_dict[role_name]['ruleset']['inherit']
        for parent in parents:
            if ir_check_custom_permissions(parent, rule_section, target_rule, f, depth +1):
                return 1
        
    return 0

@api_external_function(plugin)
def e_check_custom_permissions(username, rule_section, target_rule, f = i_default_permission_validator):
    
    if not username in users_dict:
        raise WebRequestException(400, 'error', 'AUTH_USER_NOT_FOUND')
    
    for role_name in users_dict[username]['roles']:
        if ir_check_custom_permissions(role_name, rule_section, target_rule, f):
            return 1
    
    return 0

@api_external_function(plugin)
def e_check_custom_permissions_of_current_user(rule_section, target_rule, f = i_default_permission_validator):
    
    if auth_type == "token":
        if f(e_get_permissions_of_token(current_token), rule_section, target_rule):
            return 1
    else:
        for role_name in users_dict[current_user]['roles']:
            if ir_check_custom_permissions(role_name, rule_section, target_rule, f):
                    return 1
    
    return 0

@api_external_function(plugin)
def e_get_current_user():
    return current_user

@api_external_function(plugin)
def e_get_current_user_info():
    return_json = copy.deepcopy(e_get_user(current_user))
    return_json['auth_type'] = auth_type
    
    if auth_type == "token":
        return_json['token_name'] = user_token_dict[current_token]['token_name']
        return_json['ruleset'] = user_token_dict[current_token]['ruleset']
        del return_json['roles']

    return return_json

def i_get_client_ip(reqHandler):
    
    if reqHandler.request.remote_ip == "127.0.0.1":
        x_real_ip = reqHandler.request.headers.get("X-Real-IP")
        x_forwarded_for = reqHandler.request.headers.get("X-Forwarded-For")
        return x_real_ip or x_forwarded_for or reqHandler.request.remote_ip
    
    else:
        return reqHandler.request.remote_ip

def i_clean_expired_sessions():
    global session_counter
    
    for session_id in list(session_dict.keys()):
        session = session_dict[session_id]
        if time.time() > session['expiration_time']:
            e_delete_session(session_id)
    
    session_counter = 0

# To merge dicts and lists
def update_2(d, u):
    for k, v in u.items():
        if isinstance(v, collections.Mapping):
            d[k] = update(d.get(k, {}), v)
        elif type(v) == list and k in d:
            d[k].extend(v)
        else:
            d[k] = v

    return d

def ir_merge_permissions(role_name, depth=0):
    if depth > len(roles_dict):
        raise WebRequestException(400, 'error', 'GENERAL_RECURSIVE_LOOP')
        
    parent_list = roles_dict[role_name]['ruleset']['inherit']

    return_json = copy.deepcopy(roles_dict[role_name]['ruleset'])
    del return_json['inherit']

    for parent in parent_list:
        update_2(return_json, ir_merge_permissions(parent, depth+1))

    return return_json

@api_external_function(plugin)
def e_add_permission_reduce_handler(f):
    permission_reduce_handlers.append(f)

def i_permission_reduce_handler(ruleset):
    ruleset['permissions'] = list(set(ruleset['permissions']))

    if '*' in ruleset['permissions']:
        ruleset['permissions'] = ['*']
    
    for rule in list(ruleset['permissions']):
        if rule.find('.') == -1:
            for sub_rule in list(ruleset['permissions']):
                parts = sub_rule.split('.')
                if len(parts) == 2 and parts[0] == rule:
                    ruleset['permissions'].remove(sub_rule)

    return ruleset

def i_reduce_ruleset(ruleset):
    ruleset = copy.deepcopy(ruleset)
    
    for handler in permission_reduce_handlers:
        ruleset = handler(ruleset)

    return ruleset

@api_external_function(plugin)
def e_get_permissions_of_user(username):
    if not username in users_dict:
        raise WebRequestException(400, 'error', 'AUTH_USER_NOT_FOUND')

    return_json = {}
    for parent in users_dict[username]['roles']:
        update_2(return_json, ir_merge_permissions(parent))
    
    return_json = i_reduce_ruleset(return_json)
    return return_json

@api_external_function(plugin)
def e_get_permissions_of_token(h_token):
    if not h_token in user_token_dict:
        raise WebRequestException(400, 'error', 'AUTH_TOKEN_NOT_FOUND')

    return_json = copy.deepcopy(user_token_dict[h_token]['ruleset'])
    return return_json

@api_external_function(plugin)
def e_get_permissions():
    if auth_type == "token":
        return e_get_permissions_of_token(current_token)
    else:
        return e_get_permissions_of_user(e_get_current_user())

def i_subset_permission_handler(ruleset, subset):
    section = ruleset['permissions']
    return_subset = {}

    if '*' in section:
        return copy.deepcopy(subset)
    
    return_subset['permissions'] = []

    for rule in list(subset['permissions']):
        if rule in section or rule.split('.')[0] in section:
            return_subset['permissions'].append(rule)

    return return_subset

@api_external_function(plugin)
def e_add_subset_intersection_handler(f):
    subset_intersection_handlers.append(f)

@api_external_function(plugin)
def e_intersect_subset(ruleset, subset):
    return_subset = {}

    for handler in subset_intersection_handlers:
        return_subset.update(handler(ruleset, subset))

    return return_subset

@api_external_function(plugin)
def e_list_sessions(username):
    return_json = []
    for session_id in users_dict[username]['sessions']:
        i_entry = dict(session_dict[session_id])
        return_json.append(i_entry)
    
    return return_json

@api_external_function(plugin)
def e_create_session(reqHandler, username, options):
    global session_counter
    
    if reqHandler.get_cookie("session_id"):
        if reqHandler.get_cookie("session_id") in session_dict:
            e_delete_session(reqHandler.get_cookie("session_id"))
    
    if users_dict[username]['session_count'] >= api_config()[plugin.name]['session_create_limit']:
        raise WebRequestException(400, 'error', 'AUTH_SESSION_LIMIT_EXCEEDED')
    
    new_session_id = e_generate_random_string(cookie_length)
    
    session_dict[new_session_id] = {
        'username': username,
        'remote_ip': i_get_client_ip(reqHandler),
        'creation_time': time.time(),
        'expiration_time': time.time() +api_config()[plugin.name]['session_expiration_time']
    }
    
    session_counter += 1
    if session_counter > session_clean_threshold:
        i_clean_expired_sessions()
    
    if 'csrf_token' in options and options['csrf_token'] == True:
        csrf_token = e_generate_random_string(cookie_length)
        session_dict[new_session_id]['last_csrf_token'] = csrf_token
        reqHandler.add_header('X-CSRF-TOKEN', csrf_token)
    
    users_dict[current_user]['sessions'].append(new_session_id)
    users_dict[username]['session_count'] += 1
    
    reqHandler.set_cookie("session_id", new_session_id)

@api_external_function(plugin)
def e_delete_session(session_id):
    
    if not session_id in session_dict:
        raise WebRequestException(400, 'error', 'AUTH_SESSION_ID_NOT_FOUND')
    
    username = session_dict[session_id]['username']
    users_dict[username]['sessions'].remove(session_id)
    del session_dict[session_id]
    users_dict[username]['session_count'] -= 1

@api_external_function(plugin)
def e_delete_sessions_from_user(username):
    
    i = 0;
    while i < len(users_dict[username]['sessions']):
        
        key = users_dict[username]['sessions'][i]
        del session_dict[key]
        del users_dict[username]['sessions'][i]
        users_dict[username]['session_count'] -= 1
        continue
        
        i += 1

def i_get_db_user(username):
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    with db:
        sql = """
            SELECT * FROM """ +db_prefix +"""user WHERE name = %s;
        """
        
        try:
            dbc.execute(sql, [username])
        except MySQLdb.IntegrityError as e:
            api_log().error("i_get_db_user: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')
        
        result = dbc.fetchone()
        if result == None:
            raise WebRequestException(400, 'error', 'AUTH_USER_NOT_FOUND')
        
        return result

def i_list_db_user():
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    with db:
        sql = """
            SELECT * FROM """ +db_prefix +"""user;
        """
        
        try:
            dbc.execute(sql)
            
        except MySQLdb.IntegrityError as e:
            api_log().error("i_list_db_user: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')
        
        return dbc.fetchall()

def i_local_get_user(username):
    if not username in users_dict:
        raise WebRequestException(400, 'error', 'AUTH_USER_NOT_FOUND')
    
    return_json = dict(users_dict[username])
    return_json['username'] = username
    del return_json['keys']
    del return_json['sessions']
    del return_json['h_password']
        
    return return_json

def i_list_local_users():
    return_json = []
    for key in users_dict:
        i_entry = dict(users_dict[key])
        i_entry['username'] = key
        del i_entry['keys']
        del i_entry['sessions']
        del i_entry['h_password']
        
        return_json.append(i_entry)
        
    return return_json

def i_get_db_roles_from_user(username):
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    with db:
        sql = """
            SELECT """ +db_prefix +"""role.name
                FROM """ +db_prefix +"""role_member
                JOIN """ +db_prefix +"""role ON role_id = """ +db_prefix +"""role.id
                JOIN """ +db_prefix +"""user ON user_id = """ +db_prefix +"""user.id
                WHERE """ +db_prefix +"""user.name = %s;
        """
        
        try:
            dbc.execute(sql, [username])
            
        except MySQLdb.IntegrityError as e:
            api_log().error("i_get_db_roles_from_user: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')
        
        return dbc.fetchall()

@api_external_function(plugin)
def e_get_user(username):
    if write_trough_cache_enabled:
        return i_local_get_user(username)
    
    else:
        result = i_get_db_user(username)
        
        return_json = {}
        return_json['id'] = result[0]
        return_json['username'] = result[1]
        return_json['roles'] = []
        
        for role in i_get_db_roles_from_user(username):
            return_json['roles'].append(role[0])
        
        return return_json

@api_external_function(plugin)
def e_get_db_user_by_id(user_id):
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    with db:
        sql = """
            SELECT * FROM """ +db_prefix +"""user WHERE id = %s;
        """
        
        try:
            dbc.execute(sql, [user_id])
        except MySQLdb.IntegrityError as e:
            api_log().error("e_get_db_user_by_id: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')
        
        result = dbc.fetchone()
        if result == None:
            raise WebRequestException(400, 'error', 'AUTH_USER_NOT_FOUND')
        
        return result

@api_external_function(plugin)
def e_list_users():
    if write_trough_cache_enabled:
        return i_list_local_users()
    
    else:
        return_json = []
        for row in i_list_db_user():
            i_entry = {
                'id': row[0],
                'username': row[1],
                'roles': []
            }
            
            for role in i_get_db_roles_from_user(row[1]):
                i_entry['roles'].append(role[0])
            
            return_json.append(i_entry)
        
        return return_json

@api_external_function(plugin)
def e_create_user(username, data):

    if username == 'list':
        raise WebRequestException(400, 'error', 'AUTH_EXECUTION_DENIED')

    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    if not 'password' in data:
        raise WebRequestException(400, 'error', 'AUTH_PASSWORD_MISSING')
    
    h_password = e_hash_password(username, data['password'])
    
    with db:
        sql = """
            INSERT INTO """ +db_prefix +"""user (
                    name, password
                )
                VALUES (%s, %s);
        """
        
        try:
            dbc.execute(sql,[username, h_password])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            raise WebRequestException(400, 'error', 'AUTH_USER_EXISTS')
    
    user_id = i_get_db_user(username)[0]
    
    if write_trough_cache_enabled:
        users_dict[username] = {
            'id': user_id,
            'h_password': h_password,
            'keys': [],
            'sessions': [],
            'roles': [],
            'session_count': 0
        }
    
    e_add_member_to_role('default', username)
    
    if 'roles' in data:
        for role in data['roles']:
            e_add_member_to_role(role, username)
    
    return user_id

@api_external_function(plugin)
def e_edit_user(username, data):

    if username == 'list':
        raise WebRequestException(400, 'error', 'AUTH_EXECUTION_DENIED')

    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    if not 'password' in data:
        raise WebRequestException(400, 'error', 'AUTH_PASSWORD_MISSING')
    
    h_password = e_hash_password(username, data['password'])
    
    with db:
        sql = """
            UPDATE """ +db_prefix +"""user
                SET password = %s
                WHERE name = %s;
        """
        
        try:
            dbc.execute(sql,[h_password, username])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            api_log().error("e_edit_user: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')
    
    if write_trough_cache_enabled:
        users_dict[username]['h_password'] = h_password

@api_external_function(plugin)
def e_delete_user(username):

    if username in ['admin', 'anonymous', 'list']:
        raise WebRequestException(400, 'error', 'AUTH_EXECUTION_DENIED')

    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    if write_trough_cache_enabled and not username in users_dict:
        raise WebRequestException(400, 'error', 'AUTH_USER_NOT_FOUND')
    
    with db:
        sql = """
            DELETE FROM """ +db_prefix +"""user 
                WHERE name = %s;
        """
        
        try:
            dbc.execute(sql,[username])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            api_log().error("e_delete_user: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')
    
    if write_trough_cache_enabled:
        for i in range(len(users_dict[username]['keys'])):
            key = users_dict[username]['keys'][i]
            del user_token_dict[key]
            del users_dict[username]['keys'][i]
        
        for i in range(len(users_dict[username]['sessions'])):
            key = users_dict[username]['sessions'][i]
            del session_dict[key]
            del users_dict[username]['sessions'][i]
        
        del users_dict[username]

def i_get_db_user_token(username, token_name):
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    if write_trough_cache_enabled:
        if not username in users_dict:
            raise WebRequestException(400, 'error', 'AUTH_USER_NOT_FOUND')
        
        user_id = users_dict[username]['id']
    
    else:
        user_id = i_get_db_user(username)[0]
    
    with db:
        sql = """
            SELECT * FROM """ +db_prefix +"""user_token WHERE user_id = %s AND token_name = %s;
        """
        
        try:
            dbc.execute(sql, [user_id, token_name])
            
        except MySQLdb.IntegrityError as e:
            api_log().error("i_get_db_user_token: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')
        
        result = dbc.fetchone()
        if result == None:
            raise WebRequestException(400, 'error', 'AUTH_TOKEN_NOT_FOUND')
    
        return result

def i_list_db_user_token(username):
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    with db:
        sql = """
            SELECT """ +db_prefix +"""user_token.id, name, token_name, user_key, data
                FROM """ +db_prefix +"""user_token
                JOIN """ +db_prefix +"""user
                ON user_id = """ +db_prefix +"""user.id
                WHERE name = %s;
        """
        
        try:
            dbc.execute(sql, [username])
            
        except MySQLdb.IntegrityError as e:
            api_log().error("i_list_db_user_token: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')
        
        return dbc.fetchall()

def i_list_db_token():
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    with db:
        sql = """
            SELECT """ +db_prefix +"""user_token.id, name, token_name, user_key, data
                FROM """ +db_prefix +"""user_token
                JOIN """ +db_prefix +"""user
                ON user_id = """ +db_prefix +"""user.id;
        """
        
        try:
            dbc.execute(sql)
            
        except MySQLdb.IntegrityError as e:
            api_log().error("i_list_db_token: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')
        
        return dbc.fetchall()

def i_get_local_user_token(username, token_name):
    for key in users_dict[username]['keys']:
        if not 'token_name' in user_token_dict[key]:
            continue
        
        if user_token_dict[key]['token_name'] == token_name:
            i_entry = copy.deepcopy(user_token_dict[key])
            return i_entry
    
    raise WebRequestException(400, 'error', 'AUTH_TOKEN_NOT_FOUND')

def i_list_local_user_token(username):
    return_json = []
    for key in users_dict[username]['keys']:
        i_entry = copy.deepcopy(user_token_dict[key])
        return_json.append(i_entry)
    
    return return_json

@api_external_function(plugin)
def e_get_user_token(username, token_name):
    if write_trough_cache_enabled:
        return i_get_local_user_token(username, token_name)
    
    else:
        token = i_get_db_user_token(username, token_name)
        
        return_json = {}
        return_json['token_name'] = token_name
        return_json['username'] = username
        return_json['ruleset'] = json.loads(token[4])
        
        return return_json

@api_external_function(plugin)
def e_list_user_token(username):
    if write_trough_cache_enabled:
        return i_list_local_user_token(username)
    
    else:
        return_json = []
        for token in i_list_db_user_token(username):
            i_entry = {}
            
            i_entry['token_name'] = token[1]
            i_entry['username'] = username
            i_entry['ruleset'] = json.loads(token[4])
            
            return_json.append(i_entry)
        
        return return_json

@api_external_function(plugin)
def e_create_user_token(username, token_name, ruleset = {}):

    if token_name == 'list':
        raise WebRequestException(400, 'error', 'AUTH_EXECUTION_DENIED')

    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    if write_trough_cache_enabled:
        if not username in users_dict:
            raise WebRequestException(400, 'error', 'AUTH_USER_NOT_FOUND')
        
        user_id = users_dict[username]['id']
    
    else:
        user_id = i_get_db_user(username)[0]
    
    if ruleset != {}:
        user_ruleset = e_get_permissions_of_user(username)
        try: del ruleset['inherit']
        except KeyError: pass

        if not 'permissions' in ruleset:
            ruleset['permissions'] = []
        
        intersected = e_intersect_subset(user_ruleset, ruleset)
        if intersected != ruleset:
            raise WebRequestException(401, 'unauthorized', 'AUTH_PERMISSIONS_DENIED')

    else:
        ruleset = e_get_permissions_of_user(username)

    new_token = e_generate_random_string(cookie_length)
    h_new_token = e_hash_password('', new_token)
    
    with db:
        sql = """
            INSERT INTO """ +db_prefix +"""user_token (
                    token_name, user_key, user_id, data
                )
                VALUES (%s, %s, %s, %s);
        """
        
        try:
            dbc.execute(sql,[
                token_name,
                h_new_token,
                user_id,
                json.dumps(ruleset)
            ])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            raise WebRequestException(400, 'error', 'AUTH_TOKEN_EXISTS')
    
    if write_trough_cache_enabled:
        user_token_dict[h_new_token] = {
            'username': current_user,
            'token_name': token_name,
            'ruleset': ruleset
        }
        users_dict[current_user]['keys'].append(h_new_token)

    i_apply_ruleset(h_new_token, is_token=True)
    
    return new_token

@api_external_function(plugin)
def e_edit_user_token(username, token_name, ruleset):

    if token_name == 'list':
        raise WebRequestException(400, 'error', 'AUTH_EXECUTION_DENIED')

    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    if write_trough_cache_enabled:
        if not username in users_dict:
            raise WebRequestException(400, 'error', 'AUTH_USER_NOT_FOUND')
        
        user_id = users_dict[username]['id']
    
    else:
        user_id = i_get_db_user(username)[0]
    
    if ruleset != {}:
        user_ruleset = e_get_permissions_of_user(username)
        try: del ruleset['inherit']
        except KeyError: pass

        if not 'permissions' in ruleset:
            ruleset['permissions'] = []
        
        intersected = e_intersect_subset(user_ruleset, ruleset)
        if intersected != ruleset:
            raise WebRequestException(401, 'unauthorized', 'AUTH_PERMISSIONS_DENIED')

    else:
        ruleset = e_get_permissions_of_user(username)

    i_get_db_user_token(username, token_name)
    
    with db:
        sql = """
            UPDATE """ +db_prefix +"""user_token
                SET data = %s
                WHERE user_id = %s AND token_name = %s;
        """
            
        try:
            dbc.execute(sql, [json.dumps(ruleset), user_id, token_name])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            api_log().error("e_delete_user_token: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')

    if write_trough_cache_enabled:
        for i, h_token in enumerate(users_dict[username]['keys']):
            if user_token_dict[h_token]['token_name'] == token_name:
                user_token_dict[h_token]['ruleset'] = ruleset
                i_apply_ruleset(h_token, is_token=True)
                break

@api_external_function(plugin)
def e_delete_user_token(username, token_name):

    if token_name == 'list':
        raise WebRequestException(400, 'error', 'AUTH_EXECUTION_DENIED')

    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    if write_trough_cache_enabled:
        if not username in users_dict:
            raise WebRequestException(400, 'error', 'AUTH_USER_NOT_FOUND')
        
        
        user_id = users_dict[username]['id']
    
    else:
        user_id = i_get_db_user(username)[0]

    i_get_db_user_token(username, token_name)
    
    with db:
        sql = """
            DELETE FROM """ +db_prefix +"""user_token 
                WHERE user_id = %s AND token_name = %s;
        """
            
        try:
            dbc.execute(sql,[user_id ,token_name])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            api_log().error("e_delete_user_token: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')


    if write_trough_cache_enabled:
        for i in range(len(users_dict[username]['keys'])):
            key = users_dict[username]['keys'][i]
            if user_token_dict[key]['token_name'] == token_name:
                h_token = key
                i_apply_ruleset(h_token, is_token=True, delete=True)

                del user_token_dict[key]
                del users_dict[username]['keys'][i]
                break

def i_get_db_role(role_name):
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    with db:
        sql = """
            SELECT * FROM """ +db_prefix +"""role WHERE name = %s;
        """
        
        try:
            dbc.execute(sql, [role_name])
            
        except MySQLdb.IntegrityError as e:
            api_log().error("i_get_db_role: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')
        
        result = dbc.fetchone()
        if result == None:
            raise WebRequestException(400, 'error', 'AUTH_ROLE_NOT_FOUND')
        
        return result

def i_list_db_roles():
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    with db:
        sql = """
            SELECT * FROM """ +db_prefix +"""role;
        """
        
        try:
            dbc.execute(sql)
        
        except MySQLdb.IntegrityError as e:
            api_log().error("i_list_db_roles: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501,'error','GENERAL_SQL_ERROR')
        
        return dbc.fetchall()

def i_get_local_role(role_name):
    if not role_name in roles_dict:
        raise WebRequestException(400, 'error', 'AUTH_ROLE_NOT_FOUND')

    return dict(roles_dict[role_name])

def e_list_local_roles():
    return_json = []
    
    for key in roles_dict:
        i_entry = dict(roles_dict[key])
        i_entry['role_name'] = key
        return_json.append(i_entry)
    
    return return_json

@api_external_function(plugin)
def e_get_role(role_name):
    if write_trough_cache_enabled:
        return i_get_local_role(role_name)
    
    else:
        result = i_get_db_role(role_name)
        
        return_json = {}
        return_json['id'] = result[0]
        return_json['ruleset'] = json.loads(result[2])
        
        return return_json

@api_external_function(plugin)
def e_list_roles():
    if write_trough_cache_enabled:
        return e_list_local_roles()
    
    else:
        return_json = []
        for role in i_list_db_roles():
            i_entry = {}
            
            i_entry['id'] = role[0]
            i_entry['role_name'] = role[1]
            i_entry['ruleset'] = json.loads(role[2])
            
            return_json.append(i_entry)
        
        return return_json

@api_external_function(plugin)
def e_create_role(role_name, ruleset):

    if role_name == 'list':
        raise WebRequestException(400, 'error', 'AUTH_EXECUTION_DENIED')

    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    if not 'inherit' in ruleset:
        ruleset['inherit'] = []
    
    if not 'permissions' in ruleset:
        ruleset['permissions'] = []
    
    with db:
        sql = """
            INSERT INTO """ +db_prefix +"""role (
                    name, data
                )
                VALUES (%s, %s);
        """
        
        try:
            dbc.execute(sql,[role_name, json.dumps(ruleset)])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            raise WebRequestException(400, 'error', 'AUTH_ROLE_EXISTS')
    
    role_id = i_get_db_role(role_name)[0]
    
    if write_trough_cache_enabled:
        roles_dict[role_name] = {
            'id': role_id,
            'ruleset': ruleset
        }
        
        i_apply_ruleset(role_name)
    
    return role_id

def i_edit_db_role(role_name, ruleset):
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    with db:
        sql = """
            UPDATE """ +db_prefix +"""role
                SET data = %s
                WHERE name = %s;
        """
        
        try:
            dbc.execute(sql,[json.dumps(ruleset), role_name])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            api_log().error("i_edit_db_role: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')

@api_external_function(plugin)
def e_edit_role(role_name, ruleset):

    if not 'inherit' in ruleset:
        ruleset['inherit'] = []
    
    if not 'permissions' in ruleset:
        ruleset['permissions'] = []

    if role_name == 'list':
        raise WebRequestException(400, 'error', 'AUTH_EXECUTION_DENIED')

    if write_trough_cache_enabled:
        if not role_name in roles_dict:
            raise WebRequestException(400, 'error', 'AUTH_ROLE_NOT_FOUND')
        
        roles_dict[role_name]['ruleset'] = ruleset
    
    else:
        i_get_db_role(role_name)
    
    i_edit_db_role(role_name, ruleset)

    if write_trough_cache_enabled:
        i_apply_ruleset(role_name)

@api_external_function(plugin)
def e_delete_db_role(role_name):
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    with db:
        sql = """
            DELETE FROM """ +db_prefix +"""role 
                WHERE name = %s;
        """
        
        try:
            dbc.execute(sql,[role_name])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            api_log().error("e_delete_db_role: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')

@api_external_function(plugin)
def e_delete_role(role_name):
    
    if role_name in ['admin', 'anonymous', 'default', 'list']:
        raise WebRequestException(400, 'error', 'AUTH_EXECUTION_DENIED')

    if write_trough_cache_enabled:
        if not role_name in roles_dict:
            raise WebRequestException(400, 'error', 'AUTH_ROLE_NOT_FOUND')

    else:
        i_get_db_role(role_name)
        
    e_delete_db_role(role_name)
    
    if write_trough_cache_enabled:
        for user in users_dict:
            try: users_dict[user]['roles'].remove(role_name)
            except: pass
        
        del roles_dict[role_name]
        
        i_apply_ruleset(role_name, delete=True)

@api_external_function(plugin)
def e_add_member_to_role(role_name, username):
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    if write_trough_cache_enabled:
        if not role_name in roles_dict:
            raise WebRequestException(400, 'error', 'AUTH_ROLE_NOT_FOUND')
        
        if not username in users_dict:
            raise WebRequestException(400, 'error', 'AUTH_USER_NOT_FOUND')
        
        if role_name in users_dict[username]['roles']:
            raise WebRequestException(400, 'error', 'AUTH_USER_IS_MEMBER')
        
        role_id = roles_dict[role_name]['id']
        user_id = users_dict[username]['id']
    
    else:
        role_id = i_get_db_role(role_name)[0]
        user_id = i_get_db_user(username)[0]
    
    with db:
        sql = """
            INSERT INTO """ +db_prefix +"""role_member (
                    role_id, user_id
                )
                VALUES (%s, %s);
        """
            
        try:
            dbc.execute(sql,[role_id, user_id])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            raise WebRequestException(400, 'error', 'AUTH_USER_IS_MEMBER')
    
    if write_trough_cache_enabled:
        users_dict[username]['roles'].append(role_name)

@api_external_function(plugin)
def e_remove_member_from_role(role_name, username):
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    
    if write_trough_cache_enabled:
        if not role_name in roles_dict:
            raise WebRequestException(400, 'error', 'AUTH_ROLE_NOT_FOUND')
        
        if not username in users_dict:
            raise WebRequestException(400, 'error', 'AUTH_USER_NOT_FOUND')
        
        if not role_name in users_dict[username]['roles']:
            raise WebRequestException(400, 'error', 'AUTH_USER_IS_NOT_MEMBER')
    
        role_id = roles_dict[role_name]['id']
        user_id = users_dict[username]['id']
        
    else:
        role_id = i_get_db_role(role_name)[0]
        
        user = e_get_user(username)
        user_id = user['id']
        
        if not role_name in user['roles']:
            raise WebRequestException(400, 'error', 'AUTH_USER_IS_NOT_MEMBER')
    
    dbc = db.cursor()
    sql = """
        DELETE FROM """ +db_prefix +"""role_member 
            WHERE role_id = %s AND user_id = %s;
    """
        
    try:
        dbc.execute(sql,[role_id, user_id])
        db.commit()
        
    except MySQLdb.IntegrityError as e:
        api_log().error("e_remove_member_from_role: {}".format(api_tr('GENERAL_SQL_ERROR')))
        raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')
    
    dbc.close()
    
    if write_trough_cache_enabled:
        users_dict[username]['roles'].remove(role_name)

def i_apply_ruleset(role_name, is_token=False, delete=False, no_change=False):
    
    if is_token:
        h_token = role_name

        token = user_token_dict[h_token]
        #p_name = token['username'] +":" +token['token_name']
        p_name = h_token
        ruleset = token['ruleset']
        r_type = 'tokens'

    else:
        p_name = role_name
        ruleset = roles_dict[role_name]['ruleset']
        r_type = 'roles'

    for plugin_name in action_tree:
        for action_name in action_tree[plugin_name]:
            try: action_tree[plugin_name][action_name][r_type].remove(p_name)
            except: pass

    if delete:
        return
   
    for p_rule in ruleset['permissions']:
        rule_r = p_rule.split('.')
        
        if rule_r[0] == '*':
            if len(rule_r) > 1:
                api_log().warning(api_tr('AUTH_SYNTAX_ERROR_1').format(p_name, p_rule))
                continue
            
            for plugin_name in action_tree:
                for action_name in action_tree[plugin_name]:
                    role_list = action_tree[plugin_name][action_name][r_type]
                    
                    if role_name in role_list:
                        continue
                    
                    role_list.append(p_name)
        
        elif len(rule_r) == 1:
            if not rule_r[0] in action_tree:
                api_log().warning(api_tr('AUTH_SYNTAX_ERROR_2').format(p_name, rule_r[0]))
                continue
            
            for action_name in action_tree[rule_r[0]]:
                role_list = action_tree[rule_r[0]][action_name][r_type]
                
                if role_name in role_list:
                    continue
                
                role_list.append(p_name)
                
        elif len(rule_r) == 2:
            if not rule_r[0] in action_tree:
                api_log().warning(api_tr('AUTH_SYNTAX_ERROR_2').format(p_name, rule_r[0]))
                continue
            
            if not rule_r[1] in action_tree[rule_r[0]]:
                api_log().warning(api_tr('AUTH_SYNTAX_ERROR_3').format(p_name, rule_r[1]))
                continue
            
            role_list = action_tree[rule_r[0]][rule_r[1]][r_type]
                
            if role_name in role_list:
                continue
                
            role_list.append(p_name)
            
        else:
            api_log().warning(api_tr('AUTH_SYNTAX_ERROR_1').format(p_name, p_rule))
            continue

    if is_token == False and no_change == False:
        for username, user_data in users_dict.items():
            ruleset = e_get_permissions_of_user(username)
            
            for h_token in user_data['keys']:
                subset = user_token_dict[h_token]['ruleset']
                intersection = e_intersect_subset(ruleset, subset)

                if subset != intersection:
                    e_edit_user_token(username, user_token_dict[h_token]['token_name'], intersection)

@api_event(plugin, 'check')
def check():
    
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    with db:
        # Checks if all tables exist.
        result = 1
        for table in used_tables:
            sql = "SHOW TABLES LIKE '" +db_prefix +table +"'"
            result *= dbc.execute(sql)
    
    if(result == 0):
        return 0
    
    return 1

@api_event(plugin, 'load')
def load():
    global write_trough_cache_enabled
    global bf_basic_auth_delay
    global bf_temporary_ban_enabled
    
    e_add_subset_intersection_handler(i_subset_permission_handler)
    e_add_permission_reduce_handler(i_permission_reduce_handler)

    for plugin_name in action_tree:
        for action_name in action_tree[plugin_name]:
            action_tree[plugin_name][action_name]['roles'] = []
            action_tree[plugin_name][action_name]['tokens'] = []

    for row in i_list_db_user():
        users_dict[row[1]] = {
            'id': row[0],
            'h_password': row[2],
            'keys': [],
            'sessions': [],
            'roles': [],
            'session_count': 0
        }
        
        for role in i_get_db_roles_from_user(row[1]):
            users_dict[row[1]]['roles'].append(role[0])
    
    for row in i_list_db_token():
        user_token_dict[row[3]] = {
            'username': row[1],
            'token_name': row[2],
            'ruleset': json.loads(row[4])
        }
        users_dict[row[1]]['keys'].append(row[3])
        
    for row in i_list_db_roles():
        roles_dict[row[1]] = {
            'id': row[0],
            'ruleset': json.loads(row[2])
        }
    
    for h_token in user_token_dict:
        i_apply_ruleset(h_token, is_token=True)
    
    for role_name in roles_dict:
        i_apply_ruleset(role_name, no_change=True)

    bf_basic_auth_delay = api_config()[plugin.name]['bf_basic_auth_delay']
    bf_temporary_ban_enabled = api_config()[plugin.name]['bf_temporary_ban_enabled']
    
    write_trough_cache_enabled = True
    return 1

@api_event(plugin, 'install')
def install():
    
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    api_log().info("Create new Tables...")
    
    with db:
        sql = """
            CREATE TABLE """ +db_prefix +"""user (
                id INT NOT NULL AUTO_INCREMENT,
                name VARCHAR(32) NOT NULL,
                password VARCHAR(64) NOT NULL,
                PRIMARY KEY( id ),
                UNIQUE ( name )
            ) ENGINE = InnoDB;
            """
        dbc.execute(sql)
        api_log().debug("Table '" +db_prefix +"user' created.")

        sql = """
            CREATE TABLE """ +db_prefix +"""user_token (
                id INT NOT NULL AUTO_INCREMENT,
                token_name VARCHAR(32) NOT NULL,
                user_key VARCHAR(64) NOT NULL,
                user_id INT NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (id),
                UNIQUE (token_name, user_id)
            ) ENGINE = InnoDB;
            """
        dbc.execute(sql)
        api_log().debug("Table '" +db_prefix +"user_token' created.")
        
        sql = """
            CREATE TABLE """ +db_prefix +"""role (
                id INT NOT NULL AUTO_INCREMENT,
                name VARCHAR(32) NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (id),
                UNIQUE (name)
            ) ENGINE = InnoDB;
            """
        dbc.execute(sql)
        api_log().debug("Table '" +db_prefix +"role' created.")
        
        sql = """
            CREATE TABLE """ +db_prefix +"""role_member (
                id INT NOT NULL AUTO_INCREMENT,
                role_id INT NOT NULL,
                user_id INT NOT NULL,
                PRIMARY KEY (id),
                UNIQUE (role_id, user_id)
            ) ENGINE = InnoDB;
            """
        dbc.execute(sql)
        api_log().debug("Table '" +db_prefix +"role_member' created.")
        
        sql = """
            ALTER TABLE """ +db_prefix +"""user_token
                ADD CONSTRAINT """ +db_prefix +"""user_token_to_user
                FOREIGN KEY ( user_id )
                REFERENCES """ +db_prefix +"""user ( id )
                ON DELETE CASCADE
                ON UPDATE CASCADE;
            """
        dbc.execute(sql)
        
        sql = """
            ALTER TABLE """ +db_prefix +"""role_member
                ADD CONSTRAINT """ +db_prefix +"""role_member_to_role
                FOREIGN KEY (role_id)
                REFERENCES """ +db_prefix +"""role(id)
                ON DELETE CASCADE
                ON UPDATE CASCADE;
            """
        dbc.execute(sql)
        
        sql = """
            ALTER TABLE """ +db_prefix +"""role_member
                ADD CONSTRAINT """ +db_prefix +"""role_member_to_user
                FOREIGN KEY (user_id)
                REFERENCES """ +db_prefix +"""user(id)
                ON DELETE CASCADE
                ON UPDATE CASCADE;
            """
        dbc.execute(sql)
        api_log().debug("Constraints created.")
    
    e_create_role('admin', {
        "permissions":  [
            "*"
        ]
    })
    
    e_create_role('auth_default', {
        "permissions":  [
            "auth.list_sessions",
            "auth.create_session",
            "auth.delete_session",
            "auth.delete_all_sessions",
            
            "auth.get_user_token",
            "auth.list_user_tokens",
            "auth.create_user_token",
            "auth.edit_user_token",
            "auth.delete_user_token",
            
            "auth.change_password",
            "auth.get_permissions",
            "auth.get_current_user"
        ]
    })
    
    e_create_role('anonymous', {
        "permissions":  []
    })
    
    e_create_role('default', {
        "inherit":  [
            "anonymous",
            "auth_default"
        ],
        "permissions": []
    })
    
    if api_config()['auth']['first_user_password'] != "":
        password = api_config()['auth']['first_user_password']
    else:
        password = getpass.getpass('Enter new admin password: ')

    e_create_user('admin', {
        'password': password
    })
    
    e_create_user('anonymous', {
        'password': e_generate_random_string(cookie_length)
    })
    
    e_remove_member_from_role('default', 'admin')
    e_add_member_to_role('admin', 'admin')
    
    e_remove_member_from_role('default', 'anonymous')
    e_add_member_to_role('anonymous', 'anonymous')
    
    api_log().debug("Initial data created.")
    return 1

@api_event(plugin, 'uninstall')
def uninstall():
    
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    api_log().info("Delete old Tables...")
    
    for table in reversed(used_tables):
        sql = "DROP TABLE " +db_prefix +table +";"
        
        try: dbc.execute(sql)
        except MySQLdb.Error:
            continue
            
        api_log().debug("Table '" +db_prefix +table +"' deleted.")
    
    dbc.close()
    return 1

def ir_check_permissions(role_name, target_list, depth = 0):
    
    if depth > len(roles_dict):
        raise WebRequestException(400, 'error', 'GENERAL_RECURSIVE_LOOP')
    
    if role_name in target_list:
        return 1
    
    if 'inherit' in roles_dict[role_name]['ruleset']:
        parents = roles_dict[role_name]['ruleset']['inherit']
        for parent in parents:
            if ir_check_permissions(parent, target_list, depth +1):
                return 1
        
    return 0

def unauthorized_error(error_code, error_name, error_message, remote_ip = "N/A"):
    
    return_json = {}
    if bf_temporary_ban_enabled:
        if not remote_ip in bf_blacklist:
            
            new_entry = {}
            new_entry['failed_attempts'] = 1
            new_entry['banned_until'] = time.time() + 1
            
            bf_blacklist[remote_ip] = new_entry
        
        else:
            bf_blacklist[remote_ip]['failed_attempts'] += 1
            
            ban_time = 2**bf_blacklist[remote_ip]['failed_attempts']
            bf_blacklist[remote_ip]['banned_until'] = time.time() +ban_time
            return_json['ban_time'] = ban_time
    
    raise WebRequestException(error_code, error_name, error_message, return_json)

def i_reset_ban_time(remote_ip = "N/A"):
    
    if bf_temporary_ban_enabled:
        try: del bf_blacklist[remote_ip]
        except: pass

def i_log_access(message):
    if log.loglevel >= 5:
        log.access('{} {}'.format(api_environment_variables()['transaction_id'], message))

def i_is_permitted(username, action):

    for role_name in users_dict[username]['roles']:
        if ir_check_permissions(role_name, action['roles']):
            i_log_access('authorized as {} via {}'.format(current_user, auth_type))
            return 1
    
    raise WebRequestException(401, 'unauthorized', 'AUTH_PERMISSIONS_DENIED')

def i_is_token_permitted(h_token, action):

    if h_token in action['tokens']:
        i_log_access('authorized as {} via token {}'.format(current_user, user_token_dict[h_token]['token_name']))
        return 1
    
    raise WebRequestException(401, 'unauthorized', 'AUTH_PERMISSIONS_DENIED')

@api_event(plugin, 'global_preexecution_hook')
def global_preexecution_hook(reqHandler, action):
    global current_user
    global auth_type
    global current_token
    
    remote_ip = i_get_client_ip(reqHandler)
    if bf_temporary_ban_enabled:
        if remote_ip in bf_blacklist and bf_blacklist[remote_ip]['banned_until'] > time.time():
            remaining_time = math.ceil(bf_blacklist[remote_ip]['banned_until'] - time.time())
            raise WebRequestException(401, 'unauthorized', 'AUTH_TOO_MANY_LOGIN_FAILS', {'remaining_time': remaining_time})
    
    auth_header = reqHandler.request.headers.get('Authorization', None)
    if auth_header is not None:
        r_auth_header = auth_header.split(' ')
        
        if(r_auth_header[0] == "Basic"):
            time.sleep(bf_basic_auth_delay)
            
            credentials = base64.b64decode(r_auth_header[1]).decode("utf-8").split(':')
            
            if credentials[0] in users_dict:
                if (e_hash_password(credentials[0], credentials[1]) == users_dict[credentials[0]]['h_password']):
                
                    current_user = credentials[0]
                    auth_type = "basic"
                    if i_is_permitted(current_user, action):
                        i_reset_ban_time(remote_ip)
                        return
                
            unauthorized_error(401, 'unauthorized', 'AUTH_WRONG_PASSWORD_OR_USERNAME', remote_ip)
        
        elif(r_auth_header[0] == "Bearer"):
            h_token = e_hash_password('', r_auth_header[1])
            
            if h_token in user_token_dict:
                current_user = user_token_dict[h_token]['username']
                auth_type = "token"
                current_token = h_token

                if i_is_token_permitted(h_token, action):
                    i_reset_ban_time(remote_ip)
                    return
            
            else:
                unauthorized_error(401, 'unauthorized', 'AUTH_INVALID_USER_TOKEN', remote_ip)

    if action['name'] == "auth.create_session":
        raw_body = reqHandler.request.body.decode('utf8')
        try:
            if raw_body == "":
                body = {}
            else:
                body = tornado.escape.json_decode(raw_body)

        except ValueError as e:
            raise WebRequestException(400, 'error', 'GENERAL_MALFORMED_JSON')

        if 'username' in body and 'password' in body:
            time.sleep(bf_basic_auth_delay)
            if body['username'] in users_dict and e_hash_password(body['username'], body['password']) == users_dict[body['username']]['h_password']:

                current_user = body['username']
                auth_type = "basic"
                if i_is_permitted(current_user, action):
                    i_reset_ban_time(remote_ip)
                    return
            unauthorized_error(401, 'unauthorized', 'AUTH_WRONG_PASSWORD_OR_USERNAME', remote_ip)

        raise WebRequestException(401, 'unauthorized', 'AUTH_PERMISSIONS_DENIED')
     
    session_id = reqHandler.get_cookie("session_id")
    if session_id:
        if session_id in session_dict:
            
            if 'last_csrf_token' in session_dict[session_id]:
                csrf_token = reqHandler.request.headers.get('X-CSRF-TOKEN', None)
                if csrf_token != session_dict[session_id]['last_csrf_token']:
                    unauthorized_error(401, 'unauthorized', 'AUTH_INVALID_CSRF_TOKEN', remote_ip)
                
                csrf_token = e_generate_random_string(cookie_length)
                session_dict[session_id]['last_csrf_token'] = csrf_token
                reqHandler.add_header('X-CSRF-TOKEN', csrf_token)
            
            current_user = session_dict[session_id]['username']
            auth_type = "session"
            
            if time.time() > session_dict[session_id]['expiration_time']:
                i_clean_expired_sessions()
                raise WebRequestException(401, 'unauthorized', 'AUTH_SESSION_EXPIRED')
            
            if i_is_permitted(current_user, action):
                return

    current_user = "anonymous"
    auth_type = "none"
    if i_is_permitted(current_user, action):
        return

    raise WebRequestException(401, 'unauthorized', 'AUTH_PERMISSIONS_DENIED')

#@api_action(plugin, {
#    'path': 'debug',
#    'method': 'POST',
#    'f_name': {
#        'EN': 'Debug 1'
#    },
#
#    'f_description': {
#        'EN': 'Dumps the write-through-cache.',
#        'DE': 'Gibt den write-through-cache aus.'
#    }
#})
#def auth_debug1(reqHandler, p, args, body):
#    return {
#        'users_dict': users_dict,
#        'user_token_dict': user_token_dict,
#        'session_dict': session_dict,
#        'roles_dict': roles_dict,
#        'bf_blacklist': bf_blacklist,
#        'session_counter': session_counter
#    }
#
#@api_action(plugin, {
#    'path': 'debug2',
#    'method': 'POST'
#})
#def auth_debug2(reqHandler, p, args, body):
#    
#    plist = {} 
#    for i_p in api_plugins():
#        i_pe = api_plugins()[i_p]
#        i_actions = {} 
#     
#        for i_action in i_pe.actions:
#            i_ae = {} 
#            i_ae['roles'] = i_action['roles']
#            i_ae['tokens'] = i_action['tokens']
#     
#            i_actions[i_action['name']] = i_ae 
#     
#        plist[i_pe.name] = {} 
#        plist[i_pe.name]['actions'] = i_actions
#        plist[i_pe.name]['essential'] = i_pe.essential
#    
#    return {
#        'data': plist
#    }

@api_action(plugin, {
    'path': 'whoami',
    'method': 'GET',
    'f_name': {
        'EN': 'Get current user',
        'DE': 'Zeige momentaten Benutzer'
    },

    'f_description': {
        'EN': 'Returns the current user.',
        'DE': 'Gibt Informationen über den aktuellen Benutzer zurück.'
    }
})
def get_current_user(reqHandler, p, args, body):
    return {
        'data': e_get_current_user_info()
    }

@api_action(plugin, {
    'path': 'permissions',
    'method': 'GET',
    'f_name': {
        'EN': 'Get permissions',
        'DE': 'Zeige Berechtigungen'
    },

    'f_description': {
        'EN': 'Returns a merged list of all permissions.',
        'DE': 'Gibt eine zusammengesetzte Liste mit allen Berechtigungen zurück.'
    }
})
def get_permissions(reqHandler, p, args, body):
    return {
        'data': e_get_permissions()
    }

@api_action(plugin, {
    'path': 'session/list',
    'method': 'GET',
    'f_name': {
        'EN': 'List sessions',
        'DE': 'Sessions auflisten'
    },

    'f_description': {
        'EN': 'Lists all available sessions of the current user.',
        'DE': 'Listet alle offenen Sessions des aktuellen Benutzers auf.'
    }
})
def list_sessions(reqHandler, p, args, body):
    return {
        'data': e_list_sessions(current_user)
    }

@api_action(plugin, {
    'path': 'session',
    'method': 'POST',
    'body': {
        'csrf_token': {
            'type': bool,
            'default': False,
            'f_name': {
                'EN': "CSRF-token",
                'DE': "CSRF-Token"
            }
        }
    },
    'f_name': {
        'EN': 'Create session',
        'DE': 'Session erstellen'
    },

    'f_description': {
        'EN': 'Sets a cookie and creates a session.',
        'DE': 'Setzt einen Cookie und öffnet eine Session.'
    }
})
def create_session(reqHandler, p, args, body):
    e_create_session(reqHandler, current_user, body)
    return {}

@api_action(plugin, {
    'path': 'session',
    'method': 'DELETE',
    'f_name': {
        'EN': 'Close session',
        'DE': 'Session beenden'
    },

    'f_description': {
        'EN': 'Quits the current session.',
        'DE': 'Schließt die aktuelle Session.'
    }
})
def delete_session(reqHandler, p, args, body):

    if reqHandler.get_cookie("session_id"):
        if reqHandler.get_cookie("session_id") in session_dict:
            e_delete_session(reqHandler.get_cookie("session_id"))
            return {}

    raise WebRequestException(400, 'error', 'AUTH_SESSION_NOT_FOUND')
    return {}

@api_action(plugin, {
    'path': 'session/all',
    'method': 'DELETE',
    'f_name': {
        'EN': 'Close all sessions',
        'DE': 'Alle Sessions beenden'
    },

    'f_description': {
        'EN': 'Quits all active sessions.',
        'DE': 'Schließt alle aktiven Sessions.'
    }
})
def delete_all_sessions(reqHandler, p, args, body):
    e_delete_sessions_from_user(current_user)
    return {}

@api_action(plugin, {
    'path': 'token/list',
    'method': 'GET',
    'args': {
        'verbose': {
            'type': bool,
            'default': False,
            'f_name': {
                'EN': "Verbose",
                'DE': "Ausführlich"
            }
        }
    },
    'f_name': {
        'EN': 'List API token',
        'DE': 'API Token auflisten'
    },

    'f_description': {
        'EN': 'Lists all available API token.',
        'DE': 'Listet alle erstellten API Token auf.'
    }
})
def list_user_tokens(reqHandler, p, args, body):
    full_token_list = e_list_user_token(current_user)
    
    if args['verbose']:
        return {
            'data': full_token_list
        }
    
    else:
        token_name_list = []
        for token in full_token_list:
            token_name_list.append(token['token_name'])
        
        return {
            'data': token_name_list
        }

@api_action(plugin, {
    'path': 'token/*',
    'method': 'GET',
    'params': [
        {
            'name': "token_name",
            'type': str,
            'regex': r'^[a-zA-Z0-9_-]{1,31}$',
            'f_name': {
                'EN': "Token name",
                'DE': "Tokenname"
            }
        }
    ],
    'f_name': {
        'EN': 'Get API token',
        'DE': 'Zeige API Token'
    },

    'f_description': {
        'EN': 'Returns a single API token.',
        'DE': 'Gibt ein einzelnes API Token zurück.'
    }
})
def get_user_token(reqHandler, p, args, body):
    return {
        'data': e_get_user_token(current_user, p[0])
    }

@api_action(plugin, {
    'path': 'token/*',
    'method': 'POST',
    'params': [
        {
            'name': "token_name",
            'type': str,
            'regex': r'^[a-zA-Z0-9_-]{1,31}$',
            'f_name': {
                'EN': "Token name",
                'DE': "Tokenname"
            }
        }
    ],
    'f_name': {
        'EN': 'Create API token',
        'DE': 'API Token erstellen'
    },

    'f_description': {
        'EN': 'Creates a new API token.',
        'DE': 'Erstellt ein neues API Token.'
    }
})
def create_user_token(reqHandler, p, args, body):
    return {
        'token': e_create_user_token(current_user, p[0], body)
    }

@api_action(plugin, {
    'path': 'token/*',
    'method': 'PUT',
    'params': [
        {
            'name': "token_name",
            'type': str,
            'regex': r'^[a-zA-Z0-9_-]{1,31}$',
            'f_name': {
                'EN': "Token name",
                'DE': "Tokenname"
            }
        }
    ],
    'f_name': {
        'EN': 'Edit API token',
        'DE': 'API Token editieren'
    },

    'f_description': {
        'EN': 'Edit\'s an API token.',
        'DE': 'Editiert ein API Token.'
    }
})
def edit_user_token(reqHandler, p, args, body):
    e_edit_user_token(current_user, p[0], body)
    return {}

@api_action(plugin, {
    'path': 'token/*',
    'method': 'DELETE',
    'params': [
        {
            'name': "token_name",
            'type': str,
            'regex': r'^[a-zA-Z0-9_-]{1,31}$',
            'f_name': {
                'EN': "Token name",
                'DE': "Tokenname"
            }
        }
    ],
    'f_name': {
        'EN': 'Delete API token',
        'DE': 'API Token löschen'
    },

    'f_description': {
        'EN': 'Deletes an API token.',
        'DE': 'Löscht ein API Token.'
    }
})
def delete_user_token(reqHandler, p, args, body):
    e_delete_user_token(current_user, p[0])
    return {}

@api_action(plugin, {
    'path': 'user/list',
    'method': 'GET',
    'args': {
        'verbose': {
            'type': bool,
            'default': False,
            'f_name': {
                'EN': "Verbose",
                'DE': "Ausführlich"
            }
        }
    },
    'f_name': {
        'EN': 'List users',
        'DE': 'Benutzer auflisten'
    },

    'f_description': {
        'EN': 'Returns a list with all registered users.',
        'DE': 'Gibt eine Liste mit allen registrierten Benutzern zurück.'
    }
})
def list_users(reqHandler, p, args, body):
    
    if args['verbose']:
        return {
            'data': e_list_users()
        }
    
    else:
        return {
            'data': list(users_dict.keys())
        }

@api_action(plugin, {
    'path': 'user/change_password',
    'method': 'PUT',
    'body': {
        'password': {
            'type': str,
            'f_name': {
                'EN': "Password",
                'DE': "Passwort"
            }
        }
    },
    'f_name': {
        'EN': 'Change password',
        'DE': 'Passwort ändern'
    },

    'f_description': {
        'EN': 'Changes the password of the current user.',
        'DE': 'Ändert das Passwort des momentan angemeldeten Benutzers.'
    }
})
def change_password(reqHandler, p, args, body):
    
    if not 'password' in body:
        raise WebRequestException(400, 'error', 'AUTH_PASSWORD_MISSING')
    
    e_edit_user(current_user, {'password': body['password']})
    return {}

@api_action(plugin, {
    'path': 'user/*',
    'method': 'GET',
    'params': [
        {
            'name': "username",
            'type': str,
            'regex': r'^[a-zA-Z0-9_-]{1,31}$',
            'f_name': {
                'EN': "Username",
                'DE': "Benutzername"
            }
        }
    ],
    'f_name': {
        'EN': 'Get user',
        'DE': 'Zeige Benutzer'
    },
    'f_description': {
        'EN': 'Returns a single user.',
        'DE': 'Gibt einen einzelnen Benutzer zurück.'
    }
})
def get_user(reqHandler, p, args, body):
    return {
        'data': e_get_user(p[0])
    }

@api_action(plugin, {
    'path': 'user/*',
    'method': 'POST',
    'params': [
        {
            'name': "username",
            'type': str,
            'regex': r'^[a-zA-Z0-9_-]{1,31}$',
            'f_name': {
                'EN': "Username",
                'DE': "Benutzername"
            }
        }
    ],
    'body': {
        'password': {
            'type': str,
            'f_name': {
                'EN': "Password",
                'DE': "Passwort"
            }
        },
        'roles': {
            'type': list,
            'f_name': {
                'EN': "Roles",
                'DE': "Rollen"
            },
            'allow_duplicates': False,
            'default': [],
            'childs': {
                'type': str
            }
        }
    },
    'f_name': {
        'EN': 'Create user',
        'DE': 'Benutzer erstellen'
    },

    'f_description': {
        'EN': 'Creates a new user.',
        'DE': 'Erstellt einen neuen Benutzer.'
    }
})
def create_user(reqHandler, p, args, body):
        
    if (p[0] == ""):
        raise WebRequestException(400, 'error', 'AUTH_USERNAME_MISSING')
    
    return {
        'id': str(e_create_user(p[0], body))
    }

@api_action(plugin, {
    'path': 'user/*',
    'method': 'PUT',
    'params': [
        {
            'name': "username",
            'type': str,
            'regex': r'^[a-zA-Z0-9_-]{1,31}$',
            'f_name': {
                'EN': "Username",
                'DE': "Benutzername"
            }
        }
    ],
    'body': {
        'password': {
            'type': str,
            'f_name': {
                'EN': "Password",
                'DE': "Passwort"
            }
        }
    },
    'f_name': {
        'EN': 'Edit user',
        'DE': 'Benutzer editieren'
    },

    'f_description': {
        'EN': 'Edit the properties of a user.',
        'DE': 'Editiert die Eigenschaften eines Benutzers.'
    }
})
def edit_user(reqHandler, p, args, body):
        
    if (p[0] == ""):
        raise WebRequestException(400, 'error', 'AUTH_USERNAME_MISSING')
    
    e_edit_user(p[0], body)
    return {}

@api_action(plugin, {
    'path': 'user/*',
    'method': 'DELETE',
    'params': [
        {
            'name': "username",
            'type': str,
            'regex': r'^[a-zA-Z0-9_-]{1,31}$',
            'f_name': {
                'EN': "Username",
                'DE': "Benutzername"
            }
        }
    ],
    'f_name': {
        'EN': 'Delete user',
        'DE': 'Benutzer löschen'
    },

    'f_description': {
        'EN': 'Deletes a user.',
        'DE': 'Löscht einen Benutzer.'
    }
})
def delete_user(reqHandler, p, args, body):
    
    if (p[0] == ""):
        raise WebRequestException(400, 'error', 'AUTH_USERNAME_MISSING')
    
    e_delete_user(p[0])
    return {}

@api_action(plugin, {
    'path': 'role/list',
    'method': 'GET',
    'args': {
        'verbose': {
            'type': bool,
            'default': False,
            'f_name': {
                'EN': "Verbose",
                'DE': "Ausführlich"
            }
        }
    },
    'f_name': {
        'EN': 'List roles',
        'DE': 'Rollen auflisten'
    },

    'f_description': {
        'EN': 'Lists all available roles.',
        'DE': 'Listet alle verfügbaren Rollen auf.'
    }
})
def list_roles(reqHandler, p, args, body):
    
    if args['verbose']:
        return {
            'data': e_list_roles()
        }
    
    else:
        return {
            'data': list(roles_dict.keys())
        }

@api_action(plugin, {
    'path': 'role/*',
    'method': 'GET',
    'params': [
        {
            'name': "role_name",
            'type': str,
            'regex': r'^[a-zA-Z0-9_-]{1,31}$',
            'f_name': {
                'EN': "Role name",
                'DE': "Rollenname"
            }
        }
    ],
    'f_name': {
        'EN': 'Get role',
        'DE': 'Zeige Rolle'
    },

    'f_description': {
        'EN': 'Returns a single role.',
        'DE': 'Gibt eine einzelne Rolle zurück.'
    }
})
def get_role(reqHandler, p, args, body):
    role_data = e_get_role(p[0])
    
    return {
        'data': role_data
    }

@api_action(plugin, {
    'path': 'role/*',
    'method': 'POST',
    'params': [
        {
            'name': "role_name",
            'type': str,
            'regex': r'^[a-zA-Z0-9_-]{1,31}$',
            'f_name': {
                'EN': "Role name",
                'DE': "Rollenname"
            }
        },
    ],
    'body': {
        'inherit': {
            'type': list,
            'default': [],
            'f_name': {
                'EN': "Parent groups",
                'DE': "Übergeordnete Gruppen"
            },
            'childs': {
                'type': str
            }
        },
        'permissions': {
            'type': list,
            'default': [],
            'f_name': {
                'EN': "Permissions",
                'DE': "Berechtigungen"
            },
            'childs': {
                'type': str
            }
        }
    },
    'f_name': {
        'EN': 'Create role',
        'DE': 'Rolle erstellen'
    },

    'f_description': {
        'EN': 'Creates a new role.',
        'DE': 'Erstellt eine neue Rolle.'
    }
})
def create_role(reqHandler, p, args, body):
        
    if (p[0] == ""):
        raise WebRequestException(400, 'error', 'AUTH_ROLE_MISSING')
    
    return {
        'id': str(e_create_role(p[0], body))
    }

@api_action(plugin, {
    'path': 'role/*',
    'method': 'PUT',
    'params': [
        {
            'name': "role_name",
            'type': str,
            'regex': r'^[a-zA-Z0-9_-]{1,31}$',
            'f_name': {
                'EN': "Role name",
                'DE': "Rollenname"
            }
        }
    ],
    'f_name': {
        'EN': 'Edit role',
        'DE': 'Rolle editieren'
    },

    'f_description': {
        'EN': 'Edits the properties of a role.',
        'DE': 'Editiert die Eigenschaften einer Rolle.'
    }
})
def edit_role(reqHandler, p, args, body):
        
    if (p[0] == ""):
        raise WebRequestException(400, 'error', 'AUTH_ROLE_MISSING')
    
    e_edit_role(p[0], body)
    return {}

@api_action(plugin, {
    'path': 'role/*',
    'method': 'DELETE',
    'params': [
        {
            'name': "role_name",
            'type': str,
            'regex': r'^[a-zA-Z0-9_-]{1,31}$',
            'f_name': {
                'EN': "Role name",
                'DE': "Rollenname"
            }
        }
    ],
    'f_name': {
        'EN': 'Delete role',
        'DE': 'Rolle löschen'
    },

    'f_description': {
        'EN': 'Deletes a role.',
        'DE': 'Löscht eine Rolle.'
    }
})
def delete_role(reqHandler, p, args, body):

    if (p[0] == ""):
        raise WebRequestException(400, 'error', 'AUTH_ROLE_MISSING')
    
    e_delete_role(p[0])
    return {}

@api_action(plugin, {
    'path': 'role/*/*',
    'method': 'POST',
    'params': [
        {
            'name': "role_name",
            'type': str,
            'regex': r'^[a-zA-Z0-9_-]{1,31}$',
            'f_name': {
                'EN': "Role name",
                'DE': "Rollenname"
            }
        },
        {
            'name': "username",
            'type': str,
            'regex': r'^[a-zA-Z0-9_-]{1,31}$',
            'f_name': {
                'EN': "Username",
                'DE': "Benutzername"
            }
        }
    ],
    'f_name': {
        'EN': 'Add member to role',
        'DE': 'Füge Mitglied zu Rolle hinzu'
    },

    'f_description': {
        'EN': 'Adds a new member to a role.',
        'DE': 'Fügt ein neues Mitglied zu einer Rolle hinzu.'
    }
})
def add_member_to_role(reqHandler, p, args, body):
    
    if (p[0] == ""):
        raise WebRequestException(400, 'error', 'AUTH_ROLE_MISSING')

    if (p[1] == ""):
        raise WebRequestException(400, 'error', 'AUTH_USERNAME_MISSING')

    e_add_member_to_role(p[0], p[1])
    return {}

@api_action(plugin, {
    'path': 'role/*/*',
    'method': 'DELETE',
    'params': [
        {
            'name': "role_name",
            'type': str,
            'regex': r'^[a-zA-Z0-9_-]{1,31}$',
            'f_name': {
                'EN': "Role name",
                'DE': "Rollenname"
            }
        },
        {
            'name': "username",
            'type': str,
            'regex': r'^[a-zA-Z0-9_-]{1,31}$',
            'f_name': {
                'EN': "Username",
                'DE': "Benutzername"
            }
        }
    ],
    'f_name': {
        'EN': 'Remove member from role',
        'DE': 'Entferne Mitglied aus Rolle'
    },

    'f_description': {
        'EN': 'Removes a member from a role.',
        'DE': 'Entfernt ein Mitglied aus einer Rolle.'
    }
})
def remove_member_from_role(reqHandler, p, args, body):

    if (p[0] == ""):
        raise WebRequestException(400, 'error', 'AUTH_ROLE_MISSING')

    if (p[1] == ""):
        raise WebRequestException(400, 'error', 'AUTH_USERNAME_MISSING')

    e_remove_member_from_role(p[0], p[1])
    return {}
