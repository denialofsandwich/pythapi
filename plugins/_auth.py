#!/usr/bin/python
#
# Name:        pythapi: _auth.py
# Author:      Rene Fa
# Date:        17.04.2018
# Version:     0.7
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
import tools.fancy_logs as log # Logging
import MySQLdb # MySQL
from api_plugin import * # Essential Plugin
import tornado # For POST Body decoding
from Crypto.Hash import SHA256
import base64
import time
import json
import string
import random

cookie_length = 64
max_depth = 10

plugin = api_plugin()
plugin.name = "auth"
plugin.version = "0.7"
plugin.essential = True
plugin.info['f_name'] = "Authentification"
plugin.info['f_description'] = "This plugin implements authentification. You can create accounts and grant permissions to them."

plugin.depends = []

plugin.config_defaults = {
    plugin.name: {
        'sec_salt': 'generatea128characterrandomstring',
        'first_user_name': 'admin',
        'first_user_password': 'admin'
    }
}

current_user = "anonymous"
used_tables = ["user","api_key","role","role_member"]
users_dict = {}
user_keys_dict = {}
roles_dict = {}
write_trough_cache_enabled = False

@api_external_function(plugin)
def e_generate_random_string(size=6, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

@api_external_function(plugin)
def e_hash_password(username, password):
    h = SHA256.new()
    h.update(username)
    h.update(password) 
    h.update(plugin.config[plugin.name]['sec_salt'])
    h_password = h.hexdigest()
    
    return h_password

@api_external_function(plugin)
def e_get_current_user():
    return current_user

@api_external_function(plugin)
def e_create_session(reqHandler, username, options):
    if reqHandler.get_cookie("session_id"):
        if reqHandler.get_cookie("session_id") in user_keys_dict:
            del user_keys_dict[reqHandler.get_cookie("session_id")]
    
    new_session_id = e_generate_random_string(cookie_length)
    
    user_keys_dict[new_session_id] = {
        'username': username,
        'type': 'session'
    }
    
    if 'csrf_token' in options and options['csrf_token'] == True:
        csrf_token = e_generate_random_string(cookie_length)
        user_keys_dict[new_session_id]['last_csrf_token'] = csrf_token
        reqHandler.add_header('X-CSRF-TOKEN', csrf_token)
    
    users_dict[current_user]['keys'].append(new_session_id)
    
    reqHandler.set_cookie("session_id", new_session_id)

@api_external_function(plugin)
def e_delete_session(username):
    
    i = 0;
    while i < len(users_dict[username]['keys']):
        
        key = users_dict[username]['keys'][i]
        if user_keys_dict[key]['type'] == 'session':
            del user_keys_dict[key]
            del users_dict[username]['keys'][i]
            continue
        
        i += 1

def i_get_db_user(username):
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    with db:
        sql = """
            SELECT * FROM """ +plugin.db_prefix +"""user WHERE name = %s;
        """
        
        try:
            dbc.execute(sql, [username])
        except MySQLdb.IntegrityError as e:
            log.error("i_get_db_user: Unknown SQL error.")
            raise WebRequestException(501,'error','i_get_db_user: Unknown SQL error.')
        
        result = dbc.fetchone()
        if result == None:
            raise WebRequestException(400,'error','i_get_db_user: User doesn\'t exist.')
        
        return result

def i_list_db_user():
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    with db:
        sql = """
            SELECT * FROM """ +plugin.db_prefix +"""user;
        """
        
        try:
            dbc.execute(sql)
            
        except MySQLdb.IntegrityError as e:
            log.error("i_list_db_user: Unknown SQL error.")
            raise WebRequestException(501,'error','i_list_db_user: Unknown SQL error.')
        
        return dbc.fetchall()

def i_local_get_user(username):
    if not username in users_dict:
        raise WebRequestException(400,'error','i_get_db_user: User doesn\'t exist.')
    
    return_json = dict(users_dict[username])
    return_json['username'] = username
    del return_json['keys']
    del return_json['h_password']
        
    return return_json

def i_list_local_users():
    return_json = []
    for key in users_dict:
        i_entry = dict(users_dict[key])
        i_entry['username'] = key
        del i_entry['keys']
        del i_entry['h_password']
        
        return_json.append(i_entry)
        
    return return_json

def i_get_db_roles_from_user(username):
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    with db:
        sql = """
            SELECT """ +plugin.db_prefix +"""role.role_name
                FROM """ +plugin.db_prefix +"""role_member
                JOIN """ +plugin.db_prefix +"""role ON role_id = """ +plugin.db_prefix +"""role.id
                JOIN """ +plugin.db_prefix +"""user ON user_id = """ +plugin.db_prefix +"""user.id
                WHERE """ +plugin.db_prefix +"""user.name = %s;
        """
        
        try:
            dbc.execute(sql, [username])
            
        except MySQLdb.IntegrityError as e:
            log.error("i_get_db_roles_from_user: Unknown SQL error.")
            raise WebRequestException(501,'error','i_get_db_roles_from_user: Unknown SQL error.')
        
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
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    with db:
        sql = """
            SELECT * FROM """ +plugin.db_prefix +"""user WHERE id = %s;
        """
        
        try:
            dbc.execute(sql, [user_id])
        except MySQLdb.IntegrityError as e:
            log.error("i_get_db_user: Unknown SQL error.")
            raise WebRequestException(501,'error','e_get_db_user_by_id: Unknown SQL error.')
        
        result = dbc.fetchone()
        if result == None:
            raise WebRequestException(400,'error','e_get_db_user_by_id: User doesn\'t exist.')
        
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
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    if not 'password' in data:
        raise WebRequestException(400,'error','e_create_user: Password missing.')
    
    h_password = e_hash_password(username, data['password'])
    
    with db:
        sql = """
            INSERT INTO """ +plugin.db_prefix +"""user (
                    name, password
                )
                VALUES (%s, %s);
        """
        
        try:
            dbc.execute(sql,[username, h_password])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            raise WebRequestException(400,'error','e_create_user: User already exist.')
    
    user_id = i_get_db_user(username)[0]
    
    if write_trough_cache_enabled:
        users_dict[username] = {
            'id': user_id,
            'h_password': h_password,
            'keys': [],
            'roles': []
        }
    
    e_add_member_to_role('default', username)
    
    if 'roles' in data:
        for role in data['roles']:
            e_add_member_to_role(role, username)
    
    return user_id

@api_external_function(plugin)
def e_edit_user(username, data):
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    if not 'password' in data:
        raise WebRequestException(400,'error','e_edit_user: Password missing.')
    
    h_password = e_hash_password(username, data['password'])
    
    with db:
        sql = """
            UPDATE """ +plugin.db_prefix +"""user
                SET password = %s
                WHERE name = %s;
        """
        
        try:
            dbc.execute(sql,[h_password, username])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            log.error("e_edit_user: Unknown SQL error.")
            raise WebRequestException(501,'error','e_edit_user: Unknown SQL error.')
    
    if write_trough_cache_enabled:
        users_dict[username]['h_password'] = h_password

@api_external_function(plugin)
def e_delete_user(username):
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    if write_trough_cache_enabled and not username in users_dict:
        raise WebRequestException(400,'error','e_delete_user: User doesn\'t exist.')
    
    with db:
        sql = """
            DELETE FROM """ +plugin.db_prefix +"""user 
                WHERE name = %s;
        """
        
        try:
            dbc.execute(sql,[username])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            log.error("e_delete_user: Unknown SQL error.")
            raise WebRequestException(501,'error','e_delete_user: Unknown SQL error.')
    
    if write_trough_cache_enabled:
        for i in range(len(users_dict[username]['keys'])):
            key = users_dict[username]['keys'][i]
            del user_keys_dict[key]
            del users_dict[username]['keys'][i]
        
        del users_dict[username]

def i_get_db_user_token(username, key_name):
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    if write_trough_cache_enabled:
        if not username in users_dict:
            raise WebRequestException(400,'error','i_get_db_user_token: User doesn\'t exist.')
        
        user_id = users_dict[username]['id']
    
    else:
        user_id = i_get_db_user(username)[0]
    
    with db:
        sql = """
            SELECT * FROM """ +plugin.db_prefix +"""api_key WHERE user_id = %s AND key_name = %s;
        """
        
        try:
            dbc.execute(sql, [user_id, key_name])
            
        except MySQLdb.IntegrityError as e:
            log.error("i_get_db_user_token: Unknown SQL error.")
            raise WebRequestException(501,'error','i_get_db_user_token: Unknown SQL error.')
        
        result = dbc.fetchone()
        if result == None:
            raise WebRequestException(400,'error','i_get_db_user_token: Token doesn\'t exist.')
    
        return result

def i_list_db_user_token(username):
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    with db:
        sql = """
            SELECT """ +plugin.db_prefix +"""api_key.id, name, key_name, user_key
                FROM """ +plugin.db_prefix +"""api_key
                JOIN """ +plugin.db_prefix +"""user
                ON user_id = """ +plugin.db_prefix +"""user.id
                WHERE name = %s;
        """
        
        try:
            dbc.execute(sql, [username])
            
        except MySQLdb.IntegrityError as e:
            log.error("i_list_db_user_token: Unknown SQL error.")
            raise WebRequestException(501,'error','i_list_db_user_token: Unknown SQL error.')
        
        return dbc.fetchall()

def i_list_db_token():
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    with db:
        sql = """
            SELECT """ +plugin.db_prefix +"""api_key.id, name, key_name, user_key
                FROM """ +plugin.db_prefix +"""api_key
                JOIN """ +plugin.db_prefix +"""user
                ON user_id = """ +plugin.db_prefix +"""user.id;
        """
        
        try:
            dbc.execute(sql)
            
        except MySQLdb.IntegrityError as e:
            log.error("i_list_db_token: Unknown SQL error.")
            raise WebRequestException(501,'error','i_list_db_token: Unknown SQL error.')
        
        return dbc.fetchall()

def i_get_local_user_token(username, key_name):
    for key in users_dict[username]['keys']:
        if not 'key_name' in user_keys_dict[key]:
            continue
        
        if user_keys_dict[key]['key_name'] == key_name:
            i_entry = dict(user_keys_dict[key])
            return i_entry
    
    raise WebRequestException(400,'error','i_get_local_user_token: Token doesn\'t exist.')

def i_list_local_user_token(username):
    return_json = []
    for key in users_dict[username]['keys']:
        i_entry = dict(user_keys_dict[key])
        return_json.append(i_entry)
    
    return return_json

@api_external_function(plugin)
def e_get_user_token(username, key_name):
    if write_trough_cache_enabled:
        return i_get_local_user_token(username, key_name)
    
    else:
        # Just to check if the token exists
        i_get_db_user_token(username, key_name)
        
        return_json = {}
        return_json['key_name'] = key_name
        return_json['username'] = username
        return_json['type'] = 'token'
        
        return return_json

@api_external_function(plugin)
def e_list_user_token(username):
    if write_trough_cache_enabled:
        return i_list_local_user_token(username)
    
    else:
        return_json = []
        for token in i_list_db_user_token(username):
            i_entry = {}
            
            i_entry['key_name'] = token[1]
            i_entry['username'] = username
            i_entry['type'] = 'token'
            
            return_json.append(i_entry)
        
        return return_json

@api_external_function(plugin)
def e_create_api_key(username, key_name):
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    if write_trough_cache_enabled:
        if not username in users_dict:
            raise WebRequestException(400,'error','e_create_api_key: User doesn\'t exist.')
        
        user_id = users_dict[username]['id']
    
    else:
        user_id = i_get_db_user(username)[0]
    
    new_token = e_generate_random_string(cookie_length)
    h_new_token = e_hash_password('', new_token)
    
    with db:
        sql = """
            INSERT INTO """ +plugin.db_prefix +"""api_key (
                    key_name, user_key, user_id
                )
                VALUES (%s, %s, %s);
        """
        
        try:
            dbc.execute(sql,[
                key_name,
                h_new_token,
                user_id
            ])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            raise WebRequestException(400,'error','e_create_api_key: key_name already exists.')
    
    if write_trough_cache_enabled:
        user_keys_dict[h_new_token] = {
            'username': current_user,
            'key_name': key_name,
            'type': 'token'
        }
        users_dict[current_user]['keys'].append(h_new_token)
    
    return new_token

@api_external_function(plugin)
def e_delete_api_key(username, key_name):
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    if write_trough_cache_enabled:
        if not username in users_dict:
            raise WebRequestException(400,'error','e_delete_api_key: User doesn\'t exist.')
        
        
        user_id = users_dict[username]['id']
    
    else:
        user_id = i_get_db_user(username)[0]

    i_get_db_user_token(username, key_name)
    
    with db:
        sql = """
            DELETE FROM """ +plugin.db_prefix +"""api_key 
                WHERE user_id = %s AND key_name = %s;
        """
            
        try:
            dbc.execute(sql,[user_id ,key_name])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            log.error("e_delete_api_key: Unknown SQL error.")
            raise WebRequestException(501,'error','e_delete_api_key: Unknown SQL error.')
    
    if write_trough_cache_enabled:
        for i in range(len(users_dict[username]['keys'])):
            key = users_dict[username]['keys'][i]
            if user_keys_dict[key]['key_name'] == key_name:
                del user_keys_dict[key]
                del users_dict[username]['keys'][i]
                break

def i_get_db_role(role_name):
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    with db:
        sql = """
            SELECT * FROM """ +plugin.db_prefix +"""role WHERE role_name = %s;
        """
        
        try:
            dbc.execute(sql, [role_name])
            
        except MySQLdb.IntegrityError as e:
            log.error("i_get_db_role: Unknown SQL error. (role_name: " +role_name +")")
            raise WebRequestException(501,'error','i_get_db_role: Unknown SQL error.')
        
        result = dbc.fetchone()
        if result == None:
            raise WebRequestException(400,'error','i_get_db_role: Role doesn\'t exist.')
        
        return result

def i_list_db_roles():
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    with db:
        sql = """
            SELECT * FROM """ +plugin.db_prefix +"""role;
        """
        
        try:
            dbc.execute(sql)
        
        except MySQLdb.IntegrityError as e:
            log.error("i_list_db_roles: Unknown SQL error.")
            raise WebRequestException(501,'error','i_list_db_roles: Unknown SQL error.')
        
        return dbc.fetchall()

def i_get_local_role(role_name):
    if not role_name in roles_dict:
        raise WebRequestException(400,'error','i_get_local_role: Role doesn\'t exist.')

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
    db = plugin.mysql_connect()
    dbc = db.cursor()

    with db:
        sql = """
            INSERT INTO """ +plugin.db_prefix +"""role (
                    role_name, data
                )
                VALUES (%s, %s);
        """
        
        try:
            dbc.execute(sql,[role_name, json.dumps(ruleset)])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            raise WebRequestException(400,'error','e_create_role: Role already exist.')
    
    role_id = i_get_db_role(role_name)[0]
    
    if write_trough_cache_enabled:
        roles_dict[role_name] = {
            'id': role_id,
            'ruleset': ruleset
        }
        
        i_apply_ruleset(role_name)
    
    return role_id

def i_edit_db_role(role_name, ruleset):
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    with db:
        sql = """
            UPDATE """ +plugin.db_prefix +"""role
                SET data = %s
                WHERE role_name = %s;
        """
        
        try:
            dbc.execute(sql,[json.dumps(ruleset), role_name])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            log.error("i_edit_db_role: Unknown SQL error.")
            raise WebRequestException(501,'error','i_edit_db_role: Unknown SQL error.')

@api_external_function(plugin)
def e_edit_role(role_name, ruleset):

    if write_trough_cache_enabled:
        if not role_name in roles_dict:
            raise WebRequestException(400,'error','e_edit_role: Role doesn\'t exist.')
        
        for key in ruleset:
            if ruleset[key] == None and key in roles_dict[role_name]['ruleset']:
                del roles_dict[role_name]['ruleset'][key]
            else:
                roles_dict[role_name]['ruleset'][key] = ruleset[key]
        
        ruleset = roles_dict[role_name]['ruleset']
    
    else:
        i_get_db_role(role_name)
    
    i_edit_db_role(role_name, ruleset)
    
    if write_trough_cache_enabled:
        i_apply_ruleset(role_name)

@api_external_function(plugin)
def e_delete_db_role(role_name):
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    with db:
        sql = """
            DELETE FROM """ +plugin.db_prefix +"""role 
                WHERE role_name = %s;
        """
        
        try:
            dbc.execute(sql,[role_name])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            log.error("e_delete_db_role: Unknown SQL error.")
            raise WebRequestException(501,'error','e_delete_db_role: Unknown SQL error.')

@api_external_function(plugin)
def e_delete_role(role_name):
    
    if write_trough_cache_enabled:
        if not role_name in roles_dict:
            raise WebRequestException(400,'error','e_delete_role: Role doesn\'t exist.')

    else:
        i_get_db_role(role_name)
        
    e_delete_db_role(role_name)
    
    if write_trough_cache_enabled:
        for user in users_dict:
            try: users_dict[user]['roles'].remove(role_name)
            except: pass
        
        del roles_dict[role_name]
        
        i_apply_ruleset(role_name)

@api_external_function(plugin)
def e_add_member_to_role(role_name, username):
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    if write_trough_cache_enabled:
        if not role_name in roles_dict:
            raise WebRequestException(400,'error','e_add_member_to_role: Role doesn\'t exist.')
        
        if not username in users_dict:
            raise WebRequestException(400,'error','e_add_member_to_role: User doesn\'t exist.')
        
        role_id = roles_dict[role_name]['id']
        user_id = users_dict[username]['id']
    
    else:
        role_id = i_get_db_role(role_name)[0]
        user_id = i_get_db_user(username)[0]
    
    with db:
        sql = """
            INSERT INTO """ +plugin.db_prefix +"""role_member (
                    role_id, user_id
                )
                VALUES (%s, %s);
        """
            
        try:
            dbc.execute(sql,[role_id, user_id])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            raise WebRequestException(400,'error','e_add_member_to_role: User is already member of this Role.')
    
    if write_trough_cache_enabled:
        users_dict[username]['roles'].append(role_name)

@api_external_function(plugin)
def e_remove_member_from_role(role_name, username):
    db = plugin.mysql_connect()
    
    if write_trough_cache_enabled:
        if not role_name in roles_dict:
            raise WebRequestException(400,'error','e_remove_member_from_role: Role doesn\'t exist.')
        
        if not username in users_dict:
            raise WebRequestException(400,'error','e_remove_member_from_role: User doesn\'t exist.')
        
        if not role_name in users_dict[username]['roles']:
            raise WebRequestException(400,'error','e_remove_member_from_role: User is not a member of this role.')
    
        role_id = roles_dict[role_name]['id']
        user_id = users_dict[username]['id']
        
    else:
        role_id = i_get_db_role(role_name)[0]
        
        user = e_get_user(username)
        user_id = user['id']
        
        if not role_name in user['roles']:
            raise WebRequestException(400,'error','e_remove_member_from_role: User is not a member of this role.')
    
    dbc = db.cursor()
    sql = """
        DELETE FROM """ +plugin.db_prefix +"""role_member 
            WHERE role_id = %s AND user_id = %s;
    """
        
    try:
        dbc.execute(sql,[role_id, user_id])
        db.commit()
        
    except MySQLdb.IntegrityError as e:
        raise WebRequestException(501,'error','e_remove_member_from_role: Unknown SQL error.')
    
    dbc.close()
    
    if write_trough_cache_enabled:
        users_dict[username]['roles'].remove(role_name)

def i_apply_ruleset(role_name):
    
    for plugin_name in plugin.action_tree:
        for action_name in plugin.action_tree[plugin_name]:
            try: plugin.action_tree[plugin_name][action_name]['roles'].remove(role_name)
            except: pass
    
    if not role_name in roles_dict:
        return
    
    ruleset = roles_dict[role_name]['ruleset']
    for p_rule in roles_dict[role_name]['ruleset']['permissions']:
        rule_r = re.split('\.', p_rule)
        
        if rule_r[0] == '*':
            if len(rule_r) > 1:
                log.warning("Auth: Syntax error in ruleset " +role_name +": " +p_rule)
                continue
            
            for plugin_name in plugin.action_tree:
                for action_name in plugin.action_tree[plugin_name]:
                    role_list = plugin.action_tree[plugin_name][action_name]['roles']
                    
                    if role_name in role_list:
                        continue
                    
                    role_list.append(role_name)
        
        elif len(rule_r) == 1 or (rule_r[1] == '*' and len(rule_r) == 2):
            if not rule_r[0] in plugin.action_tree:
                log.warning("Auth: Error in ruleset " +role_name +": Plugin " +rule_r[0] +" not found.")
                continue
            
            for action_name in plugin.action_tree[rule_r[0]]:
                role_list = plugin.action_tree[rule_r[0]][action_name]['roles']
                
                if role_name in role_list:
                    continue
                
                role_list.append(role_name)
                
        elif len(rule_r) == 2:
            if not rule_r[0] in plugin.action_tree:
                log.warning("Auth: Error in ruleset " +role_name +": Plugin " +rule_r[0] +" not found.")
                continue
            
            if not rule_r[1] in plugin.action_tree[rule_r[0]]:
                log.warning("Auth: Error in ruleset " +role_name +": Action " +rule_r[1] +" not found.")
                continue
            
            role_list = plugin.action_tree[rule_r[0]][rule_r[1]]['roles']
                
            if role_name in role_list:
                continue
                
            role_list.append(role_name)
            
        else:
            log.warning("Auth: Error in ruleset " +role_name +": " +p_rule +": Too high depth.")
            continue

@api_event(plugin, 'check')
def check():
    
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    with db:
        # Checks if all tables exist.
        result = 1
        for table in used_tables:
            sql = "SHOW TABLES LIKE '" +plugin.db_prefix +table +"'"
            result *= dbc.execute(sql)
    
    if(result == 0):
        return 0
    
    return 1

@api_event(plugin, 'load')
def load():
    global write_trough_cache_enabled
    
    for row in i_list_db_user():
        users_dict[row[1]] = {
            'id': row[0],
            'h_password': row[2],
            'keys': [],
            'roles': []
        }
        
        for role in i_get_db_roles_from_user(row[1]):
            users_dict[row[1]]['roles'].append(role[0])
    
    for row in i_list_db_token():
        user_keys_dict[row[3]] = {
            'username': row[1],
            'key_name': row[2],
            'type': 'token'
        }
        users_dict[row[1]]['keys'].append(row[3])
        
    for row in i_list_db_roles():
        roles_dict[row[1]] = {
            'id': row[0],
            'ruleset': json.loads(row[2])
        }
    
    for role_name in roles_dict:
        i_apply_ruleset(role_name)
    
    write_trough_cache_enabled = True
    return 1

@api_event(plugin, 'install')
def install():
    
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    log.info("Create new Tables...")
    
    with db:
        sql = """
            CREATE TABLE """ +plugin.db_prefix +"""user (
                id INT NOT NULL AUTO_INCREMENT,
                name VARCHAR(32) NOT NULL,
                password VARCHAR(64) NOT NULL,
                PRIMARY KEY( id ),
                UNIQUE ( name )
            ) ENGINE = InnoDB;
            """
        dbc.execute(sql)
        log.debug("Table: '" +plugin.db_prefix +"user' created.")

        sql = """
            CREATE TABLE """ +plugin.db_prefix +"""api_key (
                id INT NOT NULL AUTO_INCREMENT,
                key_name VARCHAR(32) NOT NULL,
                user_key VARCHAR(64) NOT NULL,
                user_id INT NOT NULL,
                PRIMARY KEY (id),
                UNIQUE (key_name, user_id)
            ) ENGINE = InnoDB;
            """
        dbc.execute(sql)
        log.debug("Table: '" +plugin.db_prefix +"api_key' created.")
        
        sql = """
            CREATE TABLE """ +plugin.db_prefix +"""role (
                id INT NOT NULL AUTO_INCREMENT,
                role_name VARCHAR(32) NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (id),
                UNIQUE (role_name)
            ) ENGINE = InnoDB;
            """
        dbc.execute(sql)
        log.debug("Table: '" +plugin.db_prefix +"role' created.")
        
        sql = """
            CREATE TABLE """ +plugin.db_prefix +"""role_member (
                id INT NOT NULL AUTO_INCREMENT,
                role_id INT NOT NULL,
                user_id INT NOT NULL,
                PRIMARY KEY (id),
                UNIQUE (role_id, user_id)
            ) ENGINE = InnoDB;
            """
        dbc.execute(sql)
        log.debug("Table: '" +plugin.db_prefix +"role_member' created.")
        
        sql = """
            ALTER TABLE """ +plugin.db_prefix +"""api_key
                ADD CONSTRAINT """ +plugin.db_prefix +"""api_key_to_user
                FOREIGN KEY ( user_id )
                REFERENCES """ +plugin.db_prefix +"""user ( id )
                ON DELETE CASCADE
                ON UPDATE CASCADE;
            """
        dbc.execute(sql)
        
        sql = """
            ALTER TABLE """ +plugin.db_prefix +"""role_member
                ADD CONSTRAINT """ +plugin.db_prefix +"""role_member_to_role
                FOREIGN KEY (role_id)
                REFERENCES """ +plugin.db_prefix +"""role(id)
                ON DELETE CASCADE
                ON UPDATE CASCADE;
            """
        dbc.execute(sql)
        
        sql = """
            ALTER TABLE """ +plugin.db_prefix +"""role_member
                ADD CONSTRAINT """ +plugin.db_prefix +"""role_member_to_user
                FOREIGN KEY (user_id)
                REFERENCES """ +plugin.db_prefix +"""user(id)
                ON DELETE CASCADE
                ON UPDATE CASCADE;
            """
        dbc.execute(sql)
        log.debug("Constraints created.")
    
    e_create_role('admin', {
        "permissions":  [
            "*"
        ]
    })
    
    e_create_role('auth_default', {
        "permissions":  [
            "auth.create_session",
            "auth.delete_session",
            
            "auth.get_api_key",
            "auth.list_api_keys",
            "auth.create_api_key",
            "auth.delete_api_key",
            
            "auth.change_password",
            "auth.get_current_user"
        ]
    })
    
    e_create_role('default', {
        "inherit":  [
            "auth_default"
        ],
        "permissions": []
    })
    
    e_create_role('anonymous', {
        "permissions":  []
    })
    
    e_create_user(plugin.config[plugin.name]['first_user_name'], {
        'password': plugin.config[plugin.name]['first_user_password']
    })
    
    e_create_user('anonymous', {
        'password': e_generate_random_string(cookie_length)
    })
    
    e_remove_member_from_role('default', plugin.config[plugin.name]['first_user_name'])
    e_add_member_to_role('admin', plugin.config[plugin.name]['first_user_name'])
    
    e_remove_member_from_role('default', 'anonymous')
    e_add_member_to_role('anonymous', 'anonymous')
    
    log.debug("Initial data created.")
    return 1

@api_event(plugin, 'uninstall')
def uninstall():
    
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    log.info("Delete old Tables...")
    
    for table in reversed(used_tables):
        sql = "DROP TABLE " +plugin.db_prefix +table +";"
        
        try: dbc.execute(sql)
        except MySQLdb.Error:
            continue
            
        log.debug("Table: '" +plugin.db_prefix +table +"' deleted.")
    
    dbc.close()
    return 1

def ir_check_permissions(role_name, target_list, depth = 0):
    
    if depth > max_depth: return 0
    
    if 'inherit' in roles_dict[role_name]['ruleset']:
        parents = roles_dict[role_name]['ruleset']['inherit']
        for parent in parents:
            if ir_check_permissions(parent, target_list, depth +1):
                return 1
    
    if role_name in target_list:
        return 1
        
    return 0

def i_is_permited(username, action):

    for role_name in users_dict[username]['roles']:
        if ir_check_permissions(role_name, action['roles']):
            return 1
    
    raise WebRequestException(401,'unauthorized','Permission denied.')

@api_event(plugin, 'global_preexecution_hook')
def global_preexecution_hook(reqHandler, action):
    global current_user
    
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    auth_header = reqHandler.request.headers.get('Authorization', None)
    if auth_header is not None:
        r_auth_header = re.split(' ', auth_header)
        
        if(r_auth_header[0] == "Basic"):
            time.sleep(0.5) # Increased security
        
            credentials = re.split(':',
                base64.b64decode(
                    r_auth_header[1]
                )
            )
            
            if credentials[0] in users_dict:
                if (e_hash_password(credentials[0], credentials[1]) == users_dict[credentials[0]]['h_password']):
                
                    current_user = credentials[0]
                    if i_is_permited(current_user, action):
                        return
                
                else:
                    raise WebRequestException(401,'unauthorized','Invalid username or password.')
        
        elif(r_auth_header[0] == "Bearer"):
            h_token = e_hash_password('', r_auth_header[1])
            
            if h_token in user_keys_dict:
                current_user = user_keys_dict[h_token]['username']
                if i_is_permited(current_user, action):
                    return
            
            else:
                raise WebRequestException(401,'unauthorized','Invalid token.')
      
    session_id = reqHandler.get_cookie("session_id")
    if session_id:
        if session_id in user_keys_dict:
            
            if 'last_csrf_token' in user_keys_dict[session_id]:
                csrf_token = reqHandler.request.headers.get('X-CSRF-TOKEN', None)
                if csrf_token != user_keys_dict[session_id]['last_csrf_token']:
                    raise WebRequestException(401,'unauthorized','Invalid CSRF-token.')
                
                csrf_token = e_generate_random_string(cookie_length)
                user_keys_dict[session_id]['last_csrf_token'] = csrf_token
                reqHandler.add_header('X-CSRF-TOKEN', csrf_token)
                
            current_user = user_keys_dict[session_id]['username']
            if i_is_permited(current_user, action):
                return

    current_user = "anonymous"
    if i_is_permited(current_user, action):
        return

    raise WebRequestException(401,'unauthorized','Permission denied.')

@api_action(plugin, {
    'path': 'debug',
    'method': 'POST',
    'f_name': 'Debug 1',
    'f_description': 'Dumps the write through cache.'
})
def auth_debug1(reqHandler, p, body):
    return {
        'users_dict': users_dict,
        'user_keys_dict': user_keys_dict,
        'roles_dict': roles_dict
    }

@api_action(plugin, {
    'path': 'debug2',
    'method': 'POST'
})
def auth_debug2(reqHandler, p, body):
    
    plist = {} 
    for i_p in plugin.all_plugins:
        i_pe = plugin.all_plugins[i_p]
        i_actions = {} 
     
        for i_action in i_pe.actions:
            i_ae = {} 
            i_ae['roles'] = i_action['roles']
     
            i_actions[i_action['name']] = i_ae 
     
        plist[i_pe.name] = {} 
        plist[i_pe.name]['actions'] = i_actions
        plist[i_pe.name]['essential'] = i_pe.essential
    
    return {
        'data': plist
    }

@api_action(plugin, {
    'path': 'whoami',
    'method': 'GET',
    'f_name': 'Get current user',
    'f_description': 'Returns the current user.'
})
def get_current_user(reqHandler, p, body):
    return {
        'data': e_get_user(e_get_current_user())
    }

@api_action(plugin, {
    'path': 'session',
    'method': 'POST',
    'f_name': 'Create session',
    'f_description': 'Sets a cookie and creates a session.'
})
def create_session(reqHandler, p, body):
    e_create_session(reqHandler, current_user, body)
    
    return {}

@api_action(plugin, {
    'path': 'session',
    'method': 'DELETE',
    'f_name': 'Delete session',
    'f_description': 'Quits all active sessions.'
})
def delete_session(reqHandler, p, body):
    
    e_delete_session(current_user)
    return {}

@api_action(plugin, {
    'path': 'token/list',
    'method': 'GET',
    'f_name': 'List API keys',
    'f_description': 'Lists all availabla session keys and token.'
})
def list_api_keys(reqHandler, p, body):
    return {
        'data': e_list_user_token(current_user)
    }

@api_action(plugin, {
    'path': 'token/*',
    'method': 'GET',
    'f_name': 'Get API key',
    'f_description': 'Returns a single API token.'
})
def get_api_key(reqHandler, p, body):
    return {
        'data': e_get_user_token(current_user, p[0])
    }

@api_action(plugin, {
    'path': 'token/*',
    'method': 'POST',
    'f_name': 'Create API Token',
    'f_description': 'Creates a new API token.'
})
def create_api_key(reqHandler, p, body):
    return {
        'token': e_create_api_key(current_user, p[0])
    }

@api_action(plugin, {
    'path': 'token/*',
    'method': 'DELETE',
    'f_name': 'Delete API Token',
    'f_description': 'Deletes an API token.'
})
def delete_api_key(reqHandler, p, body):
    e_delete_api_key(current_user, p[0])
    return {}

@api_action(plugin, {
    'path': 'user/list',
    'method': 'GET',
    'f_name': 'List users',
    'f_description': 'Returns a list with all registered users.'
})
def list_users(reqHandler, p, body):
    return {
        'data': e_list_users()
    }

@api_action(plugin, {
    'path': 'user/change_password',
    'method': 'PUT',
    'f_name': 'Change password',
    'f_description': 'Changes the password of the current user.'
})
def change_password(reqHandler, p, body):
    
    if not 'password' in body:
        raise WebRequestException(400,'error','change_password: Password missing.')
    
    e_edit_user(current_user, {'password': body['password']})
    return {}

@api_action(plugin, {
    'path': 'user/*',
    'method': 'GET',
    'f_name': 'Get user',
    'f_description': 'Returns a single user.'
})
def get_user(reqHandler, p, body):
    return {
        'data': e_get_user(p[0])
    }

@api_action(plugin, {
    'path': 'user/*',
    'method': 'POST',
    'f_name': 'Create user',
    'f_description': 'Creates a single user.'
})
def create_user(reqHandler, p, body):
        
    if (p[0] == ""):
        raise WebRequestException(400,'error','create_user: Username missing.')
    
    return {
        'id': str(e_create_user(p[0], body))
    }

@api_action(plugin, {
    'path': 'user/*',
    'method': 'PUT',
    'f_name': 'Edit user',
    'f_description': 'Edit the properties of a user.'
})
def edit_user(reqHandler, p, body):
        
    if (p[0] == ""):
        raise WebRequestException(400,'error','edit_user: Username missing.')
    
    e_edit_user(p[0], body)
    return {}

@api_action(plugin, {
    'path': 'user/*',
    'method': 'DELETE',
    'f_name': 'Delete user',
    'f_description': 'Deletes a user.'
})
def delete_user(reqHandler, p, body):
    
    if (p[0] == ""):
        raise WebRequestException(400,'error','delete_user: User missing.')
    
    e_delete_user(p[0])
    return {}

@api_action(plugin, {
    'path': 'role/list',
    'method': 'GET',
    'f_name': 'List roles',
    'f_description': 'Lists all available roles.'
})
def list_roles(reqHandler, p, body):
    return {
        'data': e_list_roles()
    }

@api_action(plugin, {
    'path': 'role/*',
    'method': 'GET',
    'f_name': 'Get role',
    'f_description': 'Returns a single role.'
})
def get_role(reqHandler, p, body):
    role_data = e_get_role(p[0])
    
    if role_data == None:
        raise WebRequestException(400,'error','get_role: Role not found.')
    
    return {
        'data': role_data
    }

@api_action(plugin, {
    'path': 'role/*',
    'method': 'POST',
    'f_name': 'Create role',
    'f_description': 'Creates a new role.'
})
def create_role(reqHandler, p, body):
        
    if (p[0] == ""):
        raise WebRequestException(400,'error','create_role: Role missing.')
    
    return {
        'id': str(e_create_role(p[0], body))
    }

@api_action(plugin, {
    'path': 'role/*',
    'method': 'PUT',
    'f_name': 'Edit role',
    'f_description': 'Edit a role and its properties.'
})
def edit_role(reqHandler, p, body):
        
    if (p[0] == ""):
        raise WebRequestException(400,'error','edit_role: Role missing.')
    
    e_edit_role(p[0], body)
    return {}

@api_action(plugin, {
    'path': 'role/*',
    'method': 'DELETE',
    'f_name': 'Delete role',
    'f_description': 'Deletes a role.'
})
def delete_role(reqHandler, p, body):

    if (p[0] == ""):
        raise WebRequestException(400,'error','delete_role: Role missing.')
    
    e_delete_role(p[0])
    return {}

@api_action(plugin, {
    'path': 'role/*/*',
    'method': 'POST',
    'f_name': 'Add member to role',
    'f_description': 'Adds a new member to a role.'
})
def add_member_to_role(reqHandler, p, body):

    if (p[0] == ""):
        raise WebRequestException(400,'error','add_member_to_role: Role missing.')

    if (p[1] == ""):
        raise WebRequestException(400,'error','add_member_to_role: User missing.')

    e_add_member_to_role(p[0], p[1])
    return {}

@api_action(plugin, {
    'path': 'role/*/*',
    'method': 'DELETE',
    'f_name': 'Remove member from role',
    'f_description': 'Removes a member from a role.'
})
def remove_member_from_role(reqHandler, p, body):

    if (p[0] == ""):
        raise WebRequestException(400,'error','remove_member_from_role: Role missing.')

    if (p[1] == ""):
        raise WebRequestException(400,'error','remove_member_from_role: User missing.')

    e_remove_member_from_role(p[0], p[1])
    return {}
