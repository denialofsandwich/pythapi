#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: data.py
# Author:      Rene Fa
# Date:        13.04.2018
# Version:     1.0
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
import MySQLdb
from api_plugin import *
import json
import re
import os
import copy

plugin = api_plugin()
plugin.name = "data"
plugin.version = "1.0"
plugin.essential = False
plugin.info['f_name'] = {
    'EN': 'Data storage',
    'DE': 'Datenspeicher'
}

plugin.info['f_description'] = {
    'EN': 'This plugin allows to save data, based on a key-value store.',
    'DE': 'Dieses Plugin ermöglicht es, Daten, basierend auf einem Key-Value Speicher, zu speichern.'
}

plugin.info['f_icon'] = {
    'EN': 'storage'
}

plugin.depends = [
    {
        'name': 'auth',
        'required': True
    }
]

plugin.translation_dict = {
    'DATA_ILLEGAL_CHARACTER_FOUND': {
        'EN': "Invalid character in key name found.",
        'DE': "Ungültiges Zeichen in Schlüsselnamen gefunden."
    }
}

plugin.config_defaults = {}

used_tables = ["data"]

def i_data_permission_validator(ruleset, rule_section, target_rule):
    if not rule_section in ruleset:
        return 0

    rules = ruleset[rule_section]

    if '/* rw' in rules:
        return 1

    path, operation = target_rule.split(' ')
    
    for rule in rules:
        i_path, i_operations = rule.split(' ')

        if '#' in i_path:
            auth = api_plugins()['auth']
            current_user = auth.e_get_current_user()
            i_path = i_path.replace('#username', current_user)
        
        if not operation in i_operations:
            continue

        if path == i_path:
            return 1
        
        if path.find(i_path[:-1]) != -1:
            return 1

    return 0

def i_data_permission_reduce_handler(ruleset):
    section_name = 'data_permissions'
    if not section_name in ruleset:
        return ruleset

    ruleset[section_name] = list(set(ruleset[section_name]))

    if '/ rw' in ruleset[section_name]:
        ruleset[section_name] = ['/ rw']

    for rule in list(ruleset[section_name]):
        path, operations = rule.split(' ')

        for sub_rule in list(ruleset[section_name]):
            if rule == sub_rule:
                continue

            sub_path, sub_operations = sub_rule.split(' ')

            fully_included = True
            for s_op in sub_operations:
                if not s_op in operations:
                    fully_included = False
                    break
                
            if not fully_included:
                continue

            if re.search(r'^' +re.escape(path), sub_rule):
                ruleset[section_name].remove(sub_rule)

    return ruleset

def i_data_subset_intersection_handler(ruleset, subset):
    section_name = 'data_permissions'
    return_subset = {}

    if section_name not in ruleset or section_name not in subset:
        return return_subset

    if '/ rw' in ruleset[section_name] or not section_name in subset:
        return copy.deepcopy(subset)

    for ss_rule in list(subset[section_name]):
        s_path, s_operations = ss_rule.split(' ')

        for rule in ruleset[section_name]:
            path, operations = rule.split(' ')

            fully_included = True
            for s_op in s_operations:
                if not s_op in operations:
                    fully_included = False
                    break
                
            if not fully_included:
                continue

            if re.search(r'^' +re.escape(path), s_path):
                if not section_name in return_subset:
                    return_subset[section_name] = []

                return_subset[section_name].append(ss_rule)
                break

    return return_subset

def i_resolve_user_id_from_path(path):
    match = re.search(r'/user/([^\/]+)/', path)
    if match:
        username = match.group(1)
        auth = api_plugins()['auth']
        user_id = auth.e_get_user(username)['id']

        return user_id

    else:
        return 1 # Admin user_id = 1

def ir_serialize_data_tree(root, data_dict):
    insert_data = []
    delete_data = []

    if type(data_dict) == dict:
        for key, value in data_dict.items():
            if key.find('/') != -1:
                raise WebRequestException(400, 'error', 'DATA_ILLEGAL_CHARACTER_FOUND')

            path = os.path.join(root, key)
            
            if type(value) == dict and value != {}:
                delete_data.append(path)

                new_insert_data, new_delete_data = ir_serialize_data_tree(path, value)

                insert_data.extend(new_insert_data)
                delete_data.extend(new_delete_data)

            else:
                delete_data.append(os.path.join(path, '%'))

                insert_data.append(path)
                insert_data.append(json.dumps(value))
                insert_data.append(i_resolve_user_id_from_path(path))

    else:
        delete_data.append(root)

        insert_data.append(root)
        insert_data.append(json.dumps(data_dict))
        insert_data.append(i_resolve_user_id_from_path(root))

    return insert_data, delete_data

@api_external_function(plugin)
def e_read_data(path):

    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()

    dbc = db.cursor()
    row_count = dbc.execute("""
            SELECT *
                FROM """ +db_prefix +"""data
                WHERE key_name = %s OR key_name LIKE %s;
        """, [path, os.path.join(path, '%')])

    if row_count == 0:
        return None
    else:
        return_json = {}

    for row in dbc:

        if path == row[0]:
            return json.loads(row[2])

        else:
            hierarchy = row[0][len(path):].lstrip('/').split('/')
            
            i_dict = return_json
            for i_dir in hierarchy[:-1]:
                i_dict = i_dict.setdefault(i_dir, {})
                
            i_dict[hierarchy[-1]] = json.loads(row[2])

    db.close()

    return return_json

@api_external_function(plugin)
def e_write_data(root, data):
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()

    insert_data, delete_data = ir_serialize_data_tree(root, data)

    insert_skeleton = ','.join(['(%s, %s, %s)'] *int(len(insert_data)/3))
    delete_skeleton = ' OR '.join(['key_name LIKE %s'] *len(delete_data))

    dbc = db.cursor()
    affected_rows = dbc.execute("""
            DELETE FROM """ +db_prefix +"""data
                WHERE """ +delete_skeleton +""";
        """, delete_data)

    affected_rows += dbc.execute("""
            INSERT INTO """ +db_prefix +"""data (
                    key_name, data, user_id
                )
                VALUES """ +insert_skeleton +"""
                ON DUPLICATE KEY
                UPDATE data = VALUES (data);
        """, insert_data)

    db.commit()
    db.close()
    return affected_rows

@api_external_function(plugin)
def e_delete_data(path):
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()

    dbc = db.cursor()
    affected_rows = dbc.execute("""
            DELETE FROM """ +db_prefix +"""data
                WHERE key_name = %s OR key_name LIKE %s;
        """, [path, os.path.join(path, '%')])

    db.commit()
    db.close()
    return affected_rows

@api_event(plugin, 'check')
def check():
    
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    # Checks if all tables exist.
    result = 1
    for table in used_tables:
        sql = "SHOW TABLES LIKE '" +db_prefix +table +"'"
        result *= dbc.execute(sql)

    db.close()
    
    if(result == 0):
        log.debug("Required tables not found! Try to install this plugin first.")
        return 0
    
    return 1

@api_event(plugin, 'install')
def install():
    
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    api_log().info("Create new Tables...")
    
    sql = """
        CREATE TABLE """ +db_prefix +"""data (
            key_name VARCHAR(255) NOT NULL,
            user_id INT NOT NULL,
            data TEXT NOT NULL,
            PRIMARY KEY (key_name)
        ) ENGINE = InnoDB DEFAULT CHARSET=utf8;
        """
    dbc.execute(sql)
    api_log().debug("Table: '" +db_prefix +"data' created.")
    
    sql = """
        ALTER TABLE """ +db_prefix +"""data
            ADD CONSTRAINT """ +db_prefix +"""data_to_user
            FOREIGN KEY ( user_id )
            REFERENCES """ +db_prefix +"""user ( id )
            ON DELETE CASCADE
            ON UPDATE CASCADE;
        """
    dbc.execute(sql)
    dbc.close()
    
    auth = api_plugins()['auth']

    auth.e_create_role('data_default', {
        'permissions':  [
            'data.*'
        ],
        'data_permissions': [
            '/user/#username rw',
            '/global r'
        ]
    })

    ruleset = auth.e_get_role('default')['ruleset']

    try:
        if 'inherit' not in ruleset:
            ruleset['inherit'] = []

        if not 'data_default' in ruleset['inherit']:
            ruleset['inherit'].append('data_default')

        auth.e_edit_role('default', ruleset)
    except WebRequestException as e:
        api_log().error('Editing the default role failed!')
        return 0

    auth.e_create_role('data_admin', {
        'permissions':  [
            'data.*'
        ],
        'data_permissions': [
            '/ rw',
        ]
    })

    ruleset = auth.e_get_user('admin')['ruleset']

    try:
        if 'inherit' not in ruleset:
            ruleset['inherit'] = []

        if not 'data_admin' in ruleset['inherit']:
            ruleset['inherit'].append('data_admin')

        auth.e_edit_user('admin', {'ruleset': ruleset})
    except WebRequestException as e:
        api_log().error('Editing the admin role failed!')
        return 0

    return 1

@api_event(plugin, 'uninstall')
def uninstall():

    auth = api_plugins()['auth']

    if auth.events['check']():
        try:
            ruleset = auth.e_get_role('default')['ruleset']
            ruleset['inherit'].remove('data_default')
            auth.e_edit_role('default', ruleset)
        except: pass

        try:
            auth.e_delete_role('data_default')
        except: pass

        try:
            ruleset = auth.e_get_user('admin')['ruleset']
            ruleset['inherit'].remove('data_admin')
            auth.e_edit_user('admin', {'ruleset': ruleset})
        except: pass

        try:
            auth.e_delete_role('data_admin')
        except: pass

        api_log().debug('Roles deleted.')

    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    api_log().info("Delete old Tables...")
    
    for table in reversed(used_tables):
        sql = "DROP TABLE " +db_prefix +table +";"
        
        try: dbc.execute(sql)
        except MySQLdb.Error: continue
    
        api_log().debug("Table: '" +db_prefix +table +"' deleted.")
    
    dbc.close()

    return 1

@api_event(plugin, 'load')
def load():
    auth = api_plugins()['auth']
    auth.e_add_permission_reduce_handler(i_data_permission_reduce_handler)
    auth.e_add_subset_intersection_handler(i_data_subset_intersection_handler)

    return 1

@api_action(plugin, {
    'regex': r'^' +re.escape(plugin.name) +r'(/.*)$',
    'method': 'GET',
    'permission': 'read',
    'f_name': {
        'EN': 'Read data',
        'DE': 'Daten lesen'
    },
    'f_description': {
        'EN': 'Reads data from the Storage.',
        'DE': 'Liest Daten aus dem Speicher.'
    }
})
def read_data(reqHandler, p, args, body):

    auth = api_plugins()['auth']
    if not auth.e_check_custom_permissions_of_current_user(plugin.name +'_permissions', p[0] +' r', i_data_permission_validator):
        raise WebRequestException(401, 'unauthorized', 'AUTH_PERMISSIONS_DENIED')

    return {
        'data': e_read_data(p[0])
    }

@api_action(plugin, {
    'regex': r'^' +re.escape(plugin.name) +r'(/.*)$',
    'method': 'POST',
    'permission': 'write',
    'f_name': {
        'EN': 'Write data',
        'DE': 'Schreibe Daten'
    },
    'f_description': {
        'EN': 'Write data in the storage.',
        'DE': 'Schreibt Daten in den Speicher.'
    }
})
def write_data(reqHandler, p, args, body):

    auth = api_plugins()['auth']
    if not auth.e_check_custom_permissions_of_current_user(plugin.name +'_permissions', p[0] +' w', i_data_permission_validator):
        raise WebRequestException(401, 'unauthorized', 'AUTH_PERMISSIONS_DENIED')

    return {
        'affected_rows': e_write_data(p[0], body)
    }

@api_action(plugin, {
    'regex': r'^' +re.escape(plugin.name) +r'(/.*)$',
    'method': 'DELETE',
    'permission': 'delete',
    'f_name': {
        'EN': 'Delete data',
        'DE': 'Daten löschen'
    },
    'f_description': {
        'EN': 'Deletes data from the storage.',
        'DE': 'Löscht daten aus dem Speicher.'
    }
})
def delete_data(reqHandler, p, args, body):

    auth = api_plugins()['auth']
    if not auth.e_check_custom_permissions_of_current_user(plugin.name +'_permissions', p[0] +' w', i_data_permission_validator):
        raise WebRequestException(401, 'unauthorized', 'AUTH_PERMISSIONS_DENIED')

    return {
        'affected_rows': e_delete_data(p[0])
    }
