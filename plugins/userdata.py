#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: userdata.py
# Author:      Rene Fa
# Date:        13.04.2018
# Version:     0.9
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
import json

plugin = api_plugin()
plugin.name = "userdata"
plugin.version = "1.0"
plugin.essential = False
plugin.info['f_name'] = {
    'EN': 'Userdata',
    'DE': 'Benutzerspeicher'
}

plugin.info['f_description'] = {
    'EN': 'This plugin allows to save userspecific data, based on a key-value store.',
    'DE': 'Dieses Plugin ermöglicht es benutzerspezifische Daten basierend auf einem Key-Value Speicher zu speichern.'
}

plugin.depends = [
    {
        'name': 'auth',
        'required': True
    }
]

plugin.config_defaults = {}

used_tables = ["user_data"]

@api_external_function(plugin)
def e_write_data(username, container_name, data, hidden = 0):
    auth = api_plugins()['auth']
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    user_id = auth.e_get_user(username)['id']
    
    values_skeleton_list = []
    data_list = []
    for key_name in data:
        values_skeleton_list.append('(%s, %s, %s, %s, %s)')
        data_list.append(user_id)
        data_list.append(container_name)
        data_list.append(key_name)
        data_list.append(hidden)
        data_list.append(json.dumps(data[key_name]))
        
    values_skeleton = ','.join(values_skeleton_list)
    
    with db:
        sql = """
            INSERT INTO """ +db_prefix +"""user_data (
                    user_id, container, key_name, hidden, data
                )
                VALUES """ +values_skeleton +"""
                ON DUPLICATE KEY
                UPDATE data = VALUES (data), hidden = VALUES (hidden);
        """
        
        try:
            dbc.execute(sql, data_list)
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            api_log().error("e_write_data: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')
    
        return dbc.rowcount

@api_external_function(plugin)
def e_delete_data(username, container_name, key_name, hidden = 0):
    auth = api_plugins()['auth']
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    key_name = key_name.replace('*', '%')
    user_id = auth.e_get_user(username)['id']

    with db:
        sql = """
            DELETE FROM """ +db_prefix +"""user_data 
                WHERE user_id = %s AND container = %s AND key_name LIKE %s AND hidden = %s;
        """
        
        try:
            dbc.execute(sql, [user_id, container_name, key_name, hidden])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            api_log().error("e_delete_data: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')
        
        return dbc.rowcount

@api_external_function(plugin)
def e_get_data(username, container_name, key_name, hidden = 0):
    auth = api_plugins()['auth']
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    key_name = key_name.replace('*', '%')
    user_id = auth.e_get_user(username)['id']
    
    with db:
        sql = """
            SELECT * 
                FROM """ +db_prefix +"""user_data
                WHERE user_id = %s AND container = %s AND key_name LIKE %s AND hidden = %s;
        """
        
        try:
            dbc.execute(sql, [user_id, container_name, key_name, hidden])
            
        except MySQLdb.IntegrityError as e:
            api_log().error("e_get_data: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')
        
    return_array = {}
    for row in dbc.fetchall():
        return_array[row[2]] = json.loads(row[4])
    
    return return_array

@api_external_function(plugin)
def e_list_containers(username, hidden = 0):
    auth = api_plugins()['auth']
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    user_id = auth.e_get_user(username)['id']
    
    with db:
        sql = """
            SELECT container, COUNT(key_name) AS "count"
                FROM pa_user_data
                WHERE user_id = %s AND hidden = %s
                GROUP BY container;
        """
        
        try:
            dbc.execute(sql, [user_id, hidden])
            
        except MySQLdb.IntegrityError as e:
            api_log().error("e_list_containers: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')
        
    return_array = []
    for row in dbc.fetchall():
        return_array.append({
            'name': row[0],
            'count': row[1]
        })
    
    return return_array

@api_external_function(plugin)
def e_list_keys_of_container(username, container_name, hidden = 0):
    auth = api_plugins()['auth']
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    user_id = auth.e_get_user(username)['id']
    
    with db:
        sql = """
            SELECT key_name
                FROM pa_user_data
                WHERE user_id = %s and container = %s AND hidden = %s;
        """
        
        try:
            dbc.execute(sql, [user_id, container_name, hidden])
            
        except MySQLdb.IntegrityError as e:
            api_log().error("e_list_keys_of_container: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')
        
    return_array = []
    for row in dbc.fetchall():
        return_array.append(row[0])
    
    return return_array

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

@api_event(plugin, 'install')
def install():
    
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    api_log().info("Create new Tables...")
    
    sql = """
        CREATE TABLE """ +db_prefix +"""user_data (
            user_id INT NOT NULL,
            container VARCHAR(64) NOT NULL,
            key_name VARCHAR(64) NOT NULL,
            hidden BOOLEAN NOT NULL,
            data TEXT NOT NULL,
            PRIMARY KEY (user_id, container, key_name)
        ) ENGINE = InnoDB;
        """
    dbc.execute(sql)
    api_log().debug("Table: '" +db_prefix +"user_data' created.")
    
    sql = """
        ALTER TABLE """ +db_prefix +"""user_data
            ADD CONSTRAINT """ +db_prefix +"""user_data_to_user
            FOREIGN KEY ( user_id )
            REFERENCES """ +db_prefix +"""user ( id )
            ON DELETE CASCADE
            ON UPDATE CASCADE;
        """
    dbc.execute(sql)
    dbc.close()
    
    auth = api_plugins()['auth']
    
    auth.e_create_role('userdata_default', {
        'permissions':  [
            'userdata.*'
        ]
    })
    
    ruleset = auth.e_get_role('default')['ruleset']
    
    try:
        if not 'userdata_default' in ruleset['inherit']:
            ruleset['inherit'].append('userdata_default')
            
        auth.e_edit_role('default', ruleset)
    except WebRequestException as e:
        api_log().error('Editing the default role failed!')
        return 0
    
    auth.e_create_role('userdata_admin', {
        plugin.name +'_permissions':  [
            'hidden_access'
        ]
    })
    
    ruleset = auth.e_get_role('admin')['ruleset']
    
    try:
        if not 'userdata_admin' in ruleset['inherit']:
            ruleset['inherit'].append('userdata_admin')
            
        auth.e_edit_role('admin', ruleset)
    except WebRequestException as e:
        api_log().error('Editing the admin role failed!')
        return 0
    
    return 1

@api_event(plugin, 'uninstall')
def uninstall():
    
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    auth = api_plugins()['auth']
    
    if auth.events['check']():
        ruleset = auth.e_get_role('default')['ruleset']
        
        try:
            ruleset['inherit'].remove('userdata_default')
            auth.e_edit_role('default', ruleset)
        except: pass
        
        try:
            auth.e_delete_role('userdata_default')
        except: pass

        api_log().debug('Ruleset deleted.')
    
    api_log().info("Delete old Tables...")
    
    for table in reversed(used_tables):
        sql = "DROP TABLE " +db_prefix +table +";"
        
        try: dbc.execute(sql)
        except MySQLdb.Error: continue
    
        api_log().debug("Table: '" +db_prefix +table +"' deleted.")
    
    dbc.close()
    return 1

@api_action(plugin, {
    'path': 'list',
    'method': 'GET',
    'f_name': {
        'EN': 'List containers',
        'DE': 'Container auflisten'
    },

    'f_description': {
        'EN': 'Lists all available containers.',
        'DE': 'Listet alle verfügbaren Container auf.'
    }
})
def list_containers(reqHandler, p, args, body):
    auth = api_plugins()['auth']
    current_user = auth.e_get_current_user()
    
    hidden = 0
    if 'hidden' in args and args['hidden'][0].decode("utf-8") == 'true':
        if auth.e_check_custom_permissions(current_user, plugin.name +'_permissions', 'hidden_access'):
            hidden = 1
        
        else:
            raise WebRequestException(401, 'unauthorized', 'AUTH_PERMISSIONS_DENIED')
    
    return {
        'data': e_list_containers(current_user, hidden)
    }

@api_action(plugin, {
    'path': '*/list',
    'method': 'GET',
    'f_name': {
        'EN': 'List keys of container',
        'DE': 'Liste Schlüssel von Container auf'
    },

    'f_description': {
        'EN': 'Lists all available keys in a container.',
        'DE': 'Listet alle verfügbaren Schlüssel eines Containers auf.'
    }
})
def list_keys_of_container(reqHandler, p, args, body):
    auth = api_plugins()['auth']
    current_user = auth.e_get_current_user()
    
    hidden = 0
    if 'hidden' in args and args['hidden'][0].decode("utf-8") == 'true':
        if auth.e_check_custom_permissions(current_user, plugin.name +'_permissions', 'hidden_access'):
            hidden = 1
        
        else:
            raise WebRequestException(401, 'unauthorized', 'AUTH_PERMISSIONS_DENIED')
    
    return {
        'data': e_list_keys_of_container(current_user, p[0], hidden)
    }

@api_action(plugin, {
    'path': '*/*',
    'method': 'GET',
    'f_name': {
        'EN': 'Get data',
        'DE': 'Zeige Datensatz'
    },

    'f_description': {
        'EN': 'Read data in a container.',
        'DE': 'Liest Datensätze aus einem Container.'
    }
})
def get_data(reqHandler, p, args, body):
    auth = api_plugins()['auth']
    current_user = auth.e_get_current_user()
    
    hidden = 0
    if 'hidden' in args and args['hidden'][0].decode("utf-8") == 'true':
        if auth.e_check_custom_permissions(current_user, plugin.name +'_permissions', 'hidden_access'):
            hidden = 1
        
        else:
            raise WebRequestException(401, 'unauthorized', 'AUTH_PERMISSIONS_DENIED')
    
    return {
        'data': e_get_data(current_user, p[0], p[1], hidden)
    }

@api_action(plugin, {
    'path': '*',
    'method': 'POST',
    'f_name': {
        'EN': 'Write data',
        'DE': 'Schreibe Daten'
    },

    'f_description': {
        'EN': 'Write data in a container.',
        'DE': 'Schreibt Daten in einen Container.'
    }
})
def write_data(reqHandler, p, args, body):
    auth = api_plugins()['auth']
    current_user = auth.e_get_current_user()
    
    if body == {}:
        raise WebRequestException(400,'error','write_data: Post body empty.')
    
    hidden = 0
    if 'hidden' in args and args['hidden'][0].decode("utf-8") == 'true':
        if auth.e_check_custom_permissions(current_user, plugin.name +'_permissions', 'hidden_access'):
            hidden = 1
        
        else:
            raise WebRequestException(401, 'unauthorized', 'AUTH_PERMISSIONS_DENIED')
    
    return {
        'affected_rows': e_write_data(current_user, p[0], body, hidden)
    }

@api_action(plugin, {
    'path': '*/*',
    'method': 'DELETE',
    'f_name': {
        'EN': 'Delete data',
        'DE': 'Lösche Daten'
    },

    'f_description': {
        'EN': 'Deletes data in a container.',
        'DE': 'Löscht Daten aus einem Container.'
    }
})
def delete_data(reqHandler, p, args, body):
    auth = api_plugins()['auth']
    current_user = auth.e_get_current_user()
    
    hidden = 0
    if 'hidden' in args and args['hidden'][0].decode("utf-8") == 'true':
        if auth.e_check_custom_permissions(current_user, plugin.name +'_permissions', 'hidden_access'):
            hidden = 1
        
        else:
            raise WebRequestException(401, 'unauthorized', 'AUTH_PERMISSIONS_DENIED')
    
    return {
        'affected_rows': e_delete_data(current_user, p[0], p[1], hidden)
    }
