#!/usr/bin/python
#
# Name:        pythapi: userdata.py
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
#              You should have received a copy of the GNU General Public License
#              along with this program.  If not, see https://www.gnu.org/licenses/agpl-3.0.de.html.
#

import sys
sys.path.append("..")
import tools.fancy_logs as log # Logging
import MySQLdb # MySQL
from api_plugin import * # Essential Plugin
import json

plugin = api_plugin()
plugin.name = "userdata"
plugin.version = "1.0"
plugin.essential = False
plugin.info['f_name'] = "User data"
plugin.info['f_description'] = "This plugin allows to save userspecific data, based on a key-value store."

plugin.depends = [
    {
        'name': 'auth',
        'required': True
    }
]

plugin.config_defaults = {
    plugin.name: {
        'cache_enabled': True
    }
}

used_tables = ["user_data"]

@api_external_function(plugin)
def e_write_data(username, container_name, data):
    auth = plugin.all_plugins['auth']
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    user_id = auth.e_get_user(username)['id']
    
    values_skeleton_list = []
    data_list = []
    for key_name in data:
        values_skeleton_list.append('(%s, %s, %s, %s)')
        data_list.append(user_id)
        data_list.append(container_name)
        data_list.append(key_name)
        data_list.append(json.dumps(data[key_name]))
        
    values_skeleton = ','.join(values_skeleton_list)
    
    with db:
        sql = """
            INSERT INTO """ +plugin.db_prefix +"""user_data (
                    user_id, container, key_name, data
                )
                VALUES """ +values_skeleton +"""
                ON DUPLICATE KEY
                UPDATE data = VALUES (data);
        """
        
        try:
            dbc.execute(sql, data_list)
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            raise WebRequestException(501,'error','i_write_db_data: Unknown SQL error.')
    
        return dbc.rowcount

@api_external_function(plugin)
def e_delete_data(username, container_name, key_name):
    auth = plugin.all_plugins['auth']
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    key_name = key_name.replace('*', '%')
    user_id = auth.e_get_user(username)['id']

    with db:
        sql = """
            DELETE FROM """ +plugin.db_prefix +"""user_data 
                WHERE user_id = %s AND container = %s AND key_name LIKE %s;
        """
        
        try:
            dbc.execute(sql, [user_id, container_name, key_name])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            raise WebRequestException(501,'error','i_write_db_data: Unknown SQL error.')
        
        return dbc.rowcount

@api_external_function(plugin)
def e_get_data(username, container_name, key_name):
    auth = plugin.all_plugins['auth']
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    key_name = key_name.replace('*', '%')
    user_id = auth.e_get_user(username)['id']
    
    with db:
        sql = """
            SELECT * 
                FROM """ +plugin.db_prefix +"""user_data
                WHERE user_id = %s AND container = %s AND key_name LIKE %s;
        """
        
        try:
            dbc.execute(sql, [user_id, container_name, key_name])
            
        except MySQLdb.IntegrityError as e:
            log.error("i_get_db_data: Unknown SQL error.")
            raise WebRequestException(501,'error','i_get_db_data: Unknown SQL error.')
        
    return_array = {}
    for row in dbc.fetchall():
        return_array[row[2]] = json.loads(row[3])
    
    return return_array

@api_external_function(plugin)
def e_list_containers(username):
    auth = plugin.all_plugins['auth']
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    user_id = auth.e_get_user(username)['id']
    
    with db:
        sql = """
            SELECT container, COUNT(key_name) AS "count"
                FROM pa_user_data
                WHERE user_id = %s
                GROUP BY container;
        """
        
        try:
            dbc.execute(sql, [user_id])
            
        except MySQLdb.IntegrityError as e:
            log.error("i_list_db_containers: Unknown SQL error.")
            raise WebRequestException(501,'error','i_list_db_containers: Unknown SQL error.')
        
    return_array = []
    for row in dbc.fetchall():
        return_array.append({
            'name': row[0],
            'count': row[1]
        })
    
    return return_array

@api_external_function(plugin)
def e_list_keys_of_container(username, container_name):
    auth = plugin.all_plugins['auth']
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    user_id = auth.e_get_user(username)['id']
    
    with db:
        sql = """
            SELECT key_name
                FROM pa_user_data
                WHERE user_id = %s and container = %s;
        """
        
        try:
            dbc.execute(sql, [user_id, container_name])
            
        except MySQLdb.IntegrityError as e:
            log.error("i_list_db_keys_of_container: Unknown SQL error.")
            raise WebRequestException(501,'error','i_list_db_keys_of_container: Unknown SQL error.')
        
    return_array = []
    for row in dbc.fetchall():
        return_array.append(row[0])
    
    return return_array

def i_dump_db_table():
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    with db:
        sql = """
            SELECT *
                FROM pa_user_data;
        """
        
        try:
            dbc.execute(sql)
            
        except MySQLdb.IntegrityError as e:
            log.error("i_dump_db_table: Unknown SQL error.")
            raise WebRequestException(501,'error','i_dump_db_table: Unknown SQL error.')
        
        return dbc.fetchall()

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

@api_event(plugin, 'install')
def install():
    
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    log.info("Create new Tables...")
    
    sql = """
        CREATE TABLE """ +plugin.db_prefix +"""user_data (
            user_id INT NOT NULL,
            container VARCHAR(64) NOT NULL,
            key_name VARCHAR(64) NOT NULL,
            data TEXT NOT NULL,
            PRIMARY KEY (user_id, container, key_name)
        ) ENGINE = InnoDB;
        """
    dbc.execute(sql)
    log.debug("Table: '" +plugin.db_prefix +"user_data' created.")
    
    sql = """
        ALTER TABLE """ +plugin.db_prefix +"""user_data
            ADD CONSTRAINT """ +plugin.db_prefix +"""user_data_to_user
            FOREIGN KEY ( user_id )
            REFERENCES """ +plugin.db_prefix +"""user ( id )
            ON DELETE CASCADE
            ON UPDATE CASCADE;
        """
    dbc.execute(sql)
    dbc.close()
    
    auth = plugin.all_plugins['auth']
    
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
        log.error('Editing the default role failed!')
        return 0
    
    return 1

@api_event(plugin, 'uninstall')
def uninstall():
    
    db = plugin.mysql_connect()
    dbc = db.cursor()
    
    auth = plugin.all_plugins['auth']
    
    if auth.events['check']():
        ruleset = auth.e_get_role('default')['ruleset']
        
        try:
            ruleset['inherit'].remove('userdata_default')
            auth.e_edit_role('default', ruleset)
        except: pass
        
        try:
            auth.e_delete_role('userdata_default')
        except: pass

        log.debug('Ruleset deleted.')
    
    log.info("Delete old Tables...")
    
    for table in reversed(used_tables):
        sql = "DROP TABLE " +plugin.db_prefix +table +";"
        
        try: dbc.execute(sql)
        except MySQLdb.Error: continue
    
        log.debug("Table: '" +plugin.db_prefix +table +"' deleted.")
    
    dbc.close()
    return 1

@api_action(plugin, {
    'path': 'list',
    'method': 'GET',
    'f_name': 'List containers',
    'f_description': 'Lists all available containers.'
})
def list_containers(reqHandler, p, body):
    auth = plugin.all_plugins['auth']
    
    return {
        'data': e_list_containers(auth.e_get_current_user())
    }

@api_action(plugin, {
    'path': '*/list',
    'method': 'GET',
    'f_name': 'List keys of container',
    'f_description': 'Lists all available keys in a container.'
})
def list_keys_of_container(reqHandler, p, body):
    auth = plugin.all_plugins['auth']
    
    return {
        'data': e_list_keys_of_container(auth.e_get_current_user(), p[0])
    }

@api_action(plugin, {
    'path': '*/*',
    'method': 'GET',
    'f_name': 'Get data',
    'f_description': 'Read data in a container.'
})
def get_data(reqHandler, p, body):
    auth = plugin.all_plugins['auth']
    
    return {
        'data': e_get_data(auth.e_get_current_user(), p[0], p[1])
    }

@api_action(plugin, {
    'path': '*',
    'method': 'POST',
    'f_name': 'Write data',
    'f_description': 'Write data in a container.'
})
def write_data(reqHandler, p, body):
    auth = plugin.all_plugins['auth']
    
    if body == {}:
        raise WebRequestException(400,'error','write_data: Post body empty.')
    
    return {
        'affected_rows': e_write_data(auth.e_get_current_user(), p[0], body)
    }

@api_action(plugin, {
    'path': '*/*',
    'method': 'DELETE',
    'f_name': 'Delete data',
    'f_description': 'Deletes data in a container.'
})
def delete_data(reqHandler, p, body):
    auth = plugin.all_plugins['auth']
    
    return {
        'affected_rows': e_delete_data(auth.e_get_current_user(), p[0], p[1])
    }
