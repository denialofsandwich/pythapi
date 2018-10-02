#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: data.py
# Author:      Rene Fa
# Date:        13.04.2018
# Version:     0.4
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
import re
import os

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

def ir_serialize_data_tree(root, data_dict):
    insert_data = []
    delete_data = []

    for key, value in data_dict.items():
        if key.find('/') != -1:
            raise WebRequestException(400, 'error', 'DATA_ILLEGAL_CHARACTER_FOUND')

        path = os.path.join(root, key)
        
        if type(value) == dict:
            delete_data.append(path)

            new_insert_data, new_delete_data = ir_serialize_data_tree(path, value)

            insert_data.extend(new_insert_data)
            delete_data.extend(new_delete_data)

        else:
            delete_data.append(os.path.join(path, '%'))

            insert_data.append(path)
            insert_data.append(json.dumps(value))

            if path[:6] == '/user/':
                username = path[6:(path[6:].find('/')+6)]
                auth = api_plugins()['auth']
                user_id = auth.e_get_user(username)['id']

                insert_data.append(user_id)

            else:
                insert_data.append(1) # Admin

    return insert_data, delete_data

@api_external_function(plugin)
def e_read_data(path):
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()

    dbc = db.cursor()
    result = dbc.execute("""
            SELECT *
                FROM """ +db_prefix +"""data
                WHERE key_name = %s OR key_name LIKE %s;
        """, [path, os.path.join(path, '%')])

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
        CREATE TABLE """ +db_prefix +"""data (
            key_name VARCHAR(256) NOT NULL,
            user_id INT NOT NULL,
            data TEXT NOT NULL,
            PRIMARY KEY (key_name)
        ) ENGINE = InnoDB;
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
        except MySQLdb.Error: continue
    
        api_log().debug("Table: '" +db_prefix +table +"' deleted.")
    
    dbc.close()
    return 1

@api_action(plugin, {
    'regex': r'^' +re.escape(plugin.name) +r'(/.*)$',
    'method': 'GET',
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
    return {
        'data': e_read_data(p[0])
    }

@api_action(plugin, {
    'regex': r'^' +re.escape(plugin.name) +r'(/.*)$',
    'method': 'POST',
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
    return {
        'affected_rows': e_write_data(p[0], body)
    }

@api_action(plugin, {
    'regex': r'^' +re.escape(plugin.name) +r'(/.*)$',
    'method': 'DELETE',
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
    return {
        'affected_rows': e_delete_data(p[0])
    }
