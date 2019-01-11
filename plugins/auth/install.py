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
import MySQLdb

from .header import *

used_tables = ["user","token","role"]

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
    
    with db:
        sql = """
            CREATE TABLE """ +db_prefix +"""user (
                id INT NOT NULL AUTO_INCREMENT,
                name VARCHAR(32) NOT NULL,
                type VARCHAR(8) NOT NULL DEFAULT 'default',
                h_password VARCHAR(64) NOT NULL,
                ruleset TEXT NOT NULL,
                time_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                time_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                PRIMARY KEY( id ),
                UNIQUE ( name )
            ) ENGINE = InnoDB;
            """
        dbc.execute(sql)
        api_log().debug("Table '" +db_prefix +"user' created.")

        sql = """
            CREATE TABLE """ +db_prefix +"""role (
                id INT NOT NULL AUTO_INCREMENT,
                name VARCHAR(32) NOT NULL,
                ruleset TEXT NOT NULL,
                time_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                time_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                PRIMARY KEY (id),
                UNIQUE (name)
            ) ENGINE = InnoDB;
            """
        dbc.execute(sql)
        api_log().debug("Table '" +db_prefix +"role' created.")
        
        sql = """
            CREATE TABLE """ +db_prefix +"""token (
                id INT NOT NULL AUTO_INCREMENT,
                token_name VARCHAR(32) NOT NULL,
                user_id INT NOT NULL,
                h_token VARCHAR(64) NOT NULL,
                ruleset TEXT NOT NULL,
                time_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                time_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                PRIMARY KEY (id),
                UNIQUE (token_name, user_id)
            ) ENGINE = InnoDB;
            """
        dbc.execute(sql)
        api_log().debug("Table '" +db_prefix +"token' created.")
        
        sql = """
            ALTER TABLE """ +db_prefix +"""token
                ADD CONSTRAINT """ +db_prefix +"""token_to_user
                FOREIGN KEY ( user_id )
                REFERENCES """ +db_prefix +"""user ( id )
                ON DELETE CASCADE
                ON UPDATE CASCADE;
            """
        dbc.execute(sql)
        api_log().debug("Constraints created.")
    
#    e_create_role('admin', {
#        "permissions":  [
#            "*"
#        ]
#    })
#    
#    e_create_role('auth_default', {
#        "permissions":  [
#            "auth.list_sessions",
#            "auth.create_session",
#            "auth.delete_session",
#            "auth.delete_all_sessions",
#            
#            "auth.get_user_token",
#            "auth.list_user_tokens",
#            "auth.create_user_token",
#            "auth.edit_user_token",
#            "auth.delete_user_token",
#            
#            "auth.change_password",
#            "auth.get_permissions",
#            "auth.get_current_user"
#        ]
#    })
#    
#    e_create_role('anonymous', {
#        "permissions":  []
#    })
#    
#    e_create_role('default', {
#        "inherit":  [
#            "anonymous",
#            "auth_default"
#        ],
#        "permissions": []
#    })
#    
#    if api_config()['auth']['first_user_password'] != "":
#        password = api_config()['auth']['first_user_password']
#    else:
#        password = getpass.getpass('Enter new admin password: ')
#
#    e_create_user('admin', {
#        'password': password
#    })
#    
#    e_create_user('anonymous', {
#        'password': e_generate_random_string(cookie_length)
#    })
#    
#    e_remove_member_from_role('default', 'admin')
#    e_add_member_to_role('admin', 'admin')
#    
#    e_remove_member_from_role('default', 'anonymous')
#    e_add_member_to_role('anonymous', 'anonymous')
    
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

