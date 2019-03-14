#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: auth.py
# Author:      Rene Fa
# Date:        08.01.2019
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
import json
import copy

from .header import *
from . import rulesets

import datetime

@api_external_function(plugin)
def e_get_current_user():
    return auth_globals.current_user

@api_external_function(plugin)
def e_get_current_user_info():
    return_json = copy.deepcopy(e_get_user(auth_globals.current_user))
    return_json['auth_type'] = auth_globals.auth_type
    
    if auth_globals.auth_type == "token":
        token_data = auth_globals.user_token_dict[auth_globals.current_token]
        return_json['token_name'] = token_data['token_name']

        if not 'inherit' in token_data['ruleset'] or not '*' in token_data['ruleset']['inherit']:
            return_json['ruleset'] = token_data['ruleset']

    return return_json

def i_get_db_user(username):
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
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
    if not username in auth_globals.users_dict:
        raise WebRequestException(400, 'error', 'AUTH_USER_NOT_FOUND')
    
    return_json = dict(auth_globals.users_dict[username])
    return_json['username'] = username
    del return_json['token']
    del return_json['sessions']
    del return_json['h_password']
        
    return return_json

def i_list_local_users():
    return_json = []
    for key in auth_globals.users_dict:
        i_entry = dict(auth_globals.users_dict[key])
        i_entry['username'] = key
        del i_entry['token']
        del i_entry['sessions']
        del i_entry['h_password']
        
        return_json.append(i_entry)
        
    return return_json

@api_external_function(plugin)
def e_get_user(username):
    if auth_globals.write_through_cache_enabled:
        return i_local_get_user(username)
    
    else:
        row = i_get_db_user(username)
        
        return_json = {
            'id': row[0],
            'username': row[1],
            'type': row[2],
            'ruleset': json.loads(row[4]),
            'time_created': row[5],
            'time_modified': row[6]
        }
        
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
    if auth_globals.write_through_cache_enabled:
        return i_list_local_users()
    
    else:
        return_json = []
        for row in i_list_db_user():
            i_entry = {
                'id': row[0],
                'username': row[1],
                'type': row[2],
                'ruleset': json.loads(row[4]),
                'time_created': row[5],
                'time_modified': row[6]
            }

            return_json.append(i_entry)
        
        return return_json

@api_external_function(plugin)
def e_create_user(username, user_type, data):

    if username == 'list':
        raise WebRequestException(400, 'error', 'AUTH_EXECUTION_DENIED')

    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    if not 'password' in data:
        raise WebRequestException(400, 'error', 'AUTH_PASSWORD_MISSING')

    if not 'ruleset' in data:
        data['ruleset'] = {
            'inherit': [
                'default'
            ]
        }

    ruleset = data['ruleset']
    ruleset = rulesets.i_reduce_ruleset(ruleset)

    h_password = e_hash_password(username, data['password'])
    
    sql = """
        INSERT INTO """ +db_prefix +"""user (
                name, type, h_password, ruleset
            )
            VALUES (%s, %s, %s, %s);
    """
    
    try:
        dbc.execute(sql,[username, user_type, h_password, json.dumps(ruleset)])
        db.commit()
        
    except MySQLdb.IntegrityError as e:
        raise WebRequestException(400, 'error', 'AUTH_USER_EXISTS')
    
    db_result = i_get_db_user(username)
    
    if auth_globals.write_through_cache_enabled:
        auth_globals.users_dict[username] = {
            'id': db_result[0],
            'type': user_type,
            'h_password': h_password,
            'ruleset': ruleset,
            'token': [],
            'sessions': [],
            'time_created': db_result[5],
            'time_modified': db_result[6]
        }

        rulesets.i_apply_ruleset(username, 'u')
    
    return db_result[0]

@api_external_function(plugin)
def e_edit_user(username, data):

    if username == 'list':
        raise WebRequestException(400, 'error', 'AUTH_EXECUTION_DENIED')

    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()

    if auth_globals.write_through_cache_enabled:
        if username not in auth_globals.users_dict:
            raise WebRequestException(400, 'error', 'AUTH_USER_NOT_FOUND')

    else:
        i_get_db_user(username)

    if 'password' in data:
        h_password = e_hash_password(username, data['password'])
    
        sql = """
            UPDATE """ +db_prefix +"""user
                SET h_password = %s
                WHERE name = %s;
        """
        
        try:
            dbc.execute(sql,[h_password, username])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            api_log().error("e_edit_user: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')
        
        if auth_globals.write_through_cache_enabled:
            auth_globals.users_dict[username]['h_password'] = h_password

    if 'ruleset' in data:

        ruleset = data['ruleset']
        ruleset = rulesets.i_reduce_ruleset(ruleset)

        sql = """
            UPDATE """ +db_prefix +"""user
                SET ruleset = %s
                WHERE name = %s;
        """
        
        try:
            dbc.execute(sql,[json.dumps(ruleset), username])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            api_log().error("e_edit_user: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')

        if auth_globals.write_through_cache_enabled:
            auth_globals.users_dict[username]['time_modified'] = datetime.datetime.now()
            auth_globals.users_dict[username]['ruleset'] = ruleset

            rulesets.i_apply_ruleset(username, 'u')

        # After a change of the Ruleset, the Token rulesets have to be revalidated
        rulesets.evaluate_token_of_user(username)

@api_external_function(plugin)
def e_delete_user(username):

    if username in ['admin', 'anonymous', 'list']:
        raise WebRequestException(400, 'error', 'AUTH_EXECUTION_DENIED')

    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    if auth_globals.write_through_cache_enabled and not username in auth_globals.users_dict:
        raise WebRequestException(400, 'error', 'AUTH_USER_NOT_FOUND')
    
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

    if auth_globals.write_through_cache_enabled:
        rulesets.i_apply_ruleset(username, 'u', delete_only=True)

        for i in range(len(auth_globals.users_dict[username]['token'])):
            key = auth_globals.users_dict[username]['token'][i]
            del auth_globals.user_token_dict[key]
        
        for i in range(len(auth_globals.users_dict[username]['sessions'])):
            key = auth_globals.users_dict[username]['sessions'][i]
            del auth_globals.session_dict[key]
        
        del auth_globals.users_dict[username]

@api_action(plugin, {
    'path': 'whoami',
    'method': 'GET',
    'permission': 'user.get.self',
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
    'path': 'user/list',
    'method': 'GET',
    'permission': 'user.get.all',
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
            'data': list(auth_globals.users_dict.keys())
        }

@api_action(plugin, {
    'path': 'user/change_password',
    'method': 'PUT',
    'permission': 'user.edit.self.password',
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
    
    e_edit_user(auth_globals.current_user, {'password': body['password']})
    return {}

@api_action(plugin, {
    'path': 'user/*',
    'method': 'GET',
    'permission': 'user.get',
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
    'permission': 'user.create',
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
        'ruleset': {
            'type': dict,
            'f_name': {
                'EN': "Ruleset",
                'DE': "Regelsatz"
            },
            'default': {}
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
        
    return {
        'id': str(e_create_user(p[0], 'default', body))
    }

@api_action(plugin, {
    'path': 'user/*',
    'method': 'PUT',
    'permission': 'user.edit',
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
        'EN': 'Edit user',
        'DE': 'Benutzer editieren'
    },

    'f_description': {
        'EN': 'Edit the properties of a user.',
        'DE': 'Editiert die Eigenschaften eines Benutzers.'
    }
})
def edit_user(reqHandler, p, args, body):
        
    e_edit_user(p[0], body)
    return {}

@api_action(plugin, {
    'path': 'user/*',
    'method': 'DELETE',
    'permission': 'user.delete',
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
    
    e_delete_user(p[0])
    return {}
