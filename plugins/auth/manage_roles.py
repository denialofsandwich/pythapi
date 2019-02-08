#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: auth.py
# Author:      Rene Fa
# Date:        10.01.2019
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
from . import manage_users

import datetime

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
    if not role_name in auth_globals.roles_dict:
        raise WebRequestException(400, 'error', 'AUTH_ROLE_NOT_FOUND')

    return dict(auth_globals.roles_dict[role_name])

def e_list_local_roles():
    return_json = []
    
    for key in auth_globals.roles_dict:
        i_entry = dict(auth_globals.roles_dict[key])
        i_entry['role_name'] = key
        return_json.append(i_entry)
    
    return return_json

@api_external_function(plugin)
def e_get_role(role_name):
    if auth_globals.write_through_cache_enabled:
        return i_get_local_role(role_name)
    
    else:
        row = i_get_db_role(role_name)
        
        return_json = {
            'id': row[0],
            'ruleset': json.loads(row[2]),
            'time_created': row[3],
            'time_modified': row[4]
        }
        
        return return_json

@api_external_function(plugin)
def e_list_roles():
    if auth_globals.write_through_cache_enabled:
        return e_list_local_roles()
    
    else:
        return_json = []
        for row in i_list_db_roles():
            i_entry = {
                'id': row[0],
                'role_name': row[1],
                'ruleset': json.loads(row[2]),
                'time_created': row[3],
                'time_modified': row[4]
            }

            return_json.append(i_entry)
        
        return return_json

@api_external_function(plugin)
def e_create_role(role_name, ruleset):

    if role_name == 'list':
        raise WebRequestException(400, 'error', 'AUTH_EXECUTION_DENIED')

    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    ruleset = rulesets.i_reduce_ruleset(ruleset)

    with db:
        sql = """
            INSERT INTO """ +db_prefix +"""role (
                    name, ruleset
                )
                VALUES (%s, %s);
        """
        
        try:
            dbc.execute(sql,[role_name, json.dumps(ruleset)])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            raise WebRequestException(400, 'error', 'AUTH_ROLE_EXISTS')
    
    db_result = i_get_db_role(role_name)
    
    if auth_globals.write_through_cache_enabled:
        auth_globals.roles_dict[role_name] = {
            'id': db_result[0],
            'ruleset': ruleset,
            'time_created': db_result[3],
            'time_modified': db_result[4]
        }
        
        rulesets.i_apply_ruleset(role_name, 'r')
    
    return db_result[0]

def i_edit_db_role(role_name, ruleset):
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    with db:
        sql = """
            UPDATE """ +db_prefix +"""role
                SET ruleset = %s
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

    if role_name == 'list':
        raise WebRequestException(400, 'error', 'AUTH_EXECUTION_DENIED')

    if auth_globals.write_through_cache_enabled:
        if not role_name in auth_globals.roles_dict:
            raise WebRequestException(400, 'error', 'AUTH_ROLE_NOT_FOUND')
        
        auth_globals.roles_dict[role_name]['ruleset'] = ruleset
    
    else:
        i_get_db_role(role_name)
    
    ruleset = rulesets.i_reduce_ruleset(ruleset)

    i_edit_db_role(role_name, ruleset)

    if auth_globals.write_through_cache_enabled:
        auth_globals.roles_dict[role_name]['time_modified'] = datetime.datetime.now()
        rulesets.i_apply_ruleset(role_name, 'r')

    rulesets.evalueate_token_of_all_users()

def i_delete_db_role(role_name):
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
            api_log().error("i_delete_db_role: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')

@api_external_function(plugin)
def e_delete_role(role_name):
    
    if role_name in ['admin', 'anonymous', 'default', 'list']:
        raise WebRequestException(400, 'error', 'AUTH_EXECUTION_DENIED')

    if auth_globals.write_through_cache_enabled:
        if not role_name in auth_globals.roles_dict:
            raise WebRequestException(400, 'error', 'AUTH_ROLE_NOT_FOUND')

    else:
        i_get_db_role(role_name)
        
    i_delete_db_role(role_name)
    
    if auth_globals.write_through_cache_enabled:
        for user in auth_globals.users_dict:
            try: auth_globals.users_dict[user]['ruleset']['inherit'].remove(role_name)
            except: pass
        
        del auth_globals.roles_dict[role_name]
        
        rulesets.i_apply_ruleset(role_name, 'r')

@api_external_function(plugin)
def e_add_role_to_user(username, role_name):

    # To check if role exists
    e_get_role(role_name)

    ruleset = copy.deepcopy(manage_users.e_get_user(username))['ruleset']

    if role_name in ruleset['inherit']:
        raise WebRequestException(400, 'error', 'AUTH_USER_IS_MEMBER')

    ruleset['inherit'].append(role_name)
    manage_users.e_edit_user(username, {'ruleset': ruleset})

@api_external_function(plugin)
def e_remove_role_from_user(username, role_name):

    # To check if role exists
    e_get_role(role_name)

    ruleset = copy.deepcopy(manage_users.e_get_user(username))['ruleset']

    try:
        ruleset['inherit'].remove(role_name)
    except:
        raise WebRequestException(400, 'error', 'AUTH_USER_IS_NOT_MEMBER')

    manage_users.e_edit_user(username, {'ruleset': ruleset})

@api_action(plugin, {
    'path': 'role/list',
    'method': 'GET',
    'permission': 'role.get.all',
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
            'data': list(auth_globals.roles_dict.keys())
        }

@api_action(plugin, {
    'path': 'role/*',
    'method': 'GET',
    'permission': 'role.get',
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
    'permission': 'role.create',
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
        
    return {
        'id': str(e_create_role(p[0], body))
    }

@api_action(plugin, {
    'path': 'role/*',
    'method': 'PUT',
    'permission': 'role.edit',
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
        
    e_edit_role(p[0], body)
    return {}

@api_action(plugin, {
    'path': 'role/*',
    'method': 'DELETE',
    'permission': 'role.delete',
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

    e_delete_role(p[0])
    return {}

@api_action(plugin, {
    'path': 'role/*/*',
    'method': 'POST',
    'permission': 'user.role.add',
    'params': [
        {
            'name': "username",
            'type': str,
            'regex': r'^[a-zA-Z0-9_-]{1,31}$',
            'f_name': {
                'EN': "Username",
                'DE': "Benutzername"
            }
        },
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
        'EN': 'Add role to user',
        'DE': 'Füge Benutzer eine Rolle hinzu'
    },

    'f_description': {
        'EN': 'Adds an addidional role to a user.',
        'DE': 'Weist einem Benutzer eine zusätzliche Rolle zu.'
    }
})
def add_member_to_role(reqHandler, p, args, body):
    
    e_add_role_to_user(p[0], p[1])
    return {}

@api_action(plugin, {
    'path': 'role/*/*',
    'method': 'DELETE',
    'permission': 'user.role.remove',
    'params': [
        {
            'name': "username",
            'type': str,
            'regex': r'^[a-zA-Z0-9_-]{1,31}$',
            'f_name': {
                'EN': "Username",
                'DE': "Benutzername"
            }
        },
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
        'EN': 'Remove role from user',
        'DE': 'Entferne Rolle von Benutzer'
    },

    'f_description': {
        'EN': 'Removes a role from a user.',
        'DE': 'Entfernt eine Rolle von einem Benutzer.'
    }
})
def remove_member_from_role(reqHandler, p, args, body):

    e_remove_role_from_user(p[0], p[1])
    return {}
