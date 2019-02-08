#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: info.py
# Author:      Rene Fa
# Date:        10.07.2018
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
import copy

plugin = api_plugin()
plugin.name = "info"
plugin.version = "1.0"
plugin.essential = False
plugin.info['f_name'] = {
    'EN': 'Information'
}

plugin.info['f_description'] = {
    'EN': 'This plugin allows to view the description and meta-informations of an action and plugins itself.',
    'DE': 'Dieses Plugin erlaubt es die Beschreibung und Meta-Informationen von Actions und Plugins einzusehen.'
}

plugin.depends = [
    {
        'name': 'auth',
        'required': False
    }
]

plugin.config_defaults = {
    plugin.name: {
        'action_property_blacklist': [],
        'plugin_property_blacklist': [],
        'hide_prohibited_actions': True
    }
}

plugin.translation_dict = {
    'INFO_PLUGIN_NOT_FOUND': {
        'EN': 'Plugin not found.',
        'DE': 'Plugin nicht gefunden.'
    },
    
    'INFO_ACTION_NOT_FOUND': {
        'EN': 'Action not found.',
        'DE': 'Action nicht gefunden.'
    }
}

action_property_blacklist = []
plugin_property_blacklist = []

def i_format_formatted_properties(return_json, property_name):
    
    try:
        translated_text = return_json[property_name][api_environment_variables()['language']]
    
    except:
        try:
            translated_text = return_json[property_name][api_config()['core.general']['default_language']]
            
        except:
            try:
                translated_text = return_json[property_name]['EN']
            
            except:
                translated_text = 'N/A'
    
    return_json[property_name] = translated_text

def ir_format_properties(return_json):
    for property_name in return_json:
        if type(return_json[property_name]) == dict:
            ir_format_properties(return_json[property_name])
            
        elif type(return_json[property_name]) == list:
            for item in return_json[property_name]:
                if type(item) == dict:
                    ir_format_properties(item)

        elif type(return_json[property_name]) == type:
            return_json[property_name] = return_json[property_name].__name__

        if property_name[:2] == 'f_':
            i_format_formatted_properties(return_json, property_name)

def i_format_action(action):
    
    if 'auth' in api_plugins():
        auth = api_plugins()['auth']
        current_user = auth.e_get_current_user()
        
        if auth.e_check_custom_permissions_of_current_user('permissions', action['permission']):
            action['permitted'] = True
        
        else:
            action['permitted'] = False
    
    for property_name in action_property_blacklist:
        try: del action[property_name]
        except: pass

    ir_format_properties(action)

    return action

def i_get_plugin(plugin_name):
    
    if not plugin_name in api_plugins():
        raise WebRequestException(400,'error','i_get_plugin: Plugin not found.')
    
    i_plugin = api_plugins()[plugin_name]
    
    return_json = {}
    return_json['name'] = i_plugin.name
    return_json['version'] = i_plugin.version
    return_json['essential'] = i_plugin.essential
    return_json['depends'] = i_plugin.depends
    return_json['action_count'] = len(i_plugin.actions)
    return_json['events'] = list(i_plugin.events.keys())
    return_json.update(i_plugin.info)
    
    for property_name in plugin_property_blacklist:
        try: del return_json[property_name]
        except: pass
    
    for property_name in return_json:
        if property_name[:2] == 'f_':
            i_format_formatted_properties(return_json, property_name)
    
    return return_json

def i_list_plugins():
    
    return_json = []
    for plugin_name in api_plugins():
        return_json.append(i_get_plugin(plugin_name))
        
    return return_json

def i_get_action_of_plugin(plugin_name, action_name):

    if not plugin_name in api_action_tree():
        raise WebRequestException(400, 'error', 'INFO_PLUGIN_NOT_FOUND')
    
    if not action_name in api_action_tree()[plugin_name]:
        raise WebRequestException(400, 'error', 'INFO_ACTION_NOT_FOUND')
    
    action = dict(api_action_tree()[plugin_name][action_name])

    if 'auth' in api_plugins():
        auth = api_plugins()['auth']
        current_user = auth.e_get_current_user()
        
        if (api_config()[plugin.name]['hide_prohibited_actions'] and
            not auth.e_check_custom_permissions_of_current_user('permissions', action['permission'])):
            raise WebRequestException(401, 'unauthorized', 'AUTH_PERMISSIONS_DENIED')

    del action['func']
    del action['c_regex']
        
    return i_format_action(copy.deepcopy(action))

def i_list_actions_of_plugin(plugin_name):
    
    if not plugin_name in api_plugins():
        raise WebRequestException(400, 'error', 'INFO_PLUGIN_NOT_FOUND')
    
    return_json = []
    for i_action in api_plugins()[plugin_name].actions:
        
        if 'auth' in api_plugins():
            auth = api_plugins()['auth']
            current_user = auth.e_get_current_user()
            
            if (api_config()[plugin.name]['hide_prohibited_actions'] and
                not auth.e_check_custom_permissions_of_current_user('permissions', i_action['permission'])):
                continue
        
        tmp_action = dict(i_action)
        del tmp_action['func']
        del tmp_action['c_regex']
        
        return_json.append(i_format_action(copy.deepcopy(tmp_action)))
        
    return return_json

def i_get_action_by_path(method, path):

    for action in api_action_call_dict()[method]:
            if action['c_regex'].match(path):
                return i_format_action(action)

@api_event(plugin, 'install')
def install():
    
    if 'auth' in api_plugins():
        api_log().info('auth installed. Apply ruleset...')
        
        auth = api_plugins()['auth']
        
        auth.e_create_role('info_default', {
            'permissions':  [
                'info.*'
            ]
        })
        
        ruleset = auth.e_get_role('default')['ruleset']
        
        try:
            if not 'info_default' in ruleset['inherit']:
                ruleset['inherit'].append('info_default')
                
            auth.e_edit_role('default', ruleset)
        except WebRequestException as e:
            api_log().error('Editing the default role failed!')
            return 0
    
    return 1

@api_event(plugin, 'uninstall')
def uninstall():
    
    if 'auth' in api_plugins() and api_plugins()['auth'].events['check']():
        
        auth = api_plugins()['auth']
        
        ruleset = auth.e_get_role('default')['ruleset']
        
        try:
            ruleset['inherit'].remove('info_default')
            auth.e_edit_role('default', ruleset)
        except: pass
        
        try:
            auth.e_delete_role('info_default')
        except: pass
    
        api_log().debug('Ruleset deleted.')
    
    return 1

@api_event(plugin, 'load')
def load():
    global action_property_blacklist
    global plugin_property_blacklist

    action_property_blacklist.extend(api_config()[plugin.name]['action_property_blacklist'])
    plugin_property_blacklist.extend(api_config()[plugin.name]['plugin_property_blacklist'])

    action_property_blacklist.extend(['token','users'])
    action_property_blacklist = list(set(action_property_blacklist))
    return 1

@api_action(plugin, {
    'path': 'list',
    'method': 'GET',
    'permission': 'plugin.get.all',
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
        'EN': 'List plugins',
        'DE': 'Zeige alle Plugins'
    },

    'f_description': {
        'EN': 'Returns a list of all enabled plugins.',
        'DE': 'Gibt eine Liste mit allen Plugins zurück.'
    }
})
def list_plugins(reqHandler, p, args, body):
    
    if args['verbose']:
        return {
            'data': i_list_plugins()
        }
    
    else:
        return {
            'data': list(api_plugins().keys())
        }

@api_action(plugin, {
    'path': '*',
    'method': 'GET',
    'permission': 'plugin.get',
    'params': [
        {
            'name': "plugin_name",
            'type': str,
            'f_name': {
                'EN': "Plugin name",
                'DE': "Plugin Name"
            }
        }
    ],
    'f_name': {
        'EN': 'Get plugin',
        'DE': 'Zeige Plugin'
    },

    'f_description': {
        'EN': 'Returns a single plugin.',
        'DE': 'Gibt ein einzelnes Plugin zurück.'
    }
})
def get_plugin(reqHandler, p, args, body):
    return {
        'data': i_get_plugin(p[0])
    }

@api_action(plugin, {
    'path': '*/list',
    'method': 'GET',
    'permission': 'action.get.all',
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
    'params': [
        {
            'name': "plugin_name",
            'type': str,
            'f_name': {
                'EN': "Plugin name",
                'DE': "Plugin Name"
            }
        }
    ],
    'f_name': {
        'EN': 'List actions of plugin',
        'DE': 'Zeige alle Actions eines Plugin'
    },

    'f_description': {
        'EN': 'Returns a list of all actions from a specific plugin.',
        'DE': 'Gibt eine Liste mit allen Actions eines bestimmten Plugins zurück.'
    }
})
def list_actions_of_plugin(reqHandler, p, args, body):

    full_action_list = i_list_actions_of_plugin(p[0])
    
    if args['verbose']:
        return {
            'data': full_action_list
        }
    
    else:
        action_name_list = []
        for action_name in full_action_list:
            action_name_list.append(action_name['name'])
        
        return {
            'data': action_name_list
        }

@api_action(plugin, {
    'path': '*/*',
    'method': 'GET',
    'permission': 'action.get',
    'params': [
        {
            'name': "plugin_name",
            'type': str,
            'f_name': {
                'EN': "Plugin name",
                'DE': "Plugin Name"
            }
        },
        {
            'name': "action_name",
            'type': str,
            'f_name': {
                'EN': "Action name",
                'DE': "Action Name"
            }
        }
    ],
    'f_name': {
        'EN': 'Get action of plugin',
        'DE': 'Zeige Action eines Plugin'
    },

    'f_description': {
        'EN': 'Returns a single action from a plugin.',
        'DE': 'Gibt eine einzelne Action eines Plugin zurück.'
    }
})
def get_action_of_plugin(reqHandler, p, args, body):
    return {
        'data': i_get_action_of_plugin(p[0], p[1])
    }

@api_action(plugin, {
    'regex': '^' +plugin.name +'/search/([^/]*)/(.*)$',
    'method': 'GET',
    'permission': 'action.get.by_path',
    'params': [
        {
            'name': "method",
            'type': str,
            'f_name': {
                'EN': "Method",
                'DE': "Methode"
            }
        },
        {
            'name': "path",
            'type': str,
            'f_name': {
                'EN': "Path",
                'DE': "Pfad"
            }
        }
    ],
    'f_name': {
        'EN': 'Search action by path',
        'DE': 'Suche Action mittels Pfad'
    },

    'f_description': {
        'EN': 'Search an action by path.',
        'DE': 'Sucht eine Action anhand eines Pfades.'
    }
})
def get_action_by_path(reqHandler, p, args, body):
    return {
        'data': i_get_action_by_path(p[0], p[1])
    }

@api_action(plugin, {
    'regex': '^' +plugin.name,
    'method': 'GET',
    'permission': 'get',
    'f_name': {
        'EN': 'Get basic informations',
        'DE': 'Zeige Basisinformationen'
    },

    'f_description': {
        'EN': 'Shows basic informations about this API and basic requests to work with pythapi.',
        'DE': 'Zeigt grundlegende Informationen über die API an und zeigt die Benutzung von Basisanfragen um mit pythapi arbeiten zu können.'
    }
})
def get_basic_informations(reqHandler, p, args, body):
    return {
        'data': {
            'name': 'pythapi',
            'list_plugins': {
                'path': '/' +plugin.name +'/list?verbose=true',
                'method': 'GET'
            },
            'list_possible_requests_of_plugin': {
                'path': '/' +plugin.name +'/<plugin_name>/list?verbose=true',
                'method': 'GET'
            }
        }
    }
