#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: info.py
# Author:      Rene Fa
# Date:        11.04.2018
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
#-

import sys
sys.path.append("..")
import tools.fancy_logs as log # Logging
import MySQLdb # MySQL
from api_plugin import * # Essential Plugin

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
        'plugin_property_blacklist': []
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
        translated_text = return_json[property_name][api_config()['core.general']['default_language']]
        
    except:
        try:
            translated_text = return_json[property_name]['EN']
        
        except:
            translated_text = 'N/A'
    
    return_json[property_name] = translated_text

def i_format_action(action):
    
    return_json = dict(action)
    del return_json['func']
    del return_json['c_regex']
    
    for property_name in action_property_blacklist:
        try: del return_json[property_name]
        except: pass
    
    for property_name in return_json:
        if property_name[:2] == 'f_':
            i_format_formatted_properties(return_json, property_name)
    
    return return_json

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

    return i_format_action(api_action_tree()[plugin_name][action_name])

def i_list_actions_of_plugin(plugin_name):
    
    if not plugin_name in api_plugins():
        raise WebRequestException(400, 'error', 'INFO_PLUGIN_NOT_FOUND')
    
    return_json = []
    for i_action in api_plugins()[plugin_name].actions:
        return_json.append(i_format_action(i_action))
        
    return return_json

def i_get_action_by_path(method, path):
    
    for i_plugin in api_action_tree():
        for i_action in api_action_tree()[i_plugin]:
            
            action = api_action_tree()[i_plugin][i_action]
            
            if not action['method'] == method.upper():
                continue
            
            if action['c_regex'].match(path):
                return i_format_action(action)

@api_event(plugin, 'install')
def install():
    
    if 'auth' in api_plugins():
        log.info('auth installed. Apply ruleset...')
        
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
            log.error('Editing the default role failed!')
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
    
        log.debug('Ruleset deleted.')
    
    return 1

@api_event(plugin, 'load')
def load():
    
    action_property_blacklist.extend(api_config()[plugin.name]['action_property_blacklist'].split(','))
    plugin_property_blacklist.extend(api_config()[plugin.name]['plugin_property_blacklist'].split(','))
    
    return 1

@api_action(plugin, {
    'path': 'list',
    'method': 'GET',
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
    return {
        'data': i_list_plugins()
    }

@api_action(plugin, {
    'path': '*',
    'method': 'GET',
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
    return {
        'data': i_list_actions_of_plugin(p[0])
    }

@api_action(plugin, {
    'path': '*/*',
    'method': 'GET',
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
