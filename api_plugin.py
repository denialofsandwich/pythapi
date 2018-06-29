#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: api_plugin.py
# Author:      Rene Fa
# Date:        23.04.2018
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

import re
import MySQLdb
import collections

import tools.fancy_logs as log # Logging

config = {}
plugin_dict = {}
action_call_dict = {}
action_tree = {}
global_preexecution_hook_list = []
global_postexecution_hook_list = []
dependency_list = []
reverse_dependency_list = []
indices_generated = False
translation_dict = {}
environment_variables = {}
log = None

def update(d, u):
    for k, v in u.items():
        if isinstance(v, collections.Mapping):
            d[k] = update(d.get(k, {}), v)
        else:
            d[k] = v
    return d

class WebRequestException(Exception):
    error_code = 0
    error_type = 'error'
    return_json = {}
    
    def __init__(self, error_code=400, error_type='error', text_id='GENERAL_ERROR' , return_json = {}):

        Exception.__init__(self,text_id)
        
        self.error_code = error_code
        self.error_type = error_type
        self.text_id = text_id
        self.return_json = return_json

def api_mysql_connect():
    return MySQLdb.connect(config['core.mysql']['hostname'],
                           config['core.mysql']['username'],
                           config['core.mysql']['password'],
                           config['core.mysql']['database'])

def api_config():
    return config

def api_plugins():
    return plugin_dict

def api_action_tree():
    return action_tree

def api_action_call_dict():
    return action_call_dict

def api_environment_variables():
    return environment_variables

def api_log():
    return log

def api_tr(text_id):
    
    try:
        return translation_dict[text_id][environment_variables['language']]
    
    except:
        try:
            return translation_dict[text_id][config['core.general']['default_language']]

        except:
            try:
                return translation_dict[text_id]['EN']
            
            except:
                try:
                    return translation_dict['GENERAL_ERROR'][config['core.general']['default_language']]
                
                except:
                    return translation_dict['GENERAL_ERROR']['EN']

class api_plugin():

    def __init__(self):
        self.name = "unknown"
        self.version = "0.0"
        self.essential = False
        self.depends = []
        self.reverse_dependencies = []
        self.info = {}
        
        self.actions = []
        self.events = {}
        self.functions = {}
        self.config_defaults = {}
        self.translation_dict = {}

    def init(self):
        global config
        global translation_dict
        
        update(self.config_defaults, config)
        config = self.config_defaults
        
        update(translation_dict, self.translation_dict)
        
        if not self.name in config:
            config[self.name] = {}
        
        if 'essential' in config[self.name]:
            self.essential = 1 if config[self.name]['essential'] == 'true' else 0

def tr(plugin, plugin_name, text_id):
    return 0

def api_event(plugin, event_name):
    def ap_generator(f):
        
        plugin.events[event_name] = f
        return f
        
    return ap_generator

def api_external_function(plugin):
    def ap_generator(f):
        
        plugin.functions[f.__name__] = f
        setattr(plugin, f.__name__, f)
        return f
    
    return ap_generator

def api_action(plugin, pJSON):
    def ap_generator(f):
        
        plugin.actions.append(pJSON)
        plugin.actions[-1]['name'] = plugin.name +'.' +f.__name__
        plugin.actions[-1]['func'] = f
        
        if not 'method' in plugin.actions[-1]:
            plugin.actions[-1]['method'] = 'GET'
        
        else:
            plugin.actions[-1]['method'] = plugin.actions[-1]['method'].upper()
        
        if not 'request_body_type' in plugin.actions[-1]:
            plugin.actions[-1]['request_body_type'] = 'application/json'
            
        if not 'content_type' in plugin.actions[-1]:
            plugin.actions[-1]['content_type'] = 'application/json'
        
        if not 'roles' in plugin.actions[-1]:
            plugin.actions[-1]['roles'] = []
        
        if 'path' in plugin.actions[-1]:
            plugin.actions[-1]['regex'] = '^' +plugin.name +'/' +plugin.actions[-1]['path'].replace('*','([^/]*)') +'$'
        
        # A precompiled regex has a better perforance
        plugin.actions[-1]['c_regex'] = re.compile(pJSON['regex'])
        return f
        
    return ap_generator
