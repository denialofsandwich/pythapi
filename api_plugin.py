#!/usr/bin/python
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
    message = 'N/A'
    return_json = {}
    
    def __init__(self, error_code=400, error_type='error', message='N/A', return_json = {}):

        Exception.__init__(self,message)
        
        self.error_code = error_code
        self.error_type = error_type
        self.message = message
        self.return_json = return_json

class api_plugin():

    def __init__(self):
        self.name = "unknown"
        self.version = "0.0"
        self.essential = False
        self.depends = []
        self.reverse_dependencies = []
        self.info = {}
        
        self.all_plugins = {}
        self.actions = []
        self.action_tree = None
        self.events = {}
        self.functions = {}
        self.config_defaults = {}

        self.config = None
        self.db_prefix = None

    def init(self, p_config, p_plugins, p_action_tree):
        self.config = p_config
        self.all_plugins = p_plugins
        self.action_tree = p_action_tree
        self.db_prefix = p_config['core.mysql']['prefix']
        
        update(self.config_defaults, self.config)
        self.config = self.config_defaults
        
        if not self.name in self.config:
            self.config[self.name] = {}
        
        if 'essential' in self.config[self.name]:
            self.essential = self.config[self.name]['essential']
        
    def mysql_connect(self):
        return MySQLdb.connect(self.config['core.mysql']['hostname'],
                               self.config['core.mysql']['username'],
                               self.config['core.mysql']['password'],
                               self.config['core.mysql']['database'])

def api_event(plugin, event_name):
    def ap_generator(f):
        
        plugin.events[event_name] = f
        return f
        
    return ap_generator

def api_external_function(plugin):
    def ap_generator(f):
        
        plugin.functions[f.func_name] = f
        setattr (plugin, f.func_name, f)
        return f
    
    return ap_generator

def api_action(plugin, pJSON):
    def ap_generator(f):
        
        plugin.actions.append(pJSON)
        plugin.actions[-1]['name'] = plugin.name +'.' +f.func_name
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
