#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: api_plugin.py
# Author:      Rene Fa
# Date:        10.07.2018
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
import sys

import datetime

import tools.fancy_logs as log # Logging

def init():
    global config
    global plugin_dict
    global action_call_dict
    global action_tree
    global global_preexecution_hook_list
    global global_postexecution_hook_list
    global dependency_list
    global reverse_dependency_list
    global indices_generated
    global translation_dict
    global environment_variables
    global log

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
    return MySQLdb.connect(host=config['core.mysql']['hostname'],
                           user=config['core.mysql']['username'],
                           passwd=config['core.mysql']['password'],
                           db=config['core.mysql']['database'],
                           port=config['core.mysql']['port'])

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

def try_convert_value(section, key, value, skel):
    desired_type = skel['type']

    if section == 'args' and type(value) == bytes:
        value = value.decode('utf8')

    if section == 'body' or section == 'args':
        if value == None:
            if 'default' in skel:
                value = skel['default']
            else:
                raise WebRequestException(400, 'error', 'GENERAL_VALUE_MISSING', {
                    'section': section,
                    'value': key
                })

    if skel['type'] == bool and (section == 'params' or section == 'args'):
        if (type(value) == bool and value) or type(value) != bool and (value.lower() == 'true' or value == '1'):
            value = True
        elif (type(value) == bool and not value) or type(value) != bool and (value.lower() == 'false' or value == '0'):
            value = False
        else:
            raise WebRequestException(400, 'error', 'GENERAL_VALUE_TYPE_ERROR', {
                'section': 'param',
                'value': key if section != "param" else "{} ({})".format(key, skel['name']),
                'expect': skel['type'].__name__
            })

    try:
        if section == 'body' or section == 'args':
            if desired_type == list:
                if type(value) == list:
                    if 'allow_empty' in skel and skel['allow_empty'] == False and len(value) == 0:
                        raise WebRequestException(400, 'error', 'GENERAL_LIST_EMPTY', {
                            'section': section,
                            'value': key if section != "param" else "{} ({})".format(key, skel['name'])
                        })
                    elif 'allow_duplicates' in skel and skel['allow_duplicates'] == False and len(value) != len(set(value)):
                        raise WebRequestException(400, 'error', 'GENERAL_DUPLICATE_IN_LIST', {
                            'section': section,
                            'value': key if section != "param" else "{} ({})".format(key, skel['name'])
                        })

                    if 'childs' in skel:
                        for i, item in enumerate(value):
                            value[i] = try_convert_value(section, "{}.{}".format(key, i), item, skel['childs'])

                    return value

                else:
                    raise TypeError()

            if desired_type == dict:
                if type(value) == dict:
                    if 'childs' in skel:
                        for sub_key in skel['childs'].keys():
                            value[sub_key] = try_convert_value(section, "{}.{}".format(key, sub_key), value.get(sub_key, None), skel['childs'][sub_key])

                    return value

                else:
                    raise TypeError()
        
        value = desired_type(value)

        if 'formatter' in skel:
            value = skel['formatter'](value, skel)

        if desired_type == str:
            if 'regex' in skel and not re.match(skel['regex'], value):
                raise WebRequestException(400, 'error', 'GENERAL_INVALID_STRING_FORMAT', {
                    'section': section,
                    'value': key if section != "param" else "{} ({})".format(key, skel['name']),
                    'regex': skel['regex']
                })

        if desired_type == int:
            if 'min' in skel and value < skel['min']:
                raise WebRequestException(400, 'error', 'GENERAL_VALUE_RANGE_EXCEEDED', {
                    'section': section,
                    'value': key if section != "param" else "{} ({})".format(key, skel['name']),
                    'min': skel['min']
                })
            elif 'max' in skel and value > skel['max']:
                raise WebRequestException(400, 'error', 'GENERAL_VALUE_RANGE_EXCEEDED', {
                    'section': section,
                    'value': key if section != "param" else "{} ({})".format(key, skel['name']),
                    'max': skel['max']
                })

    except (TypeError, ValueError) as e:
        raise WebRequestException(400, 'error', 'GENERAL_VALUE_TYPE_ERROR', {
            'section': section,
            'value': key if section != "param" else "{} ({})".format(key, skel['name']),
            'expect': skel['type'].__name__
        })
    
    return value

def convert_value(reference, value):
    if type(reference) == bool:
        return True if value.lower() == 'true' else False

    elif type(reference) == list:
        str_val = value
        value = []

        e_type = str
        try:
            e_type = type(reference[0])
        except IndexError:
            pass

        for entry in str_val.split(','):
            value.append(e_type(entry.strip()))
        
        return value
    else:
        return type(reference)(value)

def add_config_defaults_and_convert(config_defaults):
    for section_name in config_defaults:
        if not section_name in config:
            config[section_name] = {}

        for k in config_defaults[section_name]:
            v = config_defaults[section_name][k]
            try:
                config[section_name][k] = convert_value(v, config[section_name][k])

            except (TypeError, ValueError) as e:
                print("ERROR in configuration. {}.{}: {} expected.".format(section_name, k, type(v).__name__))
                sys.exit(1)

            except KeyError as e:
                config[section_name][k] = v

def r_serializable_dict(d, depth = 0):
    if depth > 100:
        raise WebRequestException(400, 'error', 'GENERAL_RECURSIVE_LOOP')

    if type(d) == list:
        old_d = d
        d = []
        for i, v in enumerate(old_d):
            d.append(r_serializable_dict(v, depth+1))

    elif type(d) == dict:
        old_d = d
        d = {}
        for k, v in old_d.items():
            d[k] = r_serializable_dict(v, depth+1)

    elif type(d) in [str, int, float, bool] or d == None:
        return d

    elif type(d) == datetime.datetime:
        d = d.strftime('%H:%M:%S %d.%m.%Y')

    else:
        return str(d)

    return d

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

        try:
            del self.info['i_loaded']
            del self.info['i_error']
        except: pass

        add_config_defaults_and_convert(self.config_defaults)
        
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
        
        if 'path' in plugin.actions[-1]:
            plugin.actions[-1]['regex'] = '^' +plugin.name +'/' +plugin.actions[-1]['path'].replace('*','([^/]*)') +'$'
        
        # A precompiled regex has a better perforance
        plugin.actions[-1]['c_regex'] = re.compile(pJSON['regex'])
        return f
        
    return ap_generator
