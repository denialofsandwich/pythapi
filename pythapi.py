#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi
# Author:      Rene Fa
# Date:        23.04.2018
# Version:     0.8
#
# Description: This is a RESTful API WebServer with focus on extensibility and performance.
#              It's target is to make it possible to easily build your own API.
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
import getpass
import signal
import configparser # apt
import MySQLdb # apt
import tools.fancy_logs
import importlib
from tornado import httpserver # apt
from tornado.ioloop import IOLoop
import tornado.web
import glob
import re
import json
import api_plugin
import logging
import datetime

usage_text = """
Syntax:
    ./pythapi.py [instruction] [options]

Global options:
    -v ,--verbosity loglevel
                        Changes the verbosity. 0 means only critical errors
                        and 5 shows debugging information

    -f ,--force
                        Force an instruction to execute.

    -h ,--help
                        Shows this help message.

Instructions:
    help [options]
                        Shows this help message.

    install [plugin] [options]
                        Install the pythapi. You can also specify a plugin.
        
        -r, --reinstall
                        Try to delete a old installation before installing.
                        
    uninstall [plugin] [options]
                        Uninstall the pythapi. This deletes tables created by pythapi.
                        You can also specify a plugin.
"""

config_defaults = {
    'core.general': {
        'loglevel': '4',
        'colored_logs': 'true',
        'file_logging_enabled': 'true',
        'logfile': 'pythapilog_[time].log',
        'user': 'root',
        'default_language': 'EN'
    },
    'core.mysql': {
        'hostname': 'localhost',
        'username': 'pythapi',
        'password': 'pythapi',
        'database': 'pythapi',
        'prefix': 'pa_'
    },
    'core.web': {
        'bind_ip': '0.0.0.0',
        'https_enabled': 'false',
        'http_port': '8123',
        'https_port': '8124',
        'ssl_cert_file': 'certfile_missing',
        'ssl_key_file': 'keyfile_missing'
    }
}

translation_dict = {
    'GENERAL_ERROR': {
        'EN': 'Unknown error.',
        'DE': 'Unbekannter Fehler.'
    },
    
    'GENERAL_SQL_ERROR': {
        'EN': 'Unknown SQL error.',
        'DE': 'Unbekannter SQL Fehler.'
    },
    
    'GENERAL_RECURSIVE_LOOP': {
        'EN': 'Recursive loop detected.',
        'DE': 'Rekursive Schleife entdeckt.'
    }
}

class MainHandler(tornado.web.RequestHandler):
    def executeRequest(self, method, path):
        for action in api_plugin.action_call_dict[method]:
            match = action['c_regex'].match(path)
            if match:
                try:
                    api_plugin.environment_variables = {}
                    
                    for hook in api_plugin.global_preexecution_hook_list:
                        hook(self, action)
                    
                    raw_body = self.request.body
                    if action['request_body_type'] == 'application/json':
                        try:
                            body = tornado.escape.json_decode(raw_body)
                        except ValueError as e:
                            body = {}
                        
                    else:
                        body = {}

                    return_value = action['func'](self, match.groups(), self.request.arguments, body)
                    
                    if action['content_type'] == "raw":
                        return
                    
                    elif action['content_type'] == "application/json":

                        if not 'status' in return_value:
                            return_value['status'] = 'success'
                        
                        return_value = json.dumps(return_value) + '\n'
                    
                    self.set_header("Content-Type", action['content_type'])
                    self.write(return_value)
                    return
                
                except api_plugin.WebRequestException as e:
                    self.set_status(e.error_code)
                    self.set_header("Content-Type", 'application/json')
                    
                    return_json = {}
                    return_json['status'] = e.error_type
                    return_json['message'] = api_plugin.api_tr(e.text_id)
                    return_json['error_id'] = e.text_id
                    return_json.update(e.return_json)
                    
                    return_value = json.dumps(return_json) + '\n'
                    self.write(return_value)
                    return
        
        self.set_status(404)
        self.set_header("Content-Type", 'application/json')
        
        return_json = {
            'status':'not found',
            'message':'Request doesn\'t exist.'
        }
        
        return_value = json.dumps(return_json) + '\n'
        self.write(return_value)
        
    def get(self, path):
        self.executeRequest('GET' ,path)
        
    def post(self, path):
        self.executeRequest('POST' ,path)
        
    def put(self, path):
        self.executeRequest('PUT' ,path)
        
    def patch(self, path):
        self.executeRequest('PATCH' ,path)
        
    def delete(self, path):
        self.executeRequest('DELETE' ,path)
        
    def copy(self, path):
        self.executeRequest('COPY' ,path)
        
    def head(self, path):
        self.executeRequest('HEAD' ,path)
        
    def options(self, path):
        self.executeRequest('OPTIONS' ,path)
        
    def link(self, path):
        self.executeRequest('LINK' ,path)
        
    def unlink(self, path):
        self.executeRequest('UNLINK' ,path)
        
    def purge(self, path):
        self.executeRequest('PURGE' ,path)
        
    def lock(self, path):
        self.executeRequest('LOCK' ,path)
        
    def unlock(self, path):
        self.executeRequest('UNLOCK' ,path)
        
    def propfind(self, path):
        self.executeRequest('PROPFIND' ,path)
        
    def view(self, path):
        self.executeRequest('VIEW' ,path)

class BaseWebServer(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/(.*)?", MainHandler)
        ]
        tornado.web.Application.__init__(self, handlers)

def r_build_dependency_list(plugin_name, max_depth, depth = 0):
    if depth > max_depth:
        log.critical(plugin_name +': Dependency loop detected! Exiting...')
        sys.exit(1)
    
    if plugin_name in api_plugin.dependency_list:
        return 1
    
    for dependency in api_plugin.plugin_dict[plugin_name].depends:
        if not dependency['name'] in api_plugin.plugin_dict:
            if dependency['required'] == True:
                
                log.error(plugin_name +': Required plugin "' +dependency['name'] +'" not found!')
                api_plugin.plugin_dict[plugin_name].info['i_error'] = 1
                if api_plugin.plugin_dict[plugin_name].essential:
                    log.critical(api_plugin.plugin_dict[plugin_name].name + " is marked as essential. Exiting...")
                    sys.exit(1)
                
                return 0
            else:
                log.warning(plugin_name +': Optional plugin "' +dependency['name'] +'" not found.')
                continue
        
        
        if 'i_error' in api_plugin.plugin_dict[dependency['name']].info:
            return 0
        
        if not r_build_dependency_list(dependency['name'], max_depth, depth +1):

            if dependency['required'] == True:
                log.error(api_plugin.plugin_dict[plugin_name].name + ": could not load a required plugin.")
                
            else:
                log.warning(api_plugin.plugin_dict[plugin_name].name + ": could not load a optional plugin.")
                continue

            api_plugin.plugin_dict[plugin_name].info['i_error'] = 1
            if api_plugin.plugin_dict[plugin_name].essential:
                log.critical(api_plugin.plugin_dict[plugin_name].name + " is marked as essential. Exiting...")
                sys.exit(1)
            
            return 0
        
        api_plugin.plugin_dict[dependency['name']].reverse_dependencies.append(plugin_name)
    
    api_plugin.dependency_list.append(plugin_name)
    return 1

def r_build_reverse_dependency_list(plugin_name, max_depth, depth = 0):
    if plugin_name in api_plugin.reverse_dependency_list:
        return
    
    for dependency in api_plugin.plugin_dict[plugin_name].reverse_dependencies:
        r_build_reverse_dependency_list(dependency, max_depth, depth +1)
    
    api_plugin.reverse_dependency_list.append(plugin_name)

def r_check_dependencies(plugin_name, max_depth, event_name, depth = 0):
    if 'i_loaded' in api_plugin.plugin_dict[plugin_name].info:
        return 1
    
    plugin = api_plugin.plugin_dict[plugin_name]
    
    for dependency in plugin.depends:
        if 'i_error' in api_plugin.plugin_dict[dependency['name']].info:
            return 0
        
        if not r_check_dependencies(dependency['name'], max_depth, event_name, depth +1):

            if dependency['required'] == True:
                log.error(plugin.name + ": could not load a required plugin.")
                
            else:
                log.warning(plugin.name + ": could not load a optional plugin.")
                continue

            plugin.info['i_error'] = 1
            if plugin.essential:
                log.critical(plugin.name + " is marked as essential. Exiting...")
                sys.exit(1)
            
            return 0
    
    log.info('Checking ' +plugin_name)
    if 'check' in plugin.events and plugin.events['check']() == 0 and event_name != 'install':
        log.error(plugin_name +" returned an error.")
        plugin.info['i_error'] = 1
        return 0
    
    elif 'check' in plugin.events and plugin.events['check']() == 1 and event_name == 'install':
        plugin.info['i_loaded'] = 1
        return 1
    
    log.info('Execute event "' +event_name +'" from ' +plugin_name)
    if event_name in plugin.events and not plugin.events[event_name]():
        log.error('Event: ' +event_name +' of ' +plugin_name +" returned an error.")
        plugin.info['i_error'] = 1
        return 0
    
    plugin.info['i_loaded'] = 1
    return 1

def i_build_indices():
    #global api_plugin.indices_generated
    
    if api_plugin.indices_generated:
        return
    
    for plugin_name in api_plugin.dependency_list:
        plugin = api_plugin.plugin_dict[plugin_name]
        
        if 'global_preexecution_hook' in plugin.events:
            api_plugin.global_preexecution_hook_list.append(plugin.events['global_preexecution_hook'])
        
        api_plugin.action_tree[plugin_name] = {}
        for action in plugin.actions:
            if not action['method'] in api_plugin.action_call_dict:
                api_plugin.action_call_dict[action['method']] = []
                
            api_plugin.action_call_dict[action['method']].append(action)
            
            action_sub_name = action['name'].split('.')[1]
            
            if action_sub_name in api_plugin.action_tree[plugin.name]:
                log.warning("Duplicate Name in: " +action['name'])
            
            api_plugin.action_tree[plugin.name][action_sub_name] = action
    
    api_plugin.indices_generated = True

def i_removeBrokenPlugins():
    for plugin_name in api_plugin.plugin_dict.keys():
        
        if 'i_error' in api_plugin.plugin_dict[plugin_name].info:
            del api_plugin.plugin_dict[plugin_name]
            continue
        
        i = 0
        while i < len(api_plugin.plugin_dict[plugin_name].reverse_dependencies):
            r_dependency = api_plugin.plugin_dict[plugin_name].reverse_dependencies[i]
            
            if not r_dependency in api_plugin.plugin_dict or 'i_error' in api_plugin.plugin_dict[r_dependency].info:
                del api_plugin.plugin_dict[plugin_name].reverse_dependencies[i]
                continue
            
            i += 1

def signal_handler(signal, frame):
    log.info("Terminate all active plugins...")
    
    for plugin_name in reversed(api_plugin.dependency_list):
        plugin = api_plugin.plugin_dict[plugin_name]
        if 'terminate' in plugin.events and not plugin.events['terminate']():
            log.error(plugin.name +" returned an error.")
            log.critical("Termination process failed!")
            sys.exit(1)
        
    log.debug("pythapi terminated.")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    
    # Read the config file
    api_plugin.config = configparser.ConfigParser()
    api_plugin.config.read('pythapi.ini')
    
    # Apply default config values
    api_plugin.update(config_defaults, api_plugin.config)
    api_plugin.config = config_defaults
    
    api_plugin.translation_dict = translation_dict

    # Initialize fancy_logs
    api_plugin.config['core.general']['logfile'] = api_plugin.config['core.general']['logfile'].replace('[time]', datetime.datetime.now().strftime('%m-%d-%Y'))
    
    api_plugin.log = tools.fancy_logs.fancy_logger(
        1 if api_plugin.config['core.general']['colored_logs'] == "true" else 0,
        int(api_plugin.config['core.general']['loglevel']),
        1 if api_plugin.config['core.general']['file_logging_enabled'] == "true" else 0,
        api_plugin.config['core.general']['logfile']
    )
    log = api_plugin.log
    
    # Only the user defined in the config should be able to execute this program
    if(getpass.getuser() != api_plugin.config['core.general']['user']):
        log.critical("The user " +getpass.getuser() + " is not authorized to execute pythapi.")
        sys.exit(1)

    # Parameter interpreter
    i = 1
    mode="none"
    p = sys.argv
    bp = 0 # Base parameters without explicit parameter tag
    while(i < len(p)):
        if(p[i] == "install" and bp == 0):
            mode = "install"
            bp += 1

        elif(p[i] == "uninstall" and bp == 0):
            mode = "uninstall"
            bp += 1
            
        elif(p[i][0] != "-" and (mode == "install" or mode == "uninstall") and bp == 1):
            param_plugin = p[i]
            bp += 1
            
        elif(p[i][:2] == "-r" or p[i] == "--reinstall" and mode == "install"):
            reinstall = True

        elif(p[i][:2] == "-f" or p[i] == "--force"):
            force_mode = True
            
        elif(p[i][:2] == "-v" or p[i] == "--verbosity"):
            api_plugin.config['core.general']['loglevel'] = p[i+1]
            del p[i+1]
            
        elif(p[i][:2] == "-h" or p[i] == "--help"):
            print(usage_text)
            sys.exit(0)
            
        else:
            log.error("Parameter Error at: " +p[i])
            log.info("Execute: 'pythapi help' for more information.")
            log.critical("Some errors make it impossiple to continue the programm.")
            sys.exit(1)

        if(p[i][0] == "-" and p[i][1] != "-" and len(p[i]) > 2):
            p[i] = p[i][:1] + p[i][2:]
            
        else:
            i += 1

    log.loglevel = int(api_plugin.config['core.general']['loglevel'])

    # Plugin loader
    log.begin("Loading Plugins...")

    dir_r = glob.glob("plugins/*.py")
    log.debug("Plugins found: " +str(len(dir_r) -1) )
    
    # Import and initializing of the found plugins
    for i_dir in dir_r:
        
        module_name = re.search('^plugins/(.*)\.py$', i_dir).group(1)
        if(module_name == "__init__"): continue
        
        plugin = importlib.import_module("plugins." +module_name).plugin
        
        plugin.init()
        api_plugin.plugin_dict[plugin.name] = plugin
        
    for plugin_name in api_plugin.plugin_dict:
        if not plugin_name in api_plugin.dependency_list and not 'i_error' in api_plugin.plugin_dict[plugin_name].info:
            r_build_dependency_list(plugin_name, len(api_plugin.plugin_dict) )
    
    i_removeBrokenPlugins()

    if mode == 'uninstall' or (mode == 'install' and 'reinstall' in globals()):
        log.begin('Start uninstallation process...')
        
        # Fill plugin list based in instruction
        if 'param_plugin' in globals():
            if not param_plugin in api_plugin.plugin_dict:
                log.critical(param_plugin +' does not exist!')
                sys.exit(1)
            
            if 'i_error' in api_plugin.plugin_dict[param_plugin].info:
                log.critical('Installation falied due to an error.')
                sys.exit(1)
            
            r_build_reverse_dependency_list(param_plugin, len(api_plugin.plugin_dict))
            
            if len(api_plugin.reverse_dependency_list) > 1 and not 'force_mode' in globals():
                log.warning(param_plugin +' is used by other plugins.')
                log.info('Use --force to ignpore this. This will also reinstall all plugins which use this plugin!')
                log.critical('Execution stopped.')
                sys.exit(1)
            
        else:
            api_plugin.reverse_dependency_list = list(reversed(api_plugin.dependency_list))
        
        for plugin_name in api_plugin.reverse_dependency_list:
            plugin = api_plugin.plugin_dict[plugin_name]
            
            log.info("Uninstall "+plugin.name)
            
            if 'uninstall' in plugin.events and not plugin.events['uninstall']():
                log.error(plugin.name +" returned an error.")
                log.critical("Unistallation failed!")
                sys.exit(1)
                
        if mode == 'uninstall':
            log.success("pythapi successfully uninstalled.")
            sys.exit(0)

    if mode == 'install':
        log.begin('Start installation process...')
        
        # Fill plugin list based in instruction
        if 'param_plugin' in globals():
            if not param_plugin in api_plugin.plugin_dict:
                log.critical(param_plugin +' does not exist!')
                sys.exit(1)
            
            if 'i_error' in api_plugin.plugin_dict[param_plugin].info:
                log.critical('Installation falied due to an error.')
                sys.exit(1)
            
            api_plugin.dependency_list = []
            r_build_dependency_list(param_plugin, len(api_plugin.plugin_dict) )
            
            if 'reinstall' in globals():
                for r_dependency in reversed(api_plugin.reverse_dependency_list):
                    if not r_dependency in api_plugin.dependency_list:
                        api_plugin.dependency_list.append(r_dependency)
        
        for plugin_name in api_plugin.dependency_list:
            if not 'i_error' in api_plugin.plugin_dict[plugin_name].info and not 'i_loaded' in api_plugin.plugin_dict[plugin_name].info:
                r_check_dependencies(plugin_name, len(api_plugin.plugin_dict), 'install')
    
    if mode == 'none':
        i_build_indices()
        
        for plugin_name in api_plugin.dependency_list:
            if not 'i_error' in api_plugin.plugin_dict[plugin_name].info and not 'i_loaded' in api_plugin.plugin_dict[plugin_name].info:
                r_check_dependencies(plugin_name, len(api_plugin.plugin_dict), 'load')
        
        i_removeBrokenPlugins()
        
        log.success("pythapi successfully started.")
        log.info("Entering main loop...")
        
        app = tornado.web.Application([
            (r"/(.*)?", MainHandler)
        ])
        
        http_ports = api_plugin.config['core.web']['http_port'].split(',')
        for port in http_ports:
            app.listen(int(port),api_plugin.config['core.web']['bind_ip'])
        
        if api_plugin.config['core.web']['https_enabled'] == 'true':
            
            https_server = tornado.httpserver.HTTPServer(app, ssl_options={
                "certfile": api_plugin.config['core.web']['ssl_cert_file'],
                "keyfile": api_plugin.config['core.web']['ssl_key_file']
            })
            
            https_ports = api_plugin.config['core.web']['https_port'].split(',')
            for port in https_ports:
                https_server.listen(int(port),api_plugin.config['core.web']['bind_ip'])
        
        hn = logging.NullHandler()
        hn.setLevel(logging.DEBUG)
        logging.getLogger("tornado.access").addHandler(hn)
        logging.getLogger("tornado.access").propagate = False
        
        IOLoop.instance().start()
