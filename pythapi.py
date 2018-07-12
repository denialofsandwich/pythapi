#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi
# Author:      Rene Fa
# Date:        10.07.2018
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
import os
import argparse

os.chdir(os.path.dirname(os.path.realpath(__file__)))
version = 0.9

config_defaults = {
    'core.general': {
        'loglevel': 5,
        'fancy_logs': True,
        'file_logging_enabled': True,
        'logfile': 'pythapilog_[time].log',
        'user': 'root',
        'default_language': 'EN',
        'enabled_plugins': ['*']
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
        'https_enabled': False,
        'http_port': [8123],
        'https_port': [8124],
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
    },

    'GENERAL_VALUE_MISSING': {
        'EN': 'Missing value.',
        'DE': 'Fehlender Wert.'
    },

    'GENERAL_VALUE_TYPE_ERROR': {
        'EN': 'Invalid value type.',
        'DE': 'Unzulässiger Variablentyp.'
    },

    'GENERAL_VALUE_RANGE_EXCEEDED': {
        'EN': 'Allowed value range exceeded.',
        'DE': 'Erlaubter Wertebereich überschritten.'
    }
}

def i_get_client_ip(reqHandler):
    
    if reqHandler.request.remote_ip == "127.0.0.1":
        x_real_ip = reqHandler.request.headers.get("X-Real-IP")
        x_forwarded_for = reqHandler.request.headers.get("X-Forwarded-For")
        return x_real_ip or x_forwarded_for or reqHandler.request.remote_ip
    
    else:
        return reqHandler.request.remote_ip

transaction_id = 0
class MainHandler(tornado.web.RequestHandler):
    
    def write_error(self, status_code, **kwargs):
        if status_code == 500:
            self.set_status(status_code)
            self.set_header("Content-Type", 'application/json')
            self.log_access_error('internal_server_error', status_code, 'GENERAL_INTERNAL_SERVER_ERROR')
            
            return_json = {}
            return_json['status'] = "internal_server_error"
            return_json['error_id'] = 'GENERAL_INTERNAL_SERVER_ERROR'
            
            return_value = json.dumps(return_json) + '\n'
            self.finish(return_value)
    
    def log_access(self, method, path):
        if log.loglevel >= 5:
            log.access('{} {} {} {}'.format(api_plugin.environment_variables['transaction_id'], i_get_client_ip(self), method, path))
    
    def log_access_error(self, status, return_code, error_id):
        if log.loglevel >= 5:
            log.access('{} {} {} {}'.format(api_plugin.environment_variables['transaction_id'], status, return_code, error_id))
    
    def executeRequest(self, method, path):
        global transaction_id
        
        for action in api_plugin.action_call_dict[method]:
            match = action['c_regex'].match(path)
            if match:
                try:
                    api_plugin.environment_variables = {}
                    api_plugin.environment_variables['transaction_id'] = transaction_id
                    self.log_access(method, path)
                    
                    transaction_id += 1
                    if transaction_id >= 65535:
                        transaction_id = 0
                    
                    for hook in api_plugin.global_preexecution_hook_list:
                        hook['func'](self, action)
                    
                    raw_body = self.request.body
                    if action['request_body_type'] == 'application/json':
                        try:
                            body = tornado.escape.json_decode(raw_body)
                        except ValueError as e:
                            body = {}
                        
                    else:
                        body = {}
                    
                    params = []
                    i = 0
                    if 'params' in action:
                        for arg, skel in zip(match.groups(), action['params']):
                            params.append(api_plugin.try_convert_value('params', i, arg, skel))
                            i += 1
                    else:
                        params = match.groups()

                    args = {}
                    if 'args' in action:
                        for key in action['args'].keys():
                            
                            value = self.request.arguments.get(key, None)
                            if action['args'][key]['type'] != list and value != None:
                                value = value[0].decode('utf8')

                            args[key] = api_plugin.try_convert_value('args', key, value, action['args'][key])

                    else:
                        args = self.request.arguments
                    
                    if 'body' in action:
                        for key in action['body'].keys():
                            body[key] = api_plugin.try_convert_value('body', key, body.get(key, None), action['body'][key])

                    # Execution of action
                    return_json = action['func'](self, params, args, body)
                    
                    for hook in api_plugin.global_postexecution_hook_list:
                        hook(self, action, return_json)
                    
                    if action['content_type'] == "raw":
                        return
                    
                    elif action['content_type'] == "application/json":

                        if not 'status' in return_json:
                            return_json['status'] = 'success'
                        
                        return_json = json.dumps(return_json) + '\n'
                    
                    self.set_header('Server', "pythapi/{}".format(version))
                    self.set_header('Content-Type', action['content_type'])
                    self.write(return_json)
                    return
                
                except api_plugin.WebRequestException as e:
                    self.set_status(e.error_code)
                    self.set_header('Server', "pythapi/{}".format(version))
                    self.set_header('Content-Type', "application/json")
                    self.log_access_error(e.error_type, e.error_code, e.text_id)
                    
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
    
    if 'i_error' in api_plugin.plugin_dict[plugin_name].info:
        return 0
    
    plugin = api_plugin.plugin_dict[plugin_name]
    
    for dependency in plugin.depends:
        if 'i_error' in api_plugin.plugin_dict[dependency['name']].info:
            
            if dependency['required'] == True:
                log.error(plugin.name + ": required plugin {} not loaded.".format(dependency['name']))
                plugin.info['i_error'] = 1
                return 0
                
            else:
                log.warning(plugin.name + ": optional plugin {} not loaded.".format(dependency['name']))
                continue
        
        if not r_check_dependencies(dependency['name'], max_depth, event_name, depth +1):

            if dependency['required'] == True:
                log.error(plugin.name + ": required plugin {} not loaded.".format(dependency['name']))
                
            else:
                log.warning(plugin.name + ": optional plugin {} not loaded.".format(dependency['name']))
                continue

            plugin.info['i_error'] = 1
            if plugin.essential:
                log.critical(plugin.name + " is marked as essential. Exiting...")
                sys.exit(1)
            
            return 0
    
    log.info('Checking ' +plugin_name)
    if not 'check' in plugin.events:
        plugin.info['i_loaded'] = 1
        check_successful = 1
    else:
        check_successful = plugin.events['check']()

    if not check_successful and event_name != 'install':
        log.error(plugin_name +" returned an error.")
        plugin.info['i_error'] = 1
        return 0
    
    elif check_successful and event_name == 'install':
        plugin.info['i_loaded'] = 1
        return 1
    if event_name in plugin.events:
        log.debug('Execute event "' +event_name +'" from ' +plugin_name)

        if not plugin.events[event_name]():
            log.error('Event: "' +event_name +'" of ' +plugin_name +" returned an error.")
            plugin.info['i_error'] = 1
            return 0
    
    plugin.info['i_loaded'] = 1
    return 1

def i_build_indices():
    
    if api_plugin.indices_generated:
        return
    
    for plugin_name in api_plugin.dependency_list:
        plugin = api_plugin.plugin_dict[plugin_name]

        if 'i_error' in plugin.info:
            continue
        
        if 'global_preexecution_hook' in plugin.events:
            api_plugin.global_preexecution_hook_list.append({
                'plugin': plugin.name,
                'func': plugin.events['global_preexecution_hook']
            })
        
        if 'global_postexecution_hook' in plugin.events:
            api_plugin.global_postexecution_hook_list.append({
                'plugin': plugin.name,
                'func': plugin.events['global_postexecution_hook']
            })
        
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
    
    for hook in list(api_plugin.global_preexecution_hook_list):
        if 'i_error' in api_plugin.plugin_dict[hook['plugin']].info:
            api_plugin.global_preexecution_hook_list.remove(hook)

    for plugin_name in list(api_plugin.plugin_dict.keys()):
        
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
    print()
    log.info("Terminate all active plugins...")
    
    for plugin_name in reversed(api_plugin.dependency_list):
        plugin = api_plugin.plugin_dict[plugin_name]
        if 'terminate' in plugin.events and not plugin.events['terminate']():
            log.error(plugin.name +" returned an error.")
            log.critical("Termination process failed!")
            sys.exit(1)
        
    log.info("pythapi terminated.")
    sys.exit(0)

class ConvertableConfigParser(configparser.ConfigParser):
    def as_dict(self):
        d = dict(self._sections)
        for k in d:
            d[k] = dict(self._defaults, **d[k])
            d[k].pop('__name__', None)
        return d

def main():
    global log
    signal.signal(signal.SIGINT, signal_handler)
    
    # Read the config file
    api_plugin.config = ConvertableConfigParser()
    api_plugin.config.read('pythapi.ini')
    api_plugin.config.read('/etc/pythapi/pythapi.ini')
    api_plugin.config = api_plugin.config.as_dict()    
    api_plugin.add_config_defaults_and_convert(config_defaults)

    api_plugin.translation_dict = translation_dict

    # Initialize fancy_logs
    api_plugin.config['core.general']['logfile'] = api_plugin.config['core.general']['logfile'].replace('[time]', datetime.datetime.now().strftime('%m-%d-%Y'))
    
    api_plugin.log = tools.fancy_logs.fancy_logger(
        api_plugin.config['core.general']['fancy_logs'],
        api_plugin.config['core.general']['loglevel'],
        api_plugin.config['core.general']['file_logging_enabled'],
        api_plugin.config['core.general']['logfile']
    )
    log = api_plugin.log
    
    # Only the user defined in the config should be able to execute this program
    if(getpass.getuser() != api_plugin.config['core.general']['user']):
        log.critical("The user " +getpass.getuser() + " is not authorized to execute pythapi.")
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument('mode', default="run", nargs='?', choices=["run", "install", "uninstall"], help="Specifies the run-mode")
    parser.add_argument('plugin', default="", nargs='?', help="Specify a plugin to install/uninstall")
    parser.add_argument('--verbosity', '-v', type=int, help="Sets the verbosity")
    parser.add_argument('--reinstall', '-r', action='store_true', help="Uninstalls a plugin before installing it")
    parser.add_argument('--force', '-f', action='store_true', help="Force an instruction to execute")
    parser.add_argument('--no-fancy', '-n', action='store_true', help="Disables the colorful logs and shows a more machine-readable logging format")

    args = parser.parse_args()

    if args.no_fancy:
        api_plugin.config['core.general']['fancy_logs'] = False
        log.setFancy(False)

    if args.verbosity != None:
        api_plugin.config['core.general']['loglevel'] = args['verbosity']
        log.setLoglevel(args['verbosity'])

    # Plugin loader
    log.begin("Loading Plugins...")

    dir_r = glob.glob("plugins/*.py")
    log.info("Plugins found: " +str(len(dir_r) -1) )
    
    plugin_whitelist = []
    if api_plugin.config['core.general']['enabled_plugins'] != '*':
        plugin_whitelist = api_plugin.config['core.general']['enabled_plugins']
    
    log.debug("Importing and initializing plugins...")
    for i_dir in dir_r:
        
        module_name = re.search('^plugins/(.*)\.py$', i_dir).group(1)
        if(module_name == "__init__"): continue
        
        if len(plugin_whitelist) and not module_name in plugin_whitelist:
            log.debug("{}.py is disabled.".format(module_name))
            continue
        
        plugin = importlib.import_module("plugins." +module_name).plugin
        
        plugin.init()
        api_plugin.plugin_dict[plugin.name] = plugin
    
    for plugin_name in api_plugin.plugin_dict:
        if not plugin_name in api_plugin.dependency_list and not 'i_error' in api_plugin.plugin_dict[plugin_name].info:
            r_build_dependency_list(plugin_name, len(api_plugin.plugin_dict) )
    
    i_removeBrokenPlugins()

    if args.mode == 'uninstall' or (args.mode == 'install' and args.reinstall):
        log.begin('Start uninstallation process...')
        
        # Fill plugin list based in instruction
        if args.plugin != "":
            if not args.plugin in api_plugin.plugin_dict:
                log.critical(args.plugin +' does not exist!')
                sys.exit(1)
            
            if 'i_error' in api_plugin.plugin_dict[args.plugin].info:
                log.critical('Installation falied due to an error.')
                sys.exit(1)
            
            r_build_reverse_dependency_list(args.plugin, len(api_plugin.plugin_dict))
            
            if len(api_plugin.reverse_dependency_list) > 1 and not args.force:
                log.warning(args.plugin +' is used by other plugins.')
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
                
        if args.mode == 'uninstall':
            log.success("pythapi successfully uninstalled.")
            sys.exit(0)

    if args.mode == 'install':
        log.begin('Start installation process...')
        
        # Fill plugin list based in instruction
        if args.plugin:
            if not args.plugin in api_plugin.plugin_dict:
                log.critical(args['plugin'] +' does not exist!')
                sys.exit(1)
            
            if 'i_error' in api_plugin.plugin_dict[args.plugin].info:
                log.critical('Installation falied due to an error.')
                sys.exit(1)
            
            api_plugin.dependency_list = []
            r_build_dependency_list(args.plugin, len(api_plugin.plugin_dict) )
            
            if args.reinstall:
                for r_dependency in reversed(api_plugin.reverse_dependency_list):
                    if not r_dependency in api_plugin.dependency_list:
                        api_plugin.dependency_list.append(r_dependency)
        
        for plugin_name in api_plugin.dependency_list:
            if not 'i_error' in api_plugin.plugin_dict[plugin_name].info and not 'i_loaded' in api_plugin.plugin_dict[plugin_name].info:
                r_check_dependencies(plugin_name, len(api_plugin.plugin_dict), 'install')

        log.success("pythapi successfully installed.")
        sys.exit(0)
    
    if args.mode == 'run':
        i_build_indices()
        for plugin_name in api_plugin.dependency_list:
            if not 'i_error' in api_plugin.plugin_dict[plugin_name].info and not 'i_loaded' in api_plugin.plugin_dict[plugin_name].info:
                if not r_check_dependencies(plugin_name, len(api_plugin.plugin_dict), 'load'):

                    if api_plugin.plugin_dict[plugin_name].essential:
                        log.critical(api_plugin.plugin_dict[plugin_name].name + " is marked as essential. Exiting...")
                        sys.exit(1)
        
        i_removeBrokenPlugins()
        
        app = tornado.web.Application([
            (r"/(.*)?", MainHandler)
        ])
        
        http_ports = api_plugin.config['core.web']['http_port']
        http_ip    = api_plugin.config['core.web']['bind_ip']
        for port in http_ports:
            app.listen(port,http_ip)
            log.debug('HTTP started at: {}:{}'.format(http_ip,port))
        
        if api_plugin.config['core.web']['https_enabled']:
            
            log.debug('SSL enabled')
            
            if not os.path.isfile(api_plugin.config['core.web']['ssl_cert_file']):
                log.critical('Certfile not found.')
                sys.exit(1)

            if not os.path.isfile(api_plugin.config['core.web']['ssl_key_file']):
                log.critical('Keyfile not found.')
                sys.exit(1)

            https_server = tornado.httpserver.HTTPServer(app, ssl_options={
                "certfile": api_plugin.config['core.web']['ssl_cert_file'],
                "keyfile": api_plugin.config['core.web']['ssl_key_file']
            })
            
            https_ports = api_plugin.config['core.web']['https_port']
            for port in https_ports:
                https_server.listen(port,http_ip)
                log.debug('HTTPS started at: {}:{}'.format(http_ip,port))
        
        hn = logging.NullHandler()
        hn.setLevel(logging.DEBUG)
        logging.getLogger("tornado.access").addHandler(hn)
        logging.getLogger("tornado.access").propagate = False
        
        log.success("pythapi successfully started.")
        log.info("Entering main loop...")
        
        IOLoop.instance().start()

if __name__ == "__main__":
    main()
