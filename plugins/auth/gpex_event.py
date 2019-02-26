#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: auth.py
# Author:      Rene Fa
# Date:        17.01.2019
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
sys.path.append("..")
from api_plugin import *

import time
import math
import tornado

from .header import *
from . import manage_users
from . import interfaces

def unauthorized_error(error_code, error_name, error_message, remote_ip = "N/A"):
    
    return_json = {}
    if auth_globals.bf_temporary_ban_enabled:
        if not remote_ip in auth_globals.bf_blacklist:
            
            new_entry = {}
            new_entry['failed_attempts'] = 1
            new_entry['banned_until'] = time.time() + 1
            
            auth_globals.bf_blacklist[remote_ip] = new_entry
        
        else:
            auth_globals.bf_blacklist[remote_ip]['failed_attempts'] += 1
            
            ban_time = 2**auth_globals.bf_blacklist[remote_ip]['failed_attempts']
            auth_globals.bf_blacklist[remote_ip]['banned_until'] = time.time() +ban_time
            return_json['ban_time'] = ban_time
    
    raise WebRequestException(error_code, error_name, error_message, return_json)

def i_reset_ban_time(remote_ip = "N/A"):
    
    if auth_globals.bf_temporary_ban_enabled:
        try: del auth_globals.bf_blacklist[remote_ip]
        except: pass

def i_log_access(message):
    if log.loglevel >= 5:
        log.access('{} {}'.format(api_environment_variables()['transaction_id'], message))

@api_event(plugin, 'global_preexecution_hook')
def global_preexecution_hook(reqHandler, action):
    
    remote_ip = i_get_client_ip(reqHandler)
    if auth_globals.bf_temporary_ban_enabled:
        if remote_ip in auth_globals.bf_blacklist and auth_globals.bf_blacklist[remote_ip]['banned_until'] > time.time():
            remaining_time = math.ceil(auth_globals.bf_blacklist[remote_ip]['banned_until'] - time.time())
            raise WebRequestException(401, 'unauthorized', 'AUTH_TOO_MANY_LOGIN_FAILS', {'remaining_time': remaining_time})
    
    auth_header = reqHandler.request.headers.get('Authorization', None)
    if auth_header is not None:
        r_auth_header = auth_header.split(' ')
        
        if(r_auth_header[0] == "Basic"):
            time.sleep(auth_globals.bf_basic_auth_delay)
            
            credentials = base64.b64decode(r_auth_header[1]).decode("utf-8").split(':')
            
            if credentials[0] in auth_globals.users_dict:
                # User exists
                if (e_hash_password(credentials[0], credentials[1]) == auth_globals.users_dict[credentials[0]]['h_password']):
                    # Passwort correct
                    auth_globals.current_user = credentials[0]
                    auth_globals.auth_type = "basic"

                    if not 'users' in action:
                        log.error('Permission lookup table not found.')
                        log.debug('You likely have a duplicated function name ({}).'.format(action['name']))
                        raise WebRequestException(500, 'error', 'GENERAL_INTERNAL_SERVER_ERROR')

                    elif auth_globals.current_user in action['users']:
                        # User permitted
                        i_log_access('authorized as {} via {}'.format(auth_globals.current_user, auth_globals.auth_type))
                        i_reset_ban_time(remote_ip)
                        return

                    raise WebRequestException(401, 'unauthorized', 'AUTH_PERMISSIONS_DENIED')
                
            unauthorized_error(401, 'unauthorized', 'AUTH_WRONG_PASSWORD_OR_USERNAME', remote_ip)
        
        elif(r_auth_header[0] == "Bearer"):
            # Generate Hash
            h_token = e_hash_password('', r_auth_header[1])

            if h_token in auth_globals.user_token_dict:
                # Token exists/correct
                auth_globals.current_user = auth_globals.user_token_dict[h_token]['username']
                auth_globals.auth_type = "token"
                auth_globals.current_token = h_token

                if not 'token' in action:
                    log.error('Permission lookup table not found.')
                    log.debug('You likely have a duplicated function name ({}).'.format(action['name']))
                    raise WebRequestException(500, 'error', 'GENERAL_INTERNAL_SERVER_ERROR')

                elif h_token in action['token']:
                    # Token permitted
                    i_log_access('authorized as {} via token {}'.format(auth_globals.current_user, auth_globals.user_token_dict[h_token]['token_name']))
                    i_reset_ban_time(remote_ip)
                    return

                raise WebRequestException(401, 'unauthorized', 'AUTH_PERMISSIONS_DENIED')

    if action['name'] == "auth.create_session":
        raw_body = reqHandler.request.body.decode('utf8')
        try:
            if raw_body == "":
                body = {}
            else:
                body = tornado.escape.json_decode(raw_body)

        except ValueError as e:
            raise WebRequestException(400, 'error', 'GENERAL_MALFORMED_JSON')

        if 'username' in body and 'password' in body:
            # Password in body
            time.sleep(auth_globals.bf_basic_auth_delay)
            if body['username'] in auth_globals.users_dict and e_hash_password(body['username'], body['password']) == auth_globals.users_dict[body['username']]['h_password']:
                # User exists/password correct

                auth_globals.current_user = body['username']
                auth_globals.auth_type = "basic"
                if auth_globals.current_user in action['users']:
                    # User permitted
                    i_log_access('authorized as {} via {}'.format(auth_globals.current_user, auth_globals.auth_type))
                    i_reset_ban_time(remote_ip)
                    return
            unauthorized_error(401, 'unauthorized', 'AUTH_WRONG_PASSWORD_OR_USERNAME', remote_ip)

        raise WebRequestException(401, 'unauthorized', 'AUTH_PERMISSIONS_DENIED')
     
    session_id = reqHandler.get_cookie("session_id")
    if session_id:
        if session_id in auth_globals.session_dict:
            
            if 'last_csrf_token' in auth_globals.session_dict[session_id]:
                csrf_token = reqHandler.request.headers.get('X-CSRF-TOKEN', None)
                if csrf_token != auth_globals.session_dict[session_id]['last_csrf_token']:
                    unauthorized_error(401, 'unauthorized', 'AUTH_INVALID_CSRF_TOKEN', remote_ip)
                
                csrf_token = e_generate_random_string(cookie_length)
                auth_globals.session_dict[session_id]['last_csrf_token'] = csrf_token
                reqHandler.add_header('X-CSRF-TOKEN', csrf_token)
            
            auth_globals.current_user = auth_globals.session_dict[session_id]['username']
            auth_globals.auth_type = "session"
            
            if time.time() > auth_globals.session_dict[session_id]['expiration_time']:
                i_clean_expired_sessions()
                raise WebRequestException(401, 'unauthorized', 'AUTH_SESSION_EXPIRED')

            if not 'users' in action:
                log.error('Permission lookup table not found.')
                log.debug('You likely have a duplicated function name ({}).'.format(action['name']))
                raise WebRequestException(500, 'error', 'GENERAL_INTERNAL_SERVER_ERROR')

            elif auth_globals.current_user in action['users']:
                # User permitted
                i_log_access('authorized as {} via {}'.format(auth_globals.current_user, auth_globals.auth_type))
                i_reset_ban_time(remote_ip)
                return

    auth_globals.current_user = "anonymous"
    auth_globals.auth_type = "none"
    if not 'users' in action:
        log.error('Permission lookup table not found.')
        log.debug('You likely have a duplicated function name ({}).'.format(action['name']))
        raise WebRequestException(500, 'error', 'GENERAL_INTERNAL_SERVER_ERROR')

    elif auth_globals.current_user in action['users']:
        return

    raise WebRequestException(401, 'unauthorized', 'AUTH_PERMISSIONS_DENIED')
