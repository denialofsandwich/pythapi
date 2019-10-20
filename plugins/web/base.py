#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base
import core.casting
from . import header

from tornado import gen
import tornado.web
import tornado.concurrent
import tornado.websocket

import json
import asyncio
import os
import copy

transaction_id = 0
_status_code_to_error_id = {
    400: "ERROR_GENERAL_BAD_REQUEST",
    401: "ERROR_GENERAL_UNAUTHORIZED",
    403: "ERROR_GENERAL_FORBIDDEN",
    404: "ERROR_GENERAL_NOT_FOUND",
    405: "ERROR_GENERAL_METHOD_NOT_ALLOWED",
    500: "ERROR_GENERAL_INTERNAL"
}


# TODO: tornado.locale ausprobieren
@gen.coroutine
def execute_function_or_coroutine(f, args=None, kwargs=None):
    args = args or ()
    kwargs = kwargs or {}

    response = f(*args, **kwargs)
    if (asyncio.iscoroutinefunction(f)
        or type(response) == tornado.concurrent.Future
    ):
        response = yield response
        return response
    else:
        return response


def _get_client_ip(self):
    if self.request.remote_ip == "127.0.0.1":
        x_real_ip = self.request.headers.get("X-Real-IP")
        x_forwarded_for = self.request.headers.get("X-Forwarded-For")
        return x_real_ip or x_forwarded_for or self.request.remote_ip

    else:
        return self.request.remote_ip


def format_message(env, message):
    data = env['request_settings']

    if data['content_type'] == "application/json":
        if message is None:
            message = {}

        r_skel = copy.copy(data['output_message_format'])
        r_skel['template'] = {
            "type": dict,
            "child": {
                "status": {
                    "type": str,
                    "default": "success",
                }
            },
            "env": env,
            "type_defaults": {
                float: {
                    "type": float,
                },
                int: {
                    "type": int,
                },
                bool: {
                    "type": bool,
                },
                tuple: {
                    "type": list,
                },
                "*": {
                    "type": str,
                }
            },
        }

        if env['url_params']['_pretty'] is True:
            r_skel['template']['pretty'] = True
            r_skel['template']['sort_keys'] = True

        return core.casting.reinterpret(message, str, **r_skel) + '\n'


# TODO: Method not supported mal richtig machen
class APIBase(tornado.web.RequestHandler):
    def __init__(self, *args, **kwargs):
        self.env = {
            "request_obj": self,
        }
        tornado.web.RequestHandler.__init__(self, *args, **kwargs)

    def _handle_error(self, error_id='ERROR_GENERAL_INTERNAL', status_code=500, message="N/A", data=None, tpl=None):
        if tpl:
            error_id = tpl.get("error_id", None) or error_id
            status_code = tpl.get("status_code", None) or status_code
            message = tpl.get("message", None) or message

        data = data or {}
        data['status'] = data.get('status', 'error')
        data['error_id'] = error_id

        message = core.casting.reinterpret(message, **{
            "inheritable_parameters": [
                "pre_format",
            ],
            "pre_format": header.format_tr_table,
            "env": self.env,
        })
        data['message'] = message

        core.plugin_base.log.access("{} {} {} {}".format(self.env.get('transaction_id', -1),
                                                         data['status'],
                                                         status_code,
                                                         data['error_id']))
        response = json.dumps(data) + '\n'

        self.set_status(status_code)
        self.set_header('Server', "pythapi/{}".format(core.plugin_base.version))
        self.set_header('Content-Type', 'application/json')
        self.write(response)
        self.finish()

    def write_error(self, status_code, **kwargs):
        error_id = 'ERROR_GENERAL_UNKNOWN'
        try:
            error_id = _status_code_to_error_id[status_code]
        except KeyError:
            pass

        self._handle_error(status_code=status_code, tpl=header.plugin.web_exception_list[error_id])

    @gen.coroutine
    def _search_and_handle_request(self):
        global transaction_id
        try:
            method = self.request.method
            path = self.request.path[len(header.request_prefix_table[self.request.host.split(':')[1]]):]
            self.env.update({
                'transaction_id': transaction_id,
            })
            found = False
            for rgx, actions in header.request_event_list.items():
                i_match = rgx.match(path)
                if i_match:
                    action = actions.get(method, None)
                    if not action:
                        self._handle_error(tpl=header.plugin.web_exception_list['ERROR_GENERAL_METHOD_NOT_ALLOWED'])
                        return

                    f = action[0]
                    data = action[1]
                    found = True

                    self.env.update({
                        'request_settings': data,
                        'match_data': i_match,
                        'response': None,
                    })

                    core.plugin_base.log.access("{} {} {} {}".format(self.env['transaction_id'],
                                                                     _get_client_ip(self),
                                                                     method,
                                                                     path))

                    # Execute pre_event_handlers
                    for pre_event in header.pre_request_event_list:
                        i_f = pre_event[0]
                        e_data = pre_event[1]
                        yield execute_function_or_coroutine(i_f, args=(self.env, e_data))

                    # Execute the actual request handler
                    self.env['response'] = yield execute_function_or_coroutine(f, kwargs=self.env)

                    # Execute post_event_handlers
                    for post_event in reversed(header.post_request_event_list):
                        i_f = post_event[0]
                        e_data = post_event[1]

                        yield execute_function_or_coroutine(i_f, args=(self.env, e_data))
            if not found:
                self._handle_error(tpl=header.plugin.web_exception_list['ERROR_GENERAL_NOT_FOUND'])

        except core.casting.CastingException as e:
            data = {'path': e.path}
            data.update(e.data)
            self._handle_error('ERROR_GENERAL_FORMAT', 400, str(e), data)
        except header.WebRequestException as e:
            data = {
                'error_id': e.error_id,
            }
            data.update(e.data)
            self._handle_error(e.error_id, e.status_code, e.message, data)
        except Exception as e:
            core.plugin_base.log.error("An exception occured.", exc_info=e)
            self._handle_error(tpl=header.plugin.web_exception_list['ERROR_GENERAL_INTERNAL'])
        finally:
            transaction_id += 1

            self.finish()

    @gen.coroutine
    def method_tpl(self, **kwargs):
        yield self._search_and_handle_request()


class WebSocketBase(tornado.websocket.WebSocketHandler):
    ws_obj = None
    is_open = False

    def __init__(self, *args, **kwargs):
        self.env = {
            "request_obj": self,
        }
        tornado.websocket.WebSocketHandler.__init__(self, *args, **kwargs)

    def _handle_error(self, error_id='ERROR_GENERAL_INTERNAL', status_code=500, message="N/A", data=None, fatal=True, tpl=None):
        if tpl:
            error_id = tpl.get("error_id", None) or error_id
            status_code = tpl.get("status_code", None) or status_code
            message = tpl.get("message", None) or message

        data = data or {}
        data['status'] = data.get('status', 'error')
        data['error_id'] = error_id

        message = core.casting.reinterpret(message, **{
            "inheritable_parameters": [
                "pre_format",
            ],
            "pre_format": header.format_tr_table,
            "env": self.env,
        })
        data['message'] = message

        if fatal:
            core.plugin_base.log.access("{} {} {} {}".format(self.env.get('transaction_id', -1),
                                                             data['status'],
                                                             status_code,
                                                             data['error_id']))

        response = json.dumps(data) + '\n'
        self.write_message(response)

        if fatal:
            self.close(status_code)

    @gen.coroutine
    def send_message(self, message):
        self.env['response'] = message

        if message is not None:
            # Execute post_event_handlers
            for post_event in reversed(header.websocket_post_message_event_list):
                i_f = post_event[0]
                e_data = post_event[1]

                yield execute_function_or_coroutine(i_f, args=(self.env, e_data))

    @gen.coroutine
    def open(self):
        global transaction_id

        try:
            path = self.request.path[len(header.request_prefix_table[self.request.host.split(':')[1]]):]
            self.env.update({
                'transaction_id': transaction_id,
                'send_message': self.send_message,
            })
            for action in header.websocket_event_list:
                i_match = action[0].match(path)
                if i_match:
                    f = action[1]
                    data = action[2]

                    self.env.update({
                        'request_settings': data,
                        'match_data': i_match,
                        'response': None,
                    })

                    core.plugin_base.log.access("{} {} {} {}".format(self.env['transaction_id'],
                                                                     _get_client_ip(self),
                                                                     "SOCKOPEN",
                                                                     path))

                    # Execute pre_event_handlers
                    for pre_event in header.websocket_pre_open_event_list:
                        i_f = pre_event[0]
                        e_data = pre_event[1]

                        yield execute_function_or_coroutine(i_f, args=(self.env, e_data))

                    # Execute the actual request handler
                    self.env['ws_obj'] = self.ws_obj = f()
                    if hasattr(self.ws_obj, 'on_open'):
                        response = yield execute_function_or_coroutine(self.ws_obj.on_open, kwargs=self.env)
                        yield self.send_message(response)

                    self.is_open = True

        except core.casting.CastingException as e:
            data = {
                'path': e.path,
            }
            data.update(e.data)
            self._handle_error('ERROR_GENERAL_FORMAT', 400, str(e), data)
        except header.WebRequestException as e:
            data = {
                'error_id': e.error_id,
            }
            data.update(e.data)
            self._handle_error(e.error_id, e.status_code, e.message, data)
        except Exception as e:
            core.plugin_base.log.error("An exception occured.", exc_info=e)
            self._handle_error(tpl=header.plugin.web_exception_list['ERROR_GENERAL_INTERNAL'])
        finally:
            transaction_id += 1

    @gen.coroutine
    def on_message(self, message):
        try:
            self.env['message_data'] = message

            # Execute pre_event_handlers
            for pre_event in header.websocket_pre_message_event_list:
                i_f = pre_event[0]
                e_data = pre_event[1]

                yield execute_function_or_coroutine(i_f, args=(self.env, e_data))

            # Execute the actual request handler
            if hasattr(self.ws_obj, 'on_message'):
                response = yield execute_function_or_coroutine(self.ws_obj.on_message, kwargs=self.env)
                yield self.send_message(response)

        except core.casting.CastingException as e:
            data = {
                'path': e.path,
            }
            data.update(e.data)
            self._handle_error('ERROR_GENERAL_FORMAT', 400, str(e), data, False)
        except header.WebRequestException as e:
            data = {
                'error_id': e.error_id,
            }
            data.update(e.data)
            self._handle_error(e.error_id, e.status_code, e.message, data, e.data.get('fatal', False))
        except Exception as e:
            core.plugin_base.log.error("An exception occured.", exc_info=e)
            self._handle_error(tpl=header.plugin.web_exception_list['ERROR_GENERAL_INTERNAL'])

    def on_close(self):
        try:
            if not self.is_open:
                return

            core.plugin_base.log.access("{} {}".format(self.env['transaction_id'], "SOCKCLOSE"))

            # Execute the actual request handler
            if hasattr(self.ws_obj, 'on_close'):
                self.ws_obj.on_close(**self.env)

            # Execute post_event_handlers
            for post_event in reversed(header.websocket_close_event_list):
                i_f = post_event[0]
                e_data = post_event[1]

                i_f(self.env, e_data)

        except Exception as e:
            core.plugin_base.log.error("An exception occured.", exc_info=e)
            self._handle_error(tpl=header.plugin.web_exception_list['ERROR_GENERAL_INTERNAL'])


class ServeMainPageHandler(tornado.web.RequestHandler):
    base_dir = "/var/www/html"

    def get(self, status_code, **kwargs):
        self.render(os.path.join(self.base_dir, "index.html"))
