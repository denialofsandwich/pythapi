#!/usr/bin/python3
# -*- coding: utf-8 -*-

import core.plugin_base
import core.casting
from . import header

from tornado import gen
import tornado.web
import tornado.concurrent

import json
import asyncio


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


class APIBase(tornado.web.RequestHandler):
    transaction_id = 0
    _status_code_to_error_id = {
        400: "ERROR_GENERAL_BAD_REQUEST",
        401: "ERROR_GENERAL_UNAUTHORIZED",
        403: "ERROR_GENERAL_FORBIDDEN",
        404: "ERROR_GENERAL_NOT_FOUND",
        405: "ERROR_GENERAL_METHOD_NOT_ALLOWED",
        500: "ERROR_GENERAL_INTERNAL"
    }

    def _get_client_ip(self):
        if self.request.remote_ip == "127.0.0.1":
            x_real_ip = self.request.headers.get("X-Real-IP")
            x_forwarded_for = self.request.headers.get("X-Forwarded-For")
            return x_real_ip or x_forwarded_for or self.request.remote_ip

        else:
            return self.request.remote_ip

    def _handle_error(self, status_code=500, error_code=None, data=None):
        data = data or {}
        data['status'] = data.get('status', 'error')
        data['error_code'] = error_code or APIBase._status_code_to_error_id[status_code]

        core.plugin_base.log.access("{} {} {} {}".format(self.env['transaction_id'], data['status'], status_code, data['error_code']))
        response = json.dumps(data) + '\n'

        self.set_status(status_code)
        self.set_header('Server', "pythapi/{}".format(core.plugin_base.version))
        self.set_header('Content-Type', 'application/json')
        self.write(response)

    def write_error(self, status_code, **kwargs):
        error_id = 'ERROR_GENERAL_UNKNOWN'
        try:
            error_id = APIBase._status_code_to_error_id[status_code]
        except KeyError:
            pass

        self._handle_error(status_code, error_id, {})

    @gen.coroutine
    def _search_and_handle_request(self):
        # TODO: Custom Methods
        try:
            method = self.request.method
            uri = self.request.uri
            found = False
            for action in header.request_event_list[method]:
                i_match = action[0].match(uri)
                if i_match:
                    f = action[1]
                    data = action[2]
                    found = True

                    self.env = {
                        'request_obj': self,
                        'request_settings': data,
                        'match_data': i_match,
                        'transaction_id': APIBase.transaction_id,
                    }

                    core.plugin_base.log.access("{} {} {} {}".format(self.env['transaction_id'], self._get_client_ip(), method, uri))

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
                self._handle_error(404, None, {
                    'message': "Request doesn't exist.",
                })

        except core.casting.CastingException as e:
            data = {
                'message': str(e),
                'path': e.path,
            }
            data.update(e.data)
            self._handle_error(400, 'ERROR_GENERAL_FORMAT', data)
        except Exception as e:
            core.plugin_base.log.error("An exception occured.", exc_info=e)
            self._handle_error(500, None, {
                'message': "Internal Server Error."
            })
        finally:
            APIBase.transaction_id += 1
            if APIBase.transaction_id > 65535:
                APIBase.transaction_id = 0

        self.finish()

    @gen.coroutine
    def get(self, **kwargs):
        yield self._search_and_handle_request()

    @gen.coroutine
    def post(self, **kwargs):
        yield self._search_and_handle_request()

    @gen.coroutine
    def put(self, **kwargs):
        yield self._search_and_handle_request()

    @gen.coroutine
    def delete(self, **kwargs):
        yield self._search_and_handle_request()

    @gen.coroutine
    def options(self, **kwargs):
        yield self._search_and_handle_request()

    @gen.coroutine
    def head(self, **kwargs):
        yield self._search_and_handle_request()
