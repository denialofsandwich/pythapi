#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base
from . import header


interval_to_unit_name = {
    1: "second",
    60: "minute",
    60 * 60: "hour",
    60 * 60 * 24: "day",
    60 * 60 * 24 * 7: "week",
}


def i_get_job_info(job_name):
    job_obj = header.plugin.job_table[job_name]

    return_data = {
        "name": job_obj.name,
        "status": job_obj.status,
        "func_name": job_obj.target.__name__,
        "type": ("one_shot" if job_obj.interval == 0 else "periodic"),
    }

    if job_obj.interval != 0:
        return_data['next_run'] = job_obj.target_time
        return_data['interval'] = job_obj.interval
        return_data['interval_unit'] = interval_to_unit_name[job_obj.unit]

    return return_data


@core.plugin_base.event(header.plugin, 'web.init')
def web_init(event_data):
    web = core.plugin_base.plugin_dict['web']

    @core.plugin_base.external(header.plugin)
    class JobNotFoundException(web.WebRequestException):
        def __init__(self, job_name, **kwargs):
            web.WebRequestException.__init__(self,
                                             error_id='ERROR_JOB_NOT_FOUND',
                                             status_code=400,
                                             message={
                                                 "_tr": True,
                                                 "EN": "Job \"{}\" does not exist.".format(job_name),
                                                 "DE": "Job \"{}\" existiert nicht.".format(job_name)
                                             }, data={
                                                  "job_name": job_name
                                             }, **kwargs)

    @core.plugin_base.event(header.plugin, 'web.request', {
        "path": "/list",
        "method": "GET",
        "url_params": {
            "child": {
                "verbose": web.web_template_table['verbose']
            }
        }
    })
    def list_jobs_request(url_params, **kwargs):
        if url_params['verbose']:
            data = {}
            for job_name in header.plugin.job_table:
                data[job_name] = i_get_job_info(job_name)
        else:
            data = []
            for job_name in header.plugin.job_table:
                data.append(job_name)

        return {
            "data": data,
        }

    @core.plugin_base.event(header.plugin, 'web.request', {
        "path": "/id/*",
        "method": "GET",
        "path_params": {
            "child": [
                header.plugin.web_template_table['job_obj']
            ]
        },
    })
    def get_job_request(path_params, **kwargs):
        return {
            "data": i_get_job_info(path_params[0]),
        }

    @core.plugin_base.event(header.plugin, 'web.request', {
        "path": "/id/*",
        "method": "DELETE",
        "path_params": {
            "child": [
                header.plugin.web_template_table['job_obj']
            ]
        },
    })
    def delete_job_request(path_params, **kwargs):
        job_obj = header.plugin.job_table[path_params[0]]
        job_obj.remove()
