#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base

from . import header


@core.plugin_base.event(header.plugin, 'core.terminate')
def terminate():
    job_table = dict(header.plugin.job_table)

    for job_name, job in job_table.items():
        job.stop()

    for job_name, job in job_table.items():
        if not job.daemon and job.is_alive():
            job.join()

    for job_name, job in list(header.plugin.job_table.items()):
        job.remove()

    core.plugin_base.log.info("Jobs terminated")
