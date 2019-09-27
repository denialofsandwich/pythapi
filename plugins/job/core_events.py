#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base

from . import header
from . import base


@core.plugin_base.event(header.plugin, 'core.terminate')
def terminate():
    job_list = list(base.JobObject.job_list)

    for job in job_list:
        job.stop()

    for job in job_list:
        if job.daemon is not True:
            job.join()

    core.plugin_base.log.info("Jobs terminated")
