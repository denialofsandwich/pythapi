#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest

import core.tests.tools
import core.plugin_base

import datetime
import time
import requests


base_url = "http://127.0.0.1:18223"


@pytest.fixture(scope='function')
def cs_bare():
    yield core.tests.tools.CoreSystem()


def _job_base_conf_gen():
    return {
        "core.general": {
            "loglevel": 6,
            "additional_plugin_paths": "plugins/job/tests/plugins",
            "enabled_plugins": "web, job, debug_job",
        },
        "web": {
            "binds": """{
                        "ip": "127.0.0.1",
                        "port": 18223
                    }""",
        }
    }


@pytest.fixture(scope='function')
def job_base_conf():
    yield _job_base_conf_gen()


@pytest.fixture(scope='class')
def core_system():
    cs = core.tests.tools.CoreSystem()
    cs.conf = _job_base_conf_gen()

    with cs:
        yield cs


def test_termination_event(cs_bare, job_base_conf):
    cs_bare.conf = job_base_conf

    with cs_bare:
        job = core.plugin_base.plugin_dict['job']

        def func(**kwargs):
            stop_event = kwargs['_thread'].term_event
            stop_event.wait()

        t = job.JobObject(name="test_job", target=func, autoremove=False)
        t.start()

    assert job.job_table == {}


class TestSeries:
    def test_job_start(self, core_system):
        job = core.plugin_base.plugin_dict['job']
        value = 0

        def func(val, **kwargs):
            nonlocal value
            value = val

            stop_event = kwargs['_thread'].term_event
            stop_event.wait()

        t = job.JobObject(name="test_job", target=func, args=(5,))
        assert t.status == "initial"

        with pytest.raises(job.MisconfigurationException):
            t2 = job.JobObject(name="test_job", target=func, args=(5,))

        t.start()
        time.sleep(0.01)
        assert t.status == "running"

        t.stop()
        t.join()
        assert t.status == "stopped"

        assert value == 5

    def test_job_persistent(self, core_system):
        job = core.plugin_base.plugin_dict['job']
        value = 0

        def func(val, **kwargs):
            nonlocal value
            value = val

            stop_event = kwargs['_thread'].term_event
            stop_event.wait()

        t = job.JobObject(name="test_job", target=func, args=(5,), autoremove=False)
        assert t.status == "initial"

        t.start()
        time.sleep(0.01)
        assert t.status == "running"

        t.stop()
        t.join()

        assert value == 5
        assert t.status == "stopped"

        t.remove()

    def test_job_interval(self, core_system):
        job = core.plugin_base.plugin_dict['job']

        def func(**kwargs):
            pass

        t = job.JobObject(name="test_job", target=func).every(2).day

        assert t.interval == 2
        assert t.unit == 60*60*24

        t.remove()

    def test_job_units(self):
        job = core.plugin_base.plugin_dict['job']

        def func(**kwargs):
            pass

        t = job.JobObject(name="test_job", target=func, autoremove=False).every()

        t.start()
        t.join()
        time.sleep(0.01)

        assert t.status == "crashed"
        assert str(t.exception) == "Interval unit undefined."

        assert t.second.unit == 1
        assert t.seconds.unit == 1
        assert t.minute.unit == 60
        assert t.minutes.unit == 60
        assert t.hour.unit == 60 * 60
        assert t.hours.unit == 60 * 60
        assert t.day.unit == 60 * 60 * 24
        assert t.days.unit == 60 * 60 * 24
        assert t.week.unit == 60 * 60 * 24 * 7
        assert t.weeks.unit == 60 * 60 * 24 * 7

        t.remove()

        with pytest.raises(RuntimeError):
            t.remove()

    def test_job_status(self):
        job = core.plugin_base.plugin_dict['job']

        def func(**kwargs):
            pass

        def func_wait(**kwargs):
            stop_event = kwargs['_thread'].term_event
            stop_event.wait()

        t = job.JobObject(name="test_job", target=func).every(4).weeks
        assert t.status == "initial"

        t.start()
        time.sleep(0.01)
        assert t.status == "sleeping"
        t.remove()

        t = job.JobObject(name="test_job", target=func_wait)
        t.start()
        time.sleep(0.01)
        assert t.status == "running"
        t.remove()

    def test_job_format_error(self):
        job = core.plugin_base.plugin_dict['job']

        def func(**kwargs):
            pass

        t = job.JobObject(name="test_job", target=func)

        with pytest.raises(job.MisconfigurationException) as e1:
            t.at("16:00")

        assert str(e1.value) == "Interval unit undefined."

        with pytest.raises(job.MisconfigurationException) as e:
            t.every().day.at("Gamma Omega")

        assert str(e.value) == "Invalid time format."

        t.remove()

    def test_job_at_next_minute(self, core_system):
        job = core.plugin_base.plugin_dict['job']

        def func(**kwargs):
            pass

        t = job.JobObject(name="test_job", target=func).every().minute.at('15')
        t.start()

        desired_target = datetime.datetime.now().replace(second=15, microsecond=0)
        if desired_target < datetime.datetime.now():
            desired_target += datetime.timedelta(0, 60)

        assert t.target_time == desired_target
        assert t.interval == 1
        assert t.unit == 60

        t.remove()

    def test_job_at_next_hour(self, core_system):
        job = core.plugin_base.plugin_dict['job']

        def func(**kwargs):
            pass

        t = job.JobObject(name="test_job", target=func).every().hour.at('15')
        t.start()

        desired_target = datetime.datetime.now().replace(minute=15, second=0, microsecond=0)
        if desired_target < datetime.datetime.now():
            desired_target += datetime.timedelta(0, 60*60)

        assert t.target_time == desired_target
        assert t.interval == 1
        assert t.unit == 60*60

        t.remove()

    def test_job_at_next_day(self, core_system):
        job = core.plugin_base.plugin_dict['job']

        def func(**kwargs):
            pass

        t = job.JobObject(name="test_job", target=func).every().day.at('10:25')
        t.start()

        desired_target = datetime.datetime.now().replace(hour=10, minute=25, second=0, microsecond=0)
        if desired_target < datetime.datetime.now():
            desired_target += datetime.timedelta(0, 60*60*24)

        assert t.target_time == desired_target
        assert t.interval == 1
        assert t.unit == 60*60*24

        t.remove()

    def test_job_at_next_monday(self, core_system):
        job = core.plugin_base.plugin_dict['job']

        def func(**kwargs):
            pass

        t = job.JobObject(name="test_job", target=func).every().week.at('Monday 00:05')
        t.start()

        assert t.target_time.strftime("%A %H:%M") == "Monday 00:05"
        assert t.interval == 1
        assert t.unit == 60*60*24*7

        t.remove()

    def test_job_scheduled_general(self, core_system):
        job = core.plugin_base.plugin_dict['job']
        value = 0

        def func(**kwargs):
            nonlocal value
            if value == 0:
                value = 5
            elif value == 10:
                raise Exception("I'm outta here.")

        t = job.JobObject(name="test_job", target=func).every().second
        t.start()

        time.sleep(1.1)
        assert value == 5

        value = 10
        time.sleep(1.1)
        assert t.status == "crashed"
        assert str(t.exception) == "I'm outta here."

        t.remove()

    def test_list_jobs(self, core_system):
        debug_job = core.plugin_base.plugin_dict['debug_job']
        debug_job.create_basic_job("test1")
        debug_job.create_basic_job("test2")

        response = requests.get(base_url + "/job/list").json()
        assert set(response['data']) == {"test1", "test2"}

        debug_job.remove_job("test1")
        debug_job.remove_job("test2")

    def test_list_jobs_verbose(self, core_system):
        debug_job = core.plugin_base.plugin_dict['debug_job']
        debug_job.create_basic_job("test1")
        debug_job.create_basic_job("test2")

        response = requests.get(base_url + "/job/list?verbose=true").json()
        assert response == {
            "data": {
                "test1": {
                    "name": "test1",
                    "status": "running",
                    "func_name": "trd",
                    "type": "one_shot",
                },
                "test2": {
                    "name": "test2",
                    "status": "running",
                    "func_name": "trd",
                    "type": "one_shot",
                }
            },
            "status": "success"
        }

        debug_job.remove_job("test1")
        debug_job.remove_job("test2")

    def test_get_job(self, core_system):
        debug_job = core.plugin_base.plugin_dict['debug_job']
        debug_job.create_basic_job("test1")

        response = requests.get(base_url + "/job/id/test1").json()
        assert response == {
            "data": {
                "name": "test1",
                "status": "running",
                "func_name": "trd",
                "type": "one_shot",
            },
            "status": "success"
        }

        response = requests.get(base_url + "/job/id/test2").json()
        assert response == {
            "status": "error",
            "error_id": "ERROR_JOB_NOT_FOUND",
            "message": "Job \"test2\" does not exist.",
            "job_name": "test2",
        }

        debug_job.remove_job("test1")

    def test_get_periodic_job(self, core_system):
        debug_job = core.plugin_base.plugin_dict['debug_job']
        debug_job.create_scheduled_job("test1")

        next_run = datetime.datetime.now().replace(hour=3, minute=35, second=0, microsecond=0)
        if next_run < datetime.datetime.now():
            next_run += datetime.timedelta(1, 0)

        response = requests.get(base_url + "/job/id/test1").json()
        assert response == {
            "data": {
                "name": "test1",
                "status": "sleeping",
                "func_name": "trd",
                "type": "periodic",
                "next_run": str(next_run),
                "interval": 2,
                "interval_unit": "day",
            },
            "status": "success"
        }

        debug_job.remove_job("test1")

    def test_delete_job(self, core_system):
        debug_job = core.plugin_base.plugin_dict['debug_job']
        job = core.plugin_base.plugin_dict['job']

        debug_job.create_basic_job("test1")

        response = requests.delete(base_url + "/job/id/test1").json()
        assert response == {"status": "success"}
        assert job.job_table == {}
