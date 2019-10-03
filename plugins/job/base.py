#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import core.plugin_base
from . import header

import threading
import datetime
import re


@core.plugin_base.external(header.plugin)
class MisconfigurationException(Exception):
    def __init__(*args, **kwargs):
        Exception.__init__(*args, **kwargs)


@core.plugin_base.external(header.plugin)
class JobObject(threading.Thread):

    _format_table = {
        1: {},  # Seconds
        60: {  # Minutes
            r"^\d{2}$": "%S",
        },
        60*60: {  # Hours
            r"^\d{2}$": "%M",
            r"^\d{2}:\d{2}$": "%M:%S",
        },
        24*60*60: {  # Days
            r"^\d{2}$": "%H",
            r"^\d{2}:\d{2}$": "%H:%M",
            r"^\d{2}:\d{2}:\d{2}$": "%H:%M:%S",
        },
        7*24*60*60: {  # Weeks
            r"^\d$": "%w",
            r"^[a-zA-Z]{2,3}$": "%a",
            r"^[a-zA-Z]{4,}$": "%A",
            r"^\d \d{2}$": "%w %H",
            r"^[a-zA-Z]{2,3} \d{2}$": "%a %H",
            r"^[a-zA-Z]{4,} \d{2}$": "%A %H",
            r"^\d \d{2}:\d{2}$": "%w %H:%M",
            r"^[a-zA-Z]{2,3} \d{2}:\d{2}$": "%a %H:%M",
            r"^[a-zA-Z]{4,} \d{2}:\d{2}$": "%A %H:%M",
            r"^\d \d{2}:\d{2}:\d{2}$": "%w %H:%M:%S",
            r"^[a-zA-Z]{2,3} \d{2}:\d{2}:\d{2}$": "%a %H:%M:%S",
            r"^[a-zA-Z]{4,} \d{2}:\d{2}:\d{2}$": "%A %H:%M:%S",
        }
    }

    def _build_target_time(self, time_str, time_format):
        target_time = datetime.datetime.strptime(time_str, time_format)
        current = datetime.datetime.now()

        # Determine the highest Unit
        rank = 0
        if any(x in time_format for x in ['%w', '%a', '%A']):
            rank = -1
            weekday = datetime.datetime.strptime("00 " + time_str, "%U " + time_format).weekday()
        elif time_format.find('%H') != -1:
            rank = 1
        elif time_format.find('%M') != -1:
            rank = 2
        elif time_format.find('%S') != -1:
            rank = 3

        # Substitute based on the determined rank
        if rank >= 3:
            target_time = target_time.replace(minute=current.minute)
        if rank >= 2:
            target_time = target_time.replace(hour=current.hour)
        if rank >= 1 or rank == -1:
            target_time = target_time.replace(day=current.day, month=current.month, year=current.year)

        if rank == -1:
            target_time = target_time + datetime.timedelta(weekday - current.weekday(), 0)

            if target_time < current:
                target_time = target_time + datetime.timedelta(7, 0)

        # Adding offset based on rank if needed
        if target_time < current:
            target_time = target_time + datetime.timedelta(0, self.unit)

        core.plugin_base.log.debug("First Execution at: {}".format(target_time))
        return target_time

    def remove(self):
        try:
            del header.plugin.job_table[self.name]

            if self.is_alive():
                self.stop()
                self.join()

        except KeyError:
            raise RuntimeError("Job already removed.")

    def run(self) -> None:
        try:
            if self.interval != 0:
                if self.unit is None:
                    raise MisconfigurationException("Interval unit undefined.")

                total_interval = self.unit * self.interval
                if self.target_time is None:
                    self.target_time = datetime.datetime.now() + datetime.timedelta(0, total_interval)

                while True:
                    delta = self.target_time - datetime.datetime.now()
                    self.term_event.wait(delta.total_seconds())

                    if self.term_event.is_set():
                        break

                    try:
                        self.running = True
                        self.target(*self.args, **self.kwargs)
                    except Exception as e:
                        core.plugin_base.log.error("A Job crashed just now", exc_info=e)
                        self.exception = e
                    finally:
                        self.running = False

                    self.target_time = self.target_time + datetime.timedelta(0, total_interval)

            if self.interval == 0:
                self.running = True
                self.target(*self.args, **self.kwargs)

        except Exception as e:
            core.plugin_base.log.error("A Job crashed just now", exc_info=e)
            self.exception = e
        finally:
            self.running = False
            if self.autoremove:
                del header.plugin.job_table[self.name]

    def __init__(self, target=None, args=(), tkwargs=None, autoremove=True, **kwargs):
        tkwargs = tkwargs or {}
        tkwargs['_thread'] = self

        self.term_event = threading.Event()
        self.target = target
        self.args = args
        self.kwargs = tkwargs
        self.autoremove = autoremove

        self.running = False
        self.interval = 0
        self.unit = None
        self.target_time = None
        self.exception = None

        super().__init__(**kwargs)

        if self.name in header.plugin.job_table:
            raise MisconfigurationException("Job Name already exist.")

        header.plugin.job_table[self.name] = self

    def stop(self):
        if self.is_alive():
            self.term_event.set()

    def every(self, interval=1):
        self.interval = interval
        return self

    def at(self, time_str, time_format=None):
        if time_format is None:
            if self.unit is None:
                raise MisconfigurationException("Interval unit undefined.")

            # Search matching time format
            for rgx, fmt in self._format_table[self.unit].items():
                if re.match(rgx, time_str):
                    time_format = fmt
                    break

            if not time_format:
                raise MisconfigurationException("Invalid time format.")

        self.target_time = self._build_target_time(time_str, time_format)
        return self

    @property
    def seconds(self):
        self.unit = 1
        return self

    @property
    def second(self):
        return self.seconds

    @property
    def minutes(self):
        self.unit = 60
        return self

    @property
    def minute(self):
        return self.minutes

    @property
    def hours(self):
        self.unit = 60 * 60
        return self

    @property
    def hour(self):
        return self.hours

    @property
    def days(self):
        self.unit = 60 * 60 * 24
        return self

    @property
    def day(self):
        return self.days

    @property
    def weeks(self):
        self.unit = 60 * 60 * 24 * 7
        return self

    @property
    def week(self):
        return self.weeks

    @property
    def status(self):
        if not self.is_alive() and not self._is_stopped:
            return "initial"

        if self.running is True:
            return "running"

        if self.exception is not None:
            return "crashed"

        if self.is_alive():
            return "sleeping"

        return "stopped"


