#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
import logging
import copy

# TODO: Print timestamp in files

color_codes = {
    "DEBUG": "[\033[94m{:^8}\033[0m]{}",
    "ACCESS": "[\033[95m{:^8}\033[0m]{}",
    "INFO": "[\033[92m{:^8}\033[0m]{}",
    "SUCCESS": "\033[93m[\033[32m{:^8}\033[0m\033[93m]\033[32m{}",
    "WARNING": "[\033[93m{:^8}\033[0m]{}",
    "ERROR": "[\033[31m{:^8}\033[0m]{}",
    "CRITICAL": "\033[93m[\033[31m{:^8}\033[0m\033[93m]\033[31m{}",
}
_indent = 0
tr_loglevel = {0: 50, 1: 40, 2: 30, 3: 25, 4: 20, 5: 15, 6: 10}


class ColoredFormatter(logging.Formatter):
    def __init__(self, msg, fancy=True):
        logging.Formatter.__init__(self, msg)
        self.fancy = fancy

    def format(self, record):
        record = copy.copy(record)
        levelname = record.levelname
        if self.fancy and levelname in color_codes:
            record.levelname = color_codes[levelname].format(levelname, ' .'*_indent)
            record.msg = str(record.msg).replace('\n', '\n' + ' '*(11 + 2*_indent))

        formatted = logging.Formatter.format(self, record)

        if self.fancy:
            formatted = formatted + "\033[0m"

        return formatted


class LoggingFunctionExecutor(logging.StreamHandler):
    def __init__(self, interposer_list):
        logging.StreamHandler.__init__(self)
        self.interposer_list = interposer_list

    def emit(self, record):
        try:
            for f in self.interposer_list:
                f(record, self)
        except (KeyboardInterrupt, SystemExit):
            raise


class FancyLogger(logging.Logger):
    def __init__(self, fancy_mode, loglevel, logging_enabled, logfile_path):

        self.interposer_list = []
        self.loglevel = 0
        self.fancy = fancy_mode

        logging.addLevelName(15, "ACCESS")
        logging.addLevelName(25, "SUCCESS")
        logging.Logger.__init__(self, "pythapi")

        self.set_loglevel(loglevel)

        if logging_enabled:
            self.fout = logging.FileHandler(logfile_path)
            self.fout.setLevel(logging.DEBUG)
            self.fout.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)s %(message)s")
            )
            self.addHandler(self.fout)

        self.sout = logging.StreamHandler(sys.stdout)
        self.sout.setLevel(logging.DEBUG)

        self.set_fancy(fancy_mode)

        self.addHandler(LoggingFunctionExecutor(self.interposer_list))
        self.addHandler(self.sout)

    def success(self, *args):
        self.log(25, *args)

    def access(self, *args):
        self.log(15, *args)

    def indent(self, num):
        if not self.fancy:
            return

        global _indent
        _indent += num

        if _indent < 0:
            _indent = 0

    def set_fancy(self, flag):
        self.fancy = flag
        self.sout.setFormatter(
            ColoredFormatter("%(levelname)s %(message)s", fancy=flag)
        )

    def set_loglevel(self, loglevel):

        if loglevel > 6:
            loglevel = 6

        self.loglevel = loglevel

        loglevel = tr_loglevel[loglevel]

        self.setLevel(loglevel)

    def add_interposer(self, f):
        self.interposer_list.append(f)
