#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import logging
import copy

# "ACCESS": "[\033[95m{:^8}\033[0m]{}", # 15
# "SUCCESS": "\033[93m[\033[32m{:^8}\033[0m\033[93m]\033[32m{}", # 25


class FancyLogger(logging.Logger):
    color_codes = {
        "DEBUG": "[\033[94m{:^8}\033[0m]{}",
        "INFO": "[\033[92m{:^8}\033[0m]{}",
        "WARNING": "[\033[93m{:^8}\033[0m]{}",
        "ERROR": "[\033[31m{:^8}\033[0m]{}",
        "CRITICAL": "\033[93m[\033[31m{:^8}\033[0m\033[93m]\033[31m{}",
    }
    levelname_to_level = {

    }
    indent = 0

    class ColoredFormatter(logging.Formatter):
        def __init__(self, msg, master, fancy=True):
            logging.Formatter.__init__(self, msg)
            self.master = master
            self.fancy = fancy

        def format(self, record):
            record = copy.copy(record)
            levelname = record.levelname
            if self.fancy and levelname in self.master.color_codes:
                record.levelname = self.master.color_codes[levelname].format(levelname, ' .' * self.master.indent)
                record.msg = str(record.msg).replace('\n', '\n' + ' ' * (11 + 2 * self.master.indent))

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

    def __init__(self, fancy_mode, loglevel, show_timestamp, logging_enabled, logfile_path):
        self.interposer_list = []
        self.loglevel = 0
        self.fancy = fancy_mode
        self.indent = 0

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

        if show_timestamp:
            self.print_str = "%(asctime)s %(levelname)s %(message)s"
        else:
            self.print_str = "%(levelname)s %(message)s"

        self.set_fancy(fancy_mode)

        self.addHandler(self.LoggingFunctionExecutor(self.interposer_list))
        self.addHandler(self.sout)

    def create_loglevel(self, name, level, pretty_format="[\033[95m{:^8}\033[0m]{}"):
        logging.addLevelName(level, name.upper())
        self.color_codes[name.upper()] = pretty_format
        setattr(self, name.lower(), lambda *a: self.log(level, *a))

    def set_indent(self, num):
        if not self.fancy:
            return

        self.indent += num

        if self.indent < 0:
            self.indent = 0

    def set_fancy(self, flag):
        self.fancy = flag
        self.sout.setFormatter(
            self.ColoredFormatter(self.print_str, self, fancy=flag)
        )

    def set_loglevel(self, loglevel):

        if loglevel < 0:
            loglevel = 0

        self.loglevel = loglevel
        self.setLevel(loglevel)

    def add_interposer(self, f):
        self.interposer_list.append(f)
