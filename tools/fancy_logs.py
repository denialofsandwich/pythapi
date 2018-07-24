#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        fancy_logs.py
# Author:      Rene Fa
# Date:        22.06.2018
# Version:     0.9
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

import os
import sys
import logging

color_codes = {
    'DEBUG':    '[\033[94m{}\033[0m]',
    'ACCESS':   '[\033[95m{}\033[0m]',
    'INFO':     '[\033[92m{}\033[0m]',
    'BEGIN':    '[\033[92m{}\033[0m]\033[92m   ',
    'SUCCESS':  '\033[93m[\033[32m{}\033[0m\033[93m]\033[32m ',
    'WARNING':  '[\033[93m{}\033[0m]',
    'ERROR':    '[\033[31m{}\033[0m]',
    'CRITICAL': '\033[93m[\033[31m{}\033[0m\033[93m]\033[31m'
}

tr_loglevel = {
    0: 50,
    1: 40,
    2: 30,
    3: 25,
    4: 20,
    5: 15,
    6: 10
}

interposer_list = []

class ColoredFormatter(logging.Formatter):
    def __init__(self, msg, fancy = True):
        logging.Formatter.__init__(self, msg)
        self.fancy = fancy

    def format(self, record):
        levelname = record.levelname
        if self.fancy and levelname in color_codes:
            record.levelname = color_codes[levelname].format(levelname)
            
        return logging.Formatter.format(self, record)

class LoggingFunctionExecutor(logging.StreamHandler):
    def emit(self, record):
        try:
            for f in interposer_list:
                f(record, self)
        except (KeyboardInterrupt, SystemExit):
            raise

class fancy_logger(logging.Logger):

    def __init__(self,
                 fancy_mode,
                 loglevel,
                 logging_enabled,
                 logfile_path):
        
        logging.addLevelName(15, 'ACCESS')
        logging.addLevelName(22, 'BEGIN')
        logging.addLevelName(25, 'SUCCESS')
        logging.Logger.__init__(self, 'pythapi')
        
        self.loglevel = loglevel
        
        if loglevel > 6:
            loglevel = 6
        
        loglevel = tr_loglevel[loglevel]
        
        self.setLevel(loglevel)

        if logging_enabled:
            self.fout = logging.FileHandler(logfile_path)
            self.fout.setLevel(logging.DEBUG)
            self.fout.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
            self.addHandler(self.fout)

        self.sout = logging.StreamHandler(sys.stdout)
        self.sout.setLevel(logging.DEBUG)

        if fancy_mode:
            self.sout.setFormatter(ColoredFormatter("%(levelname)-19s %(message)s\033[0m", fancy = True))

        else:
            self.sout.setFormatter(ColoredFormatter('%(levelname)s %(message)s', fancy = False))

        self.addHandler(LoggingFunctionExecutor())
        self.addHandler(self.sout)
    
    def success(self, *args):
        self.log(25, *args)

    def begin(self, *args):
        self.log(22, *args)

    def access(self, *args):
        self.log(15, *args)

    def setFancy(self, flag):
        if flag:
            self.sout.setFormatter(ColoredFormatter("%(levelname)-19s %(message)s\033[0m", fancy = True))

        else:
            self.sout.setFormatter(ColoredFormatter('%(levelname)s %(message)s', fancy = False))
        
    def setLoglevel(self, loglevel):
        
        self.loglevel = loglevel
        
        if loglevel > 6:
            loglevel = 6
        
        loglevel = tr_loglevel[loglevel]
        
        self.setLevel(loglevel)

    def addInterposer(self, f):
        interposer_list.append(f)
