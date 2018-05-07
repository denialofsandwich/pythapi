#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        fancy_logs.py
# Author:      Rene Fa
# Date:        17.04.2018
# Version:     0.6
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
fancy_mode = False
loglevel = 2

def init():
    global fancy_mode
    if(os.name == "posix"): fancy_mode = True

class cc:
    DEBUG    = '\033[94m'
    INFO     = '\033[92m'
    SUCCESS  = '\033[32m'
    HEADER   = '\033[92m'
    WARNING  = '\033[93m'
    ERROR    = '\033[31m'
    END      = '\033[0m'
    
def critical(message):
    if(loglevel < 0): return

    if(fancy_mode):
        print(cc.ERROR +"[CRITICAL] " +str(message) +cc.END)
    else:
        print("[CRITICAL] " +str(message))

def error(message):
    if(loglevel < 1): return
    
    if(fancy_mode):
        print(cc.ERROR +"[ERROR]    " +cc.END +str(message))
    else:
        print("[ERROR] " +str(message))

def warning(message):
    if(loglevel < 2): return
    
    if(fancy_mode):
        print(cc.WARNING +"[WARNING]  " +cc.END +str(message))
    else:
        print("[WARNING] " +str(message))

def success(message):
    if(loglevel < 3): return
    
    if(fancy_mode):
        print(cc.SUCCESS +"[SUCCESS]  " +str(message) +cc.END)
    else:
        print("[SUCCESS] " +str(message))

def header(message):
    if(loglevel < 3): return
    
    if(fancy_mode):
        print(cc.HEADER +"[BEGIN]    " +str(message) +cc.END)
    else:
        print("[BEGIN] " +str(message))

def info(message):
    if(loglevel < 4): return
    
    if(fancy_mode):
        print(cc.INFO +"[INFO]     " +cc.END +str(message))
    else:
        print("[INFO] " +str(message))

def debug(message):
    if(loglevel < 5): return
    
    if(fancy_mode):
        print(cc.DEBUG +"[DEBUG]    " +cc.END +str(message))
    else:
        print("[DEBUG] " +str(message))
