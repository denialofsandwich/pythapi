#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: auth.py
# Author:      Rene Fa
# Date:        03.01.2019
# Version:     1.6
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

import sys
sys.path.append("..")
from api_plugin import *

from .header import *

import copy

@api_external_function(plugin)
def i_default_permission_validator(ruleset, section, target_rule):

    if not section in ruleset:
        return 0
    
    if '*' in ruleset[section]:
        return 1

    if target_rule in ruleset[section]:
        return 1

    for rule in list(ruleset[section]):
        if rule[-1] == '*' and rule[:-2] == target_rule[:len(rule)-2]:
            return 1

    return 0

def i_permission_reduce_handler(ruleset):
    section = 'permissions'
    if section in ruleset:
        ruleset[section] = list(set(ruleset[section]))

        if '*' in ruleset[section]:
            ruleset[section] = ['*']
        else:
            for rule in list(ruleset[section]):
                if rule[-1] == '*':
                    for sub_rule in list(ruleset[section]):
                        if sub_rule != rule and rule[:-2] in [sub_rule, sub_rule[:len(rule)-2]]:
                            ruleset[section].remove(sub_rule)

    section = 'inherit'
    if section in ruleset:
        ruleset[section] = list(set(ruleset[section]))

    return ruleset

def i_subset_permission_handler(ruleset, subset):
    return_subset = {}

    section = 'permissions'
    if section in ruleset and section in subset:
        if '*' in ruleset[section]:
            return_subset[section] = list(subset[section])
        else:
            return_subset[section] = []

        for rule in ruleset[section]:
            if rule[-1] == '*':
                for ss_rule in list(subset[section]):
                    if rule[:-2] in [ss_rule, ss_rule[:len(rule)-2]]:
                        return_subset[section].append(ss_rule)
            elif rule in subset[section]:
                return_subset[section].append(rule)

    section = 'inherit'
    if section in ruleset and section in subset:
        return_subset[section] = []
        
        for rule in ruleset[section]:
            if rule in subset[section]:
                return_subset[section].append(rule)

    return return_subset
