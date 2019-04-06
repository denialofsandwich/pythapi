#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi
# Author:      Rene Fa
# Date:        03.04.2019
#
# Copyright:   Copyright (C) 2019  Rene Fa
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

def try_strToInt(val, **kwargs):
    return try_intToInt(int(val), **kwargs)

def try_strToBool(val, validator=None, **kwargs):
    
    if val.lower() in ['true', '1']:
        return True
    elif val.lower() in ['false', '0']:
        return False
    
    raise ValueError

def try_strToStr(val, regex=None, validator=None, **kwargs):
    
    if validator and not validator(val):
        raise ValueError
    
    return val

def try_intToInt(val, min=None, max=None, validator=None, **kwargs):

    if min and val < min:
        raise ValueError
    elif max and val > max:
        raise ValueError
    elif validator and not validator(val):
        raise ValueError
    
    return val

_convert_dict = {
    str: {
        int: try_strToInt,
        bool: try_strToBool,
        str: try_strToStr,
    },
    bool: {
        bool: lambda x, **kwargs: x,
    },
    int: {
        int: try_intToInt,
    }
}

def cast_to(value, t=None, **kwargs):
    t = t or kwargs['type']
    try:
        return _convert_dict[type(value)][t](value, **kwargs)
    except KeyError:
        raise ValueError("From: {}, To: {}".format(type(value).__name__, t.__name__))
