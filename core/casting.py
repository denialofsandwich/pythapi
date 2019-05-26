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

# TODO: extend library
# TODO: default type (str)


def str_to_int(val, **kwargs):
    return int_to_int(int(val), **kwargs)


def str_to_bool(val, validator=None, **kwargs):

    if val.lower() in ["true", "1"]:
        return True
    elif val.lower() in ["false", "0"]:
        return False

    raise ValueError


def str_to_str(val, regex=None, validator=None, **kwargs):

    if validator and not validator(val):
        raise ValueError

    return val


def str_to_list(val, delimiter=',', neutral=' \t\n', children=None, **kwargs):
    children = children or {}

    if val.strip(neutral) == '':
        return []

    wlist = val.split(delimiter)
    for i, item in enumerate(wlist):
        wlist[i] = cast_to(item.strip(neutral), **children)

    return wlist


def int_to_int(val, min=None, max=None, validator=None, **kwargs):

    if min and val < min:
        raise ValueError
    elif max and val > max:
        raise ValueError
    elif validator and not validator(val):
        raise ValueError

    return val


def list_to_list(val, **kwargs):
    return val


_convert_dict = {
    str: {int: str_to_int, bool: str_to_bool, str: str_to_str, list: str_to_list},
    int: {int: int_to_int},
    bool: {bool: lambda x, **kwargs: x},
    list: {list: list_to_list},
}


def cast_to(value, t=None, **kwargs):
    t = t or kwargs["type"] or None

    if not t:
        return value

    try:
        return _convert_dict[type(value)][t](value, **kwargs)
    except KeyError:
        raise ValueError("From: {}, To: {}".format(type(value).__name__, t.__name__))
