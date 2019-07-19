#!/usr/bin/python3
# -*- coding: utf-8 -*-

import collections
import copy
import re
import math
import json

# TODO: Restrict Keys d2d

_reinterpret_defaults = {
    'path': '.',
    'convert': True,
}


class CastingException(ValueError):
    def __init__(self, path='.', msg=None, data=None, *args, **kwargs):
        self.path = path
        self.data = data or {}
        ValueError.__init__(self, msg)


class InconvertibleError(CastingException):
    def __init__(*args, **kwargs):
        CastingException.__init__(*args, **kwargs)


class EmptyError(CastingException):
    def __init__(*args, **kwargs):
        CastingException.__init__(*args, **kwargs)


class InvalidFormatError(CastingException):
    def __init__(*args, **kwargs):
        CastingException.__init__(*args, **kwargs)


class RangeExceededError(CastingException):
    def __init__(*args, **kwargs):
        CastingException.__init__(*args, **kwargs)


def _update(d, u):
    for k, v in u.items():
        if isinstance(v, collections.Mapping):
            d[k] = _update(d.get(k, {}), v)
        else:
            d[k] = v
    return d


def _inherit_from_parent(children, parent):

    children['convert'] = parent['convert']

    return children


def _verify_range(val, min_val=None, max_val=None, **kwargs):

    if min_val and val < min_val:
        raise RangeExceededError(kwargs['path'], data={
            'min_val': min_val,
        })
    elif max_val and val > max_val:
        raise RangeExceededError(kwargs['path'], data={
            'max_val': max_val,
        })


def str_to_int(val, base=10, **kwargs):
    try:
        return int_to_int(int(val, base), **kwargs)
    except ValueError:
        raise InconvertibleError(kwargs['path'], "Can't convert {} to int".format(val))


def str_to_float(val, **kwargs):
    try:
        return float_to_float(float(val), **kwargs)
    except ValueError:
        raise InconvertibleError(kwargs['path'], "Can't convert {} to float".format(val))


def str_to_bool(val, **kwargs):

    if val.lower() in ["true", "1"]:
        return True
    elif val.lower() in ["false", "0"]:
        return False

    raise InconvertibleError(kwargs['path'], "Can't convert {} to bool".format(val))


def str_to_str(val, regex=None, **kwargs):

    if regex and not re.match(regex, val):
        raise InvalidFormatError(kwargs['path'], "This string has an invalid Format", {
            'pattern': regex,
        })

    return val


def str_to_list(val, delimiter=',', neutral=' \t\n', **kwargs):

    if val.strip(neutral) == '':
        wlist = []
    else:
        wlist = [x.strip() for x in val.split(delimiter)]

    return list_to_list(wlist, **kwargs)


def str_to_dict(val, **kwargs):
    parsed = json.loads(val)
    return dict_to_dict(parsed, **kwargs)


def int_to_int(val, min_val=None, max_val=None, **kwargs):

    _verify_range(val, min_val, max_val, **kwargs)
    return val


def int_to_float(val, **kwargs):

    return float_to_float(float(val), **kwargs)


def float_to_float(val, round_digits=None, min_val=None, max_val=None, **kwargs):

    _verify_range(val, min_val, max_val, **kwargs)
    if round_digits:
        val = round(val, round_digits)

    return val


def float_to_int(val, round_type=0, **kwargs):

    if round_type < 0:
        return int_to_int(math.floor(val), **kwargs)
    elif round_type > 0:
        return int_to_int(math.ceil(val), **kwargs)

    return int_to_int(round(val), **kwargs)


def list_to_list(val, empty=True, children=None, **kwargs):
    children = children or {}

    if empty is False and val == []:
        raise EmptyError(kwargs['path'])

    children = _inherit_from_parent(children, kwargs)

    try:
        for i, item in enumerate(val):
            children['path'] = kwargs['path'] + str(i) + '.'
            val[i] = reinterpret(item, **children)

    finally:
        try:
            del children['path']
        except KeyError:
            pass

    return val


def dict_to_dict(val, empty=True, child=None, children=None, **kwargs):
    children = children or {}
    child = child or {}

    if empty is False and val == {}:
        raise EmptyError(kwargs['path'])

    children = _inherit_from_parent(children, kwargs)

    key_children_list = list(child.keys())
    for key, item in val.items():
        i_children = children
        if key in key_children_list:
            i_children = _update(copy.copy(i_children), child[key])
            key_children_list.remove(key)

        i_children['path'] = kwargs['path'] + str(key) + '.'
        val[key] = reinterpret(item, **i_children)

    for key in key_children_list:
        i_children = _update(copy.copy(children), child[key])
        i_children['path'] = kwargs['path'] + str(key) + '.'
        val[key] = reinterpret(None, **i_children)

    return val


_convert_dict = {
    str: {
        int: str_to_int,
        float: str_to_float,
        bool: str_to_bool,
        str: str_to_str,
        list: str_to_list,
        dict: str_to_dict
    },
    int: {int: int_to_int, float: int_to_float},
    float: {float: float_to_float, int: float_to_int},
    bool: {bool: lambda x, **kwargs: x},
    list: {list: list_to_list},
    dict: {dict: dict_to_dict}
}


def reinterpret(value, t=None, pre_format=None, post_format=None, default=None, **kwargs):
    if t is None and 'type' in kwargs:
        t = kwargs['type']

    if t is None:
        return value

    if value is None:
        if default is None:
            return None
        else:
            value = default

    kwargs = _update(copy.copy(_reinterpret_defaults), kwargs)

    if pre_format:
        value = pre_format(value, t, **kwargs)

    if not kwargs['convert'] and t != type(value):
        raise InconvertibleError(kwargs['path'])

    try:
        result = _convert_dict[type(value)][t](value, **kwargs)
    except KeyError:
        raise InconvertibleError(kwargs['path'])

    kwargs['raw_value'] = value
    if post_format:
        result = post_format(result, t, **kwargs)

    return result
