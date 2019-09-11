#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import collections
import copy
import re
import math
import json

# TODO: reinterpret auf das reinterpret skeleton (Auweia)
#   - Zum Glück sind ja jetzt Templates implementiert.
# TODO: inherit_dict pro template ergänzen
#   - Damit lassen sich zB. formatter an das ganze dict durchpropagieren
# TODO: Restrict Keys d2d
# TODO: Accept und Produce lists
#   - Mit der steigenden Komplexität, wird es unübersichtlich, welche Datentypen akzeptiert und welches resultiert
#   - Idee: Eine Funktion, welche die Daten auf genau jene Informationen runterbricht.
# TODO: Reformat keys from dict
#   - Ein Dict kann anders als JSON jeden serialisierbaren Datentypen als Key haben.
#   - Deswegen ist auch hier eine Formatierung von Nöten.

_reinterpret_defaults = {
    'path': [],
    'convert': True,
    'verify': False,
}

_inheritable_parameters = [
    'path',
    'convert',
    'verify',
    'type_defaults',
]


class CastingException(ValueError):
    def __init__(self, path=None, msg=None, data=None, *args, **kwargs):
        path = path or []
        self.path = '.' + '.'.join(path)
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


class MissingValueError(CastingException):
    def __init__(*args, **kwargs):
        CastingException.__init__(*args, **kwargs)


class SkipException(Exception):
    pass


def _update(d, u):
    for k, v in u.items():
        if isinstance(v, collections.Mapping):
            d[k] = _update(d.get(k, {}), v)
        else:
            d[k] = v
    return d


def _base_n(num, b, numerals="0123456789abcdefghijklmnopqrstuvwxyz"):
    return ((num == 0) and numerals[0]) or (_base_n(num // b, b, numerals).lstrip(numerals[0]) + numerals[num % b])


def _verify_range(val, min_val=None, max_val=None, **kwargs):

    if min_val and val < min_val:
        raise RangeExceededError(kwargs['path'], "You have exceeded the boundaries of this value.", data={
            'min_val': min_val,
        })
    elif max_val and val > max_val:
        raise RangeExceededError(kwargs['path'], "You have exceeded the boundaries of this value.", data={
            'max_val': max_val,
        })


def _join_templates(d):
    if 'template' in d:
        template = d['template']
        del d['template']

        d = _update(copy.copy(template), d)
        d = _join_templates(d)

    return d


def str_to_int(val, base=10, **kwargs):
    try:
        return int_to_int(int(val, base), **kwargs)
    except ValueError:
        raise InconvertibleError(kwargs['path'], "Can't convert \"{}\" to int".format(val))


def str_to_float(val, **kwargs):
    try:
        return float_to_float(float(val), **kwargs)
    except ValueError:
        raise InconvertibleError(kwargs['path'], "Can't convert \"{}\" to float".format(val))


def str_to_bool(val, **kwargs):

    if val.lower() in ["true", "1"]:
        return True
    elif val.lower() in ["false", "0"]:
        return False

    raise InconvertibleError(kwargs['path'], "Can't convert \"{}\" to bool".format(val))


def str_to_str(val, regex=None, **kwargs):

    if regex and not re.match(regex, val):
        raise InvalidFormatError(kwargs['path'], "This string has an invalid Format", {
            'pattern': regex,
        })

    return val


def str_to_list(val, delimiter=',', neutral=' \t\n', regex=None, **kwargs):

    if val.strip(neutral) == '':
        wlist = []
    else:
        if regex is not None:
            wlist = list(re.match(regex, val).groups())
        else:
            wlist = [x.strip() for x in val.split(delimiter)]

    return list_to_list(wlist, **kwargs)


def str_to_dict(val, **kwargs):
    if val == "":
        parsed = {}
    else:
        try:
            parsed = json.loads(val)
        except json.decoder.JSONDecodeError as e:
            raise InconvertibleError(kwargs['path'], str(e))

    return dict_to_dict(parsed, **kwargs)


def int_to_int(val, min_val=None, max_val=None, **kwargs):

    _verify_range(val, min_val, max_val, **kwargs)
    return val


def int_to_float(val, **kwargs):

    return float_to_float(float(val), **kwargs)


def int_to_str(val, base=10, **kwargs):
    return _base_n(int_to_int(val, **kwargs), base)


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


def list_to_list(val, empty=True, children=None, child=None, single_cast_mode=0, **kwargs):
    children = children or {}
    child = child or []

    if empty is False and val == []:
        raise EmptyError(kwargs['path'])

    children = copy.copy(children)
    for p in _inheritable_parameters:
        if p in kwargs:
            children[p] = _update(kwargs[p], children.get(p, {}))

    child_list = list(range(len(child)))
    for i, item in enumerate(val):
        i_children = copy.copy(children)

        if i < len(child):
            i_children = _update(i_children, child[i])
            child_list.remove(i)

        i_children['path'] = list(i_children['path'])
        i_children['path'].append(str(i))
        val[i] = reinterpret(item, **i_children)

    if len(child_list) > 0:
        for i in range(child_list[-1] + 1):
            if i < len(val):
                continue

            if i in child_list:
                i_children = _update(copy.copy(children), child[i])
                i_children['path'] = list(i_children['path'])
                i_children['path'].append(str(i))
                val.append(reinterpret(None, **i_children))

    if single_cast_mode >= 1 and len(val) == 1:
        return val[0]
    elif single_cast_mode == 2 and len(val) > 1:
        raise InvalidFormatError(kwargs['path'], "Only one item expected")

    return val


def list_to_dict(val, **kwargs):
    try:
        return dict(val)
    except ValueError:
        raise InconvertibleError(kwargs['path'], "Can't convert \"{}\" to dict".format(val))


def dict_to_dict(val, empty=True, child=None, children=None, **kwargs):
    children = children or {}
    child = child or {}

    if empty is False and val == {}:
        raise EmptyError(kwargs['path'])

    children = copy.copy(children)
    for p in _inheritable_parameters:
        if p in kwargs:
            children[p] = _update(kwargs[p], children.get(p, {}))

    key_children_list = list(child.keys())
    for key, item in val.items():
        i_children = copy.copy(children)
        if key in key_children_list:
            i_children = _update(i_children, child[key])
            key_children_list.remove(key)

        i_children['path'] = list(i_children['path'])
        i_children['path'].append(key)
        val[key] = reinterpret(item, **i_children)

    for key in key_children_list:
        i_children = _update(copy.copy(children), child[key])
        i_children['path'] = list(i_children['path'])
        i_children['path'].append(key)
        val[key] = reinterpret(None, **i_children)

    return val


def dict_to_str(val, pretty=False, sort_keys=False, **kwargs):
    cval = reinterpret(val, dict, **kwargs)
    indent = 4 if pretty else None
    return json.dumps(cval, indent=indent, sort_keys=sort_keys)


def bytes_to_str_to_all(val, encoding='utf8', **kwargs):
    return reinterpret(val.decode(encoding), **kwargs)


def all_to_type_default(val, **kwargs):
    type_defaults = kwargs.get('type_defaults', {})
    s = type(val)

    type_default = copy.copy(type_defaults.get(s, type_defaults.get('*', None)))

    if type_default is None:
        return val
    else:
        if kwargs['type'] is None:
            del kwargs['type']

        kwargs = _update(type_default, kwargs)
        kwargs['type'] = kwargs.get('type', None)

    return reinterpret(val, **kwargs)


def all_to_str(val, **kwargs):
    return str(val)


convert_dict = {
    str: {
        int: str_to_int,
        float: str_to_float,
        bool: str_to_bool,
        str: str_to_str,
        list: str_to_list,
        dict: str_to_dict,
    },
    int: {
        int: int_to_int,
        str: int_to_str,
        float: int_to_float,
    },
    float: {
        float: float_to_float,
        int: float_to_int,
    },
    bool: {
        bool: lambda x, **kwargs: x,
    },
    list: {
        None: list_to_list,
        list: list_to_list,
        dict: list_to_dict,
    },
    dict: {
        None: dict_to_dict,
        dict: dict_to_dict,
        str: dict_to_str,
    },
    bytes: {
         '*': bytes_to_str_to_all,
    },
    '*': {
        None: all_to_type_default,
        str: all_to_str,
    },
}


def _d1_reinterpret(value, pre_format=None, post_format=None, default=None, pipe=None, **kwargs):
    type_defaults = kwargs.get('type_defaults', {})
    pipe = pipe or []
    t = kwargs['type']

    kwargs = _update(copy.copy(_reinterpret_defaults), kwargs)

    if value is None:
        if default is None:
            if kwargs['verify']:
                raise MissingValueError(kwargs['path'], "This Value must be set.")
            else:
                return None
        else:
            value = default

    if pre_format:
        try:
            value = pre_format(value, **kwargs)
        except SkipException:
            return value

    if not kwargs['convert'] and t != type(value) and t is not None:
        if type(t) != type:
            t_name = str(t)
        else:
            t_name = t

        raise InconvertibleError(kwargs['path'], "Expected {}, got {}.".format(t_name, type(value).__name__))

    try:
        s = type(value)

        if t not in convert_dict.get(s, {}):
            if '*' in convert_dict.get(s, {}):
                t = '*'
            else:
                s = '*'
                if t not in convert_dict.get(s, {}):
                    raise KeyError

        type_default = copy.copy(type_defaults.get(s, type_defaults.get('*', {})))
        kwargs = _update(type_default, kwargs)

        result = convert_dict[s][t](value, **kwargs)
    except KeyError:
        raise InconvertibleError(kwargs['path'])

    kwargs['raw_value'] = value
    if post_format:
        result = post_format(result, **kwargs)

    for entry in pipe:
        result = reinterpret(result, **entry)

    return result


def reinterpret(value, t=None, **kwargs):
    if t is not None:
        kwargs['type'] = t

    kwargs = _join_templates(kwargs)

    if 'type' not in kwargs:
        kwargs['type'] = None

    if 'path' not in kwargs:
        kwargs['path'] = []

    return _d1_reinterpret(value, **kwargs)
