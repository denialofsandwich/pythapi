#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest
import core.casting as c

import math
import datetime


# Basic Tests
def test_no_cast():
    data = "Test"
    casted = c.reinterpret(data)

    assert type(casted) == str
    assert casted == data


def test_type_in_kwargs():
    data = "Test"
    casted = c.reinterpret(data, **{'type': str})

    assert type(casted) == str
    assert casted == data


def test_convert():
    data = '34'
    desired = 34
    casted = c.reinterpret(data, int, convert=True)

    assert type(casted) == int
    assert casted == desired

    with pytest.raises(c.InconvertibleError):
        c.reinterpret(data, int, convert=False)

    data = 34
    casted = c.reinterpret(data, int, convert=False)

    assert type(casted) == int
    assert casted == data

    with pytest.raises(c.InconvertibleError):
        c.reinterpret(data, '*', convert=False)


def test_pre_post_verifier():
    # Treated as a string
    def i_pre_verify(val, **kwargs):
        if len(val) == 0:
            raise c.InvalidFormatError(kwargs['path'])

        return val

    # Treated as a list
    def i_post_verify(val, **kwargs):
        if len(val) > 4:
            raise c.InvalidFormatError(kwargs['path'])

        return val

    # Pre Verify
    data = "one, two, three"
    c.reinterpret(data, list, pre_format=i_pre_verify)

    data = ""
    with pytest.raises(c.InvalidFormatError):
        c.reinterpret(data, list, pre_format=i_pre_verify)

    # Post Verify
    data = "one, two, three"
    c.reinterpret(data, list, post_format=i_post_verify)

    data = "one, two, three, four, five"
    with pytest.raises(c.InvalidFormatError):
        c.reinterpret(data, list, post_format=i_post_verify)


def test_pre_post_formatter():
    def i_pre_format(val, **kwargs):
        return val + ', extended'

    def i_post_format(val, **kwargs):
        val.append('list_extended')
        return val

    # Pre Format
    data = "one, two, three"
    casted = c.reinterpret(data, list, pre_format=i_pre_format)
    assert casted == ['one', 'two', 'three', 'extended']

    # Post Format
    data = "one, two, three"
    casted = c.reinterpret(data, list, post_format=i_post_format)
    assert casted == ['one', 'two', 'three', 'list_extended']


def test_inconvertible():
    data = [34, 5, 1]
    with pytest.raises(c.InconvertibleError):
        c.reinterpret(data, float)


def test_template():
    data = {"a": 45, "c": "5"}
    desired = {"a": "45", "b": True, "c": 5}
    template = {
        'type': dict,
        'child': {
            "a": {
                "type": str,
            },
            "b": {
                "type": bool,
                "default": True,
            },
        }
    }

    casted = c.reinterpret(data, template=template, child={
        "c": {
            "type": int,
        }
    })

    assert casted == desired


# Boolean Tests
def test_b2b_base():
    data = True
    casted = c.reinterpret(data, bool)

    assert type(casted) == bool
    assert casted == data


# List Tests
def test_l2l_base():
    data = [34, 66, 89]
    casted = c.reinterpret(data, list)

    assert type(casted) == list
    assert casted == data


def test_l2l_empty():
    data = [34, 66, 89]
    c.reinterpret(data, list, empty=False)

    data = []
    with pytest.raises(c.EmptyError):
        c.reinterpret(data, list, empty=False)


def test_l2l_children():
    data = [34, 66, 89]
    casted = c.reinterpret(data, list, convert=False, children={
        'type': int,
    })

    assert type(casted) == list
    assert casted == data

    data = [34, 'string', 99]
    with pytest.raises(c.InconvertibleError):
        c.reinterpret(data, list, convert=False, children={
            'type': int,
        })


def test_l2l_child():
    data = [34, 66]
    desired = [34, "66", None, 89]
    casted = c.reinterpret(data, list, child=[
        {
            "type": int,
        },
        {
            "type": str,
        },
        {
            "type": int,
        },
        {
            "type": int,
            "default": 89,
        }
    ])

    assert type(casted) == list
    assert casted == desired

    data = [b'89']
    desired = [89]
    casted = c.reinterpret(data, list, template={
        "child": [
            {
                "type": int,
                "default": 89,
            }
        ]
    })

    assert casted == desired


@pytest.mark.parametrize('expectation', [
    ([34], 34),
    ([34, 35], [34, 35])
])
def test_l2l_single_cast_mode_1(expectation):
    casted = c.reinterpret(expectation[0], list, single_cast_mode=1)
    assert casted == expectation[1]


def test_l2l_single_cast_mode_2():
    data = [34]
    desired = "34"
    casted = c.reinterpret(data, list, single_cast_mode=2, child=[
        {
            "type": str
        }
    ])
    assert casted == desired

    data = [34, 35]
    with pytest.raises(c.InvalidFormatError) as e:
        c.reinterpret(data, list, single_cast_mode=2)


# Int/Float tests
def test_i2i_base():
    data = 10
    casted = c.reinterpret(data, int)

    assert type(casted) == int
    assert casted == data


def test_i2i_range():
    min_val = 5
    max_val = 15

    data = 10
    casted = c.reinterpret(data, int, min_val=min_val, max_val=max_val)

    assert type(casted) == int
    assert casted == data

    c.reinterpret(min_val, int, min_val=min_val, max_val=max_val)
    c.reinterpret(max_val, int, min_val=min_val, max_val=max_val)

    data = 3
    with pytest.raises(c.RangeExceededError) as e:
        c.reinterpret(data, int, min_val=min_val, max_val=max_val)

    assert e.value.data['min_val'] == min_val
    assert 'max_val' not in e.value.data

    data = 23
    with pytest.raises(c.RangeExceededError) as e:
        c.reinterpret(data, int, min_val=min_val, max_val=max_val)

    assert 'min_val' not in e.value.data
    assert e.value.data['max_val'] == max_val


def test_i2s_base():
    data = 99
    desired = "99"
    casted = c.reinterpret(data, str)
    assert type(casted) == str
    assert casted == desired

    desired = "1100011"
    casted = c.reinterpret(data, str, base=2)
    assert type(casted) == str
    assert casted == desired


def test_f2f_base():
    data = 10.6789776

    casted = c.reinterpret(data, float)
    assert type(casted) == float
    assert casted == data

    casted = c.reinterpret(data, float, round_digits=2)
    assert casted == round(data, 2)


def test_fi2f_range():
    min_val = -15.1
    max_val = 17.4

    data = 10.234
    casted = c.reinterpret(data, float, min_val=min_val, max_val=max_val)

    assert type(casted) == float
    assert casted == data

    c.reinterpret(min_val, float, min_val=min_val, max_val=max_val)
    c.reinterpret(max_val, float, min_val=min_val, max_val=max_val)

    data = -20.2
    with pytest.raises(c.RangeExceededError) as e:
        c.reinterpret(data, float, min_val=min_val, max_val=max_val)

    assert e.value.data['min_val'] == min_val
    assert 'max_val' not in e.value.data

    data = 23
    with pytest.raises(c.RangeExceededError) as e:
        c.reinterpret(data, float, min_val=min_val, max_val=max_val)

    assert 'min_val' not in e.value.data
    assert e.value.data['max_val'] == max_val


def test_f2i_round_types():
    data = 10.51

    casted = c.reinterpret(data, int)
    assert type(casted) == int
    assert casted == round(data)

    casted = c.reinterpret(data, int, round_type=1)
    assert type(casted) == int
    assert casted == math.ceil(data)

    casted = c.reinterpret(data, int, round_type=-1)
    assert type(casted) == int
    assert casted == math.floor(data)


# Dict tests
def test_d2d_base():
    data = {'a': 1, 'b': 2, 3: 'c'}
    casted = c.reinterpret(data, dict)

    assert type(casted) == dict
    assert casted == data


def test_d2d_empty():
    data = {'a': 1, 'b': 2, 3: 'c'}
    c.reinterpret(data, dict, empty=False)

    data = {}
    with pytest.raises(c.EmptyError):
        c.reinterpret(data, dict, empty=False)


def test_d2d_children():
    data = {'a': 1, 'b': '2', 'c': 3}
    desired = {'a': 1, 'b': 2, 'c': 3}
    casted = c.reinterpret(data, dict, children={
        'type': int,
    })

    assert casted == desired


def test_d2d_child():
    data = {'a': '1', 'b': '2', 'c': '3'}
    desired = {'a': '1', 'b': 2, 'c': 3, 'd': '4'}
    casted = c.reinterpret(data, dict, children={
        'type': int,
    }, child={
        'a': {
            'type': str,
        },
        'd': {
            'type': str,
            'default': '4',
        }
    })

    assert casted == desired


def test_d2s():
    data = {'a': 1}
    desired = '{"a": 1}'

    casted = c.reinterpret(data, str)
    assert casted == desired


def test_s2d_pretty():
    data = {'a': 34, 'b': "alpha"}
    desired = '{\n' \
              '    "a": 34,\n' \
              '    "b": "alpha"\n' \
              '}'
    casted = c.reinterpret(data, str, pretty=True, sort_keys=True)
    print(casted)
    assert casted == desired


# String tests
def test_s2s_base():
    data = "I am a string!"
    casted = c.reinterpret(data, str)

    assert type(casted) == str
    assert casted == data


def test_s2s_regex():
    data = "I am a string!"
    test_regex = r'^.{,16}!$'

    c.reinterpret(data, str, regex=test_regex)

    data = "I am a pretty long string!"
    with pytest.raises(c.InvalidFormatError) as e:
        c.reinterpret(data, str, regex=test_regex)

    assert e.value.data['pattern'] == test_regex


def test_s2i_base():
    data = "99"
    desired = 99
    casted = c.reinterpret(data, int)
    assert type(casted) == int
    assert casted == desired

    with pytest.raises(c.InconvertibleError):
        c.reinterpret(data, int, base=2)


def test_s2f_base():
    data = "99.56"
    desired = 99.56
    casted = c.reinterpret(data, float)
    assert type(casted) == float
    assert casted == desired

    data = "99wads"
    with pytest.raises(c.InconvertibleError):
        c.reinterpret(data, float)


def test_s2b_base():
    assert c.reinterpret('true', bool) is True
    assert c.reinterpret('True', bool) is True
    assert c.reinterpret('1', bool) is True

    assert c.reinterpret('false', bool) is False
    assert c.reinterpret('False', bool) is False
    assert c.reinterpret('0', bool) is False

    with pytest.raises(c.InconvertibleError):
        c.reinterpret('bot a bool', bool)


def test_s2l_base():
    data = "one, two, three"
    casted = c.reinterpret(data, list)
    assert casted == ['one', 'two', 'three']

    data = ""
    casted = c.reinterpret(data, list)
    assert casted == []


def test_s2d_base():
    data = '{"a": 34, "b": "alpha"}'
    casted = c.reinterpret(data, dict)
    assert casted == {'a': 34, 'b': "alpha"}


def test_byt2a_base():
    data = b'45'
    casted = c.reinterpret(data, int)
    desired = 45
    assert casted == desired

    data = b'{"a": 45}'
    casted = c.reinterpret(data, dict, child={
        "b": {
            "type": str,
            "default": "bravo",
        }
    })
    desired = {"a": 45, "b": "bravo"}
    assert casted == desired


def test_type_defaults():
    # Part 1
    data = {"a": {"b": {"c": 4}}, "b": 7}
    desired = {"a": {"b": {"c": "4"}}, "b": "7"}

    type_defaults = {
        int: {
            "type": str
        }
    }

    casted = c.reinterpret(data, dict, type_defaults=type_defaults)
    assert casted == desired

    # Part 2
    data = {'a': 1, 'b': datetime.datetime(2019, 10, 12)}
    desired = '{"a": 1.0, "b": "2019:10:12"}'

    def pf(val, **kwargs):
        return val.strftime("%Y:%m:%d")

    casted = c.reinterpret(data, str, type_defaults={
        datetime.datetime: {
            'pre_format': pf,
            'type': str,
        },
        '*': {
            "type": float
        }
    }, sort_keys=True)
    assert casted == desired


def test_a2s_base():
    data = datetime.datetime.now()
    desired = str(data)
    casted = c.reinterpret(data, str)
    assert casted == desired

    class JustATest:
        a = 0

        def __init__(self):
            pass

    data = JustATest()
    desired = str(data)
    casted = c.reinterpret(data, str)
    assert casted == desired


def test_something2what():
    data = datetime.datetime.now()
    with pytest.raises(c.InconvertibleError):
        c.reinterpret(data, float)


def test_s2l_regex():
    data = "https://alfa.bravo/test"
    desired = ["https", "alfa.bravo", "test"]
    regex = r"^(\w+)\:\/\/(\w+.\w+)/(\w+)$"
    casted = c.reinterpret(data, list, regex=regex)
    assert casted == desired


def test_l2d_base():
    data = [["a", 1], ["b", 2], ["c", 3]]
    desired = {"a": 1, "b": 2, "c": 3}
    casted = c.reinterpret(data, dict)
    assert casted == desired

    data = [["a", 1], ["b", 2], ["c", 3, 4]]
    with pytest.raises(c.InconvertibleError):
        c.reinterpret(data, dict)

    data = """X-Forwardado-For: 10.250.0.1,
              Another-Header: Test"""
    desired = {
        "X-Forwardado-For": "10.250.0.1",
        "Another-Header": "Test"
    }

    casted = c.reinterpret(data, **{
        "type": list,
        "default": [],
        "children": {
            "type": list,
            "delimiter": ':',
            "children": {
                "type": str
            },
        },
        "pipe": [
            {"type": dict}
        ]
    },)
    assert casted == desired


def test_pipes():
    data = "https://alfa.bravo/test"
    desired = {"protocol": "https", "domain": "alfa.bravo", "path": "test"}
    regex = r"^(\w+)\:\/\/(\w+.\w+)/(\w+)$"
    casted = c.reinterpret(data,
                           list,
                           regex=regex,
                           post_format=lambda val, **kwargs: list(zip(["protocol", "domain", "path"], val)),
                           pipe=[{"type": dict}])

    assert casted == desired


def test_skip():
    data = """X-Forwardado-For: 10.250.0.1,
              Another-Header: Test"""
    desired = {
        "X-Forwardado-For": "10.250.0.1",
        "Another-Header": "Test"
    }

    def skip_if_not_str(val, **kwargs):
        if type(val) != str:
            raise c.SkipException

        return val

    skel = {
        "type": list,
        "default": [],
        "children": {
            "type": list,
            "delimiter": ':',
            "children": {
                "type": str
            },
        },
        "pipe": [
            {"type": dict}
        ],
        "pre_format": skip_if_not_str,
    }

    casted = data
    for i in range(3):
        casted = c.reinterpret(casted, **skel)
        assert casted == desired


def test_verify():
    data = None
    with pytest.raises(c.MissingValueError):
        c.reinterpret(data, verify=True)


def test_s2d_empty():
    data = ''
    casted = c.reinterpret(data, dict)
    assert casted == {}


def test_s2d_syntax_error():
    data = '{}}'
    with pytest.raises(c.InconvertibleError):
        c.reinterpret(data, dict)

