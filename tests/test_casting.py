#!/usr/bin/python3
# -*- coding: utf-8 -*-

import pytest
import core.casting as c

import math


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


def test_pre_post_verifier():

    # Treated as a string
    def i_pre_verify(val, t, **kwargs):
        if len(val) == 0:
            raise c.InvalidFormatError(kwargs['path'])

        return val

    # Treated as a list
    def i_post_verify(val, t, **kwargs):
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

    def i_pre_format(val, t, **kwargs):
        return val + ', extended'

    def i_post_format(val, t, **kwargs):
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
        c.reinterpret(data, dict)


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