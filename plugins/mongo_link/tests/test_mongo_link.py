#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest

import tests.tools

import core.plugin_base

from mongoengine import *

class TestPerson(Document):
    name = StringField(required=True, max_length=50)
    age = IntField(required=True)
    friends = ListField(ReferenceField('self'))
    __test__ = False
    def __str__(self):
        return "{} ist {} Jahre alt.".format(self.name, self.age)
    @property
    def json(self):
        return {
            "name": self.name,
            "age": self.age,
            "friends": list(self.friends),
            "man": self.manlyman,
        }

@pytest.fixture(scope='function')
def cs_bare():
    yield tests.tools.CoreSystem()


def _base_conf_gen():
    return {
        "core.general": {
            "loglevel": 6,
            "additional_plugin_paths": "plugins/mongo_link/tests/plugins",
            "enabled_plugins": "mongo_link, debug_mongo_link",
        },
    }


@pytest.fixture(scope='function')
def base_conf():
    yield _base_conf_gen()


@pytest.fixture(scope='class')
def core_system():
    cs = tests.tools.CoreSystem()
    cs.conf = _base_conf_gen()

    with cs:
        yield cs

# TODO test doesn't get connection from load event from mongo_link plugin
#def test_connect(base_conf, cs_bare):
#    cs_bare.conf = base_conf
#
#    #connect()
#    with cs_bare:
#        # Pythapi läuft
#        result = None
#        try:
#            result = TestPerson.objects
#        except MongoEngineConnectionError as e:
#            print(e)
#            pytest.fail("Connection to MongoDB failed.")
#        except Exception as e:
#            print(e)
#            pytest.fail("Unexpected Exception.")


