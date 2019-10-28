from mongoengine import *

import core.plugin_base
# from . import header

from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
import datetime


def _set_password(password):
    secret = core.plugin_base.config['session']['secret']
    # These Parameters should be strong enough for interactive Logins. Estimated calculation time: 100ms
    salt = get_random_bytes(32)
    h_password = scrypt(secret + password.encode('utf8'), salt, 32, N=2 ** 14, r=8, p=1)

    return h_password, salt


class Token(EmbeddedDocument):
    name = StringField(required=True, max_length=64)
    h_key = BinaryField(required=True, max_bytes=32)
    ruleset = MapField(field=MapField(field=StringField()))

    time_created = DateTimeField(default=datetime.datetime.utcnow())


class User(Document):
    name = StringField(required=True, max_length=64)
    _salt = BinaryField(required=True, max_bytes=32)
    _h_password = BinaryField(required=True, max_bytes=32)
    ruleset = MapField(field=ListField(StringField()))
    token_list = ListField(EmbeddedDocumentField(Token))

    time_created = DateTimeField(default=datetime.datetime.utcnow())

    def set_password(self, password):
        self._h_password, self._salt = _set_password(password)

    def __init__(self, *args, **kwargs):
        if 'password' in kwargs:
            kwargs['_h_password'], kwargs['_salt'] = _set_password(kwargs['password'])
            del kwargs['password']

        super().__init__(*args, **kwargs)

    @property
    def json(self):
        return {
            "name": self.name,
            "ruleset": self.ruleset,
            "time_created": self.time_created,
        }


class Role(Document):
    name = StringField(required=True, max_length=64)
    ruleset = MapField(field=MapField(field=StringField()))
    member = ListField(ReferenceField(User))  # TODO: Hier vielleicht was besseres

    time_created = DateTimeField(default=datetime.datetime.utcnow())
