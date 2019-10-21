from mongoengine import *

class Person(Document):
    name = StringField(required=True, max_length=50)
    age = IntField(required=True)
    friends = ListField(ReferenceField('self'))
    def __str__(self):
        return "{} is {} years old.".format(self.name, self.age)
    @property
    def json(self):
        return {
            "name": self.name,
            "age": self.age,
        }
