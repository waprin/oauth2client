# Copyright 2015 Google Inc.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Contains a storage module that stores credentials using the Django
ORM."""

from django.db.utils import DatabaseError

from oauth2client.client import Storage


class DjangoORMStorage(Storage):
    """Store and retrieve a single credential to and from the Django datastore.

    This Storage helper presumes the Credentials
    have been stored as a CredentialsField
    on a db model class.
    """

    def __init__(self, model_class, key_name, key_value, property_name):
        """Constructor for Storage.

        Args:
            model: string, fully qualified name of db.Model model class
            key_name: string, key name for the entity that has the credentials
            key_value: string, key value for the entity that has the
               credentials
            property_name: string, name of the property that is an
                           CredentialsProperty
        """
        super(DjangoORMStorage, self).__init__()
        self.model_class = model_class
        self.key_name = key_name
        self.key_value = key_value
        self.property_name = property_name

    def locked_get(self):
        """Retrieve stored credential.

        Returns:
            oauth2client.Credentials
        """
        credential = None

        query = {self.key_name: self.key_value}
        try:
            entities = self.model_class.objects.filter(**query)
        except TypeError:
            raise DatabaseError(
                'Failed to load credential entity from Django storage')
        if len(entities) > 0:
            credential = getattr(entities[0], self.property_name)
            if credential and hasattr(credential, 'set_store'):
                credential.set_store(self)
        return credential

    def locked_put(self, credentials):
        """Write a Credentials to the Django datastore.

        Args:
            credentials: Credentials, the credentials to store.
        """
        args = {self.key_name: self.key_value}

        (entity,
         unused_is_new) = self.model_class.objects.get_or_create(**args)

        setattr(entity, self.property_name, credentials)
        entity.save()

    def locked_delete(self):
        """Delete Credentials from the datastore."""

        query = {self.key_name: self.key_value}
        self.model_class.objects.filter(**query).delete()
