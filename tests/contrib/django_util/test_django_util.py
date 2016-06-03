# Copyright 2015 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy

import django.conf
from django.conf.urls import include, url
from django.contrib.auth.models import AnonymousUser
from django.core import exceptions
import mock
from six.moves import reload_module
from tests.contrib.django_util import TestWithDjangoEnvironment
import unittest2

from oauth2client.contrib import django_util
import oauth2client.contrib.django_util
from oauth2client.contrib.django_util import (
    _CREDENTIALS_KEY, get_storage, site, UserOAuth2)


urlpatterns = [
    url(r'^oauth2/', include(site.urls))
]

urlpatterns += [url(r'^oauth2/', include(site.urls))]


class OAuth2SetupTest(unittest2.TestCase):

    def setUp(self):
        import django.conf
        self.save_settings = copy.deepcopy(django.conf.settings)
        reload_module(oauth2client.contrib.django_util)

    def tearDown(self):
        import django.conf
        django.conf.settings = copy.deepcopy(self.save_settings)

    @mock.patch("oauth2client.contrib.django_util.clientsecrets")
    def test_settings_initialize(self, clientsecrets):
        django.conf.settings.GOOGLE_OAUTH2_CLIENT_SECRETS_JSON = 'file.json'
        clientsecrets.loadfile.return_value = (
            clientsecrets.TYPE_WEB,
            {
                'client_id': 'myid',
                'client_secret': 'hunter2'
            }
        )

        oauth2_settings = django_util.OAuth2Settings(django.conf.settings)
        self.assertTrue(clientsecrets.loadfile.called)
        self.assertEqual(oauth2_settings.client_id, 'myid')
        self.assertEqual(oauth2_settings.client_secret, 'hunter2')
        django.conf.settings.GOOGLE_OAUTH2_CLIENT_SECRETS_JSON = None

    @mock.patch("oauth2client.contrib.django_util.clientsecrets")
    def test_settings_initialize_invalid_type(self, clientsecrets):
        django.conf.settings.GOOGLE_OAUTH2_CLIENT_SECRETS_JSON = 'file.json'
        clientsecrets.loadfile.return_value = (
            "wrong_type",
            {
                'client_id': 'myid',
                'client_secret': 'hunter2'
            }
        )

        with self.assertRaises(ValueError):
            django_util.OAuth2Settings.__init__(
                object.__new__(django_util.OAuth2Settings),
                django.conf.settings)

    @mock.patch("oauth2client.contrib.django_util.clientsecrets")
    def test_no_settings(self, clientsecrets):
        django.conf.settings.GOOGLE_OAUTH2_CLIENT_SECRETS_JSON = None
        django.conf.settings.GOOGLE_OAUTH2_CLIENT_SECRET = None
        django.conf.settings.GOOGLE_OAUTH2_CLIENT_ID = None

        with self.assertRaises(exceptions.ImproperlyConfigured):
            django_util.OAuth2Settings.__init__(
                object.__new__(django_util.OAuth2Settings),
                django.conf.settings)

    @mock.patch("oauth2client.contrib.django_util.clientsecrets")
    def test_no_session_middleware(self, clientsecrets):
        django.conf.settings.MIDDLEWARE_CLASSES = ()

        with self.assertRaises(exceptions.ImproperlyConfigured):
            django_util.OAuth2Settings.__init__(
                object.__new__(django_util.OAuth2Settings),
                django.conf.settings)

    def test_storage_model(self):
        STORAGE_MODEL = {
            'model': 'tests.contrib.django_util.models.CredentialsModel',
            'user_property': 'user_id',
            'credentials_property': 'credentials'
        }
        django.conf.settings.GOOGLE_OAUTH2_STORAGE_MODEL = STORAGE_MODEL
        oauth2_settings = django_util.OAuth2Settings(django.conf.settings)
        self.assertEqual(oauth2_settings.storage_model, STORAGE_MODEL['model'])
        self.assertEqual(oauth2_settings.storage_model_user_property,
                         STORAGE_MODEL['user_property'])
        self.assertEqual(oauth2_settings.storage_model_credentials_property,
                         STORAGE_MODEL['credentials_property'])


class MockObjectWithSession(object):
    def __init__(self, session):
        self.session = session


class SessionStorageTest(TestWithDjangoEnvironment):

    def setUp(self):
        super(SessionStorageTest, self).setUp()
        self.save_settings = copy.deepcopy(django.conf.settings)
        reload_module(oauth2client.contrib.django_util)

    def tearDown(self):
        super(SessionStorageTest, self).tearDown()
        django.conf.settings = copy.deepcopy(self.save_settings)

    def test_session_delete(self):
        self.session[_CREDENTIALS_KEY] = "test_val"
        request = MockObjectWithSession(self.session)
        django_storage = get_storage(request)
        django_storage.delete()
        self.assertIsNone(self.session.get(_CREDENTIALS_KEY))

    def test_session_delete_nothing(self):
        request = MockObjectWithSession(self.session)
        django_storage = get_storage(request)
        django_storage.delete()


class TestUserOAuth2Object(TestWithDjangoEnvironment):

    def setUp(self):
        super(TestUserOAuth2Object, self).setUp()
        self.save_settings = copy.deepcopy(django.conf.settings)
        STORAGE_MODEL = {
            'model': 'tests.contrib.django_util.models.CredentialsModel',
            'user_property': 'user_id',
            'credentials_property': 'credentials'
        }
        django.conf.settings.GOOGLE_OAUTH2_STORAGE_MODEL = STORAGE_MODEL
        reload_module(oauth2client.contrib.django_util)

    def tearDown(self):
        super(TestUserOAuth2Object, self).tearDown()
        import django.conf
        django.conf.settings = copy.deepcopy(self.save_settings)

    def test_get_credentials_anon_user(self):
        request = self.factory.get('oauth2/oauth2authorize',
                                   data={'return_url': '/return_endpoint'})
        request.session = self.session
        request.user = AnonymousUser()
        oauth2 = UserOAuth2(request)
        self.assertIsNone(oauth2.credentials)
