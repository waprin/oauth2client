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


import json
import unittest

from django.conf.urls import include, url
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse, HttpResponseRedirect
from django.http import HttpResponseBadRequest
from django.test import RequestFactory, TestCase
from mock import MagicMock, Mock, patch
from oauth2client.client import FlowExchangeError, OAuth2WebServerFlow
from oauth2client.django_util import settings as django_settings
from oauth2client.django_util import UserOAuth2
from oauth2client.django_util.decorators import required
from oauth2client.django_util.site import urls
from oauth2client.django_util.views import oauth2_authorize, oauth2_callback
from six.moves.urllib.parse import urlparse

urlpatterns = [
    url(r'^oauth2/', include(urls))
]

urlpatterns += [url(r'^oauth2/', include(urls))]


class OAuth2SetupTest(unittest.TestCase):

    @patch("oauth2client.django_util.clientsecrets")
    def test_settings_initialize(self, clientsecrets):
        django_settings.GOOGLE_OAUTH2_CLIENT_SECRETS_JSON = 'file.json'
        clientsecrets.loadfile.return_value = (
            clientsecrets.TYPE_WEB,
            {
                'client_id': 'myid',
                'client_secret': 'hunter2'
            }
        )

        oauth2 = UserOAuth2(django_settings)
        self.assertTrue(clientsecrets.loadfile.called)
        self.assertEqual(oauth2.client_id, 'myid')
        self.assertEqual(oauth2.client_secret, 'hunter2')

    @patch("oauth2client.django_util.clientsecrets")
    def test_settings_initialize_invalid_type(self, clientsecrets):
        django_settings.GOOGLE_OAUTH2_CLIENT_SECRETS_JSON = 'file.json'
        clientsecrets.loadfile.return_value = (
            "wrong_type",
            {
                'client_id': 'myid',
                'client_secret': 'hunter2'
            }
        )

        self.assertRaises(ValueError, UserOAuth2.__init__,
                          object.__new__(UserOAuth2), django_settings)

    @patch("oauth2client.django_util.clientsecrets")
    def test_no_settings(self, clientsecrets):
        django_settings.GOOGLE_OAUTH2_CLIENT_SECRETS_JSON = None
        django_settings.GOOGLE_OAUTH2_CLIENT_SECRET = None
        django_settings.GOOGLE_OAUTH2_CLIENT_ID = None

        self.assertRaises(ImproperlyConfigured, UserOAuth2.__init__,
                          object.__new__(UserOAuth2), django_settings)

    @patch("oauth2client.django_util.clientsecrets")
    def test_no_session_middleware(self, clientsecrets):
        old_classes = django_settings.MIDDLEWARE_CLASSES
        django_settings.MIDDLEWARE_CLASSES = ()

        self.assertRaises(ImproperlyConfigured,
                          UserOAuth2.__init__, object.__new__(UserOAuth2),
                          django_settings)
        django_settings.MIDDLEWARE_CLASSES = old_classes


class TestWithSession(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        from django.contrib.sessions.backends.file import SessionStore

        store = SessionStore()
        store.save()
        self.session = store


class Oauth2DecoratorTest(TestWithSession):
    def test_redirects_without_credentials(self):
        request = self.factory.get('/test')
        request.session = self.session

        @required
        def test_view(request):
            return HttpResponse("test")

        response = test_view(request)
        self.assertTrue(isinstance(response, HttpResponseRedirect))
        self.assertEquals(urlparse(response['Location']).path,
                          "/oauth2/oauth2authorize/")
        self.assertEquals(urlparse(response['Location']).query,
                          "return_url=%2Ftest")
        self.assertEquals(response.status_code, 302)

    @patch("oauth2client.django_util.storage.OAuth2Credentials")
    def test_has_credentials_in_storage(self, OAuth2Credentials):
        request = self.factory.get('/test')
        request.session = MagicMock()
        credentials_mock = Mock(scopes=django_settings.GOOGLE_OAUTH2_SCOPES)
        credentials_mock.has_scopes.return_value = True

        OAuth2Credentials.from_json.return_value = credentials_mock

        @required
        def test_view(request):
            return HttpResponse("test")

        response = test_view(request)
        self.assertEquals(response.status_code, 200)
        self.assertEquals(response.content, b"test")

    @patch("oauth2client.django_util.storage.OAuth2Credentials")
    def test_has_credentials_in_storage_no_scopes(self, OAuth2Credentials):
        request = self.factory.get('/test')

        request.session = MagicMock()
        credentials_mock = Mock(scopes=django_settings.GOOGLE_OAUTH2_SCOPES)
        credentials_mock.has_scopes.return_value = False

        OAuth2Credentials.from_json.return_value = credentials_mock

        @required
        def test_view(request):
            return HttpResponse("test")

        response = test_view(request)
        self.assertEquals(response.status_code, 302)

    @patch("oauth2client.django_util.storage.OAuth2Credentials")
    def test_specified_scopes(self, OAuth2Credentials):
        request = self.factory.get('/test')
        request.session = MagicMock()

        credentials_mock = Mock(scopes=django_settings.GOOGLE_OAUTH2_SCOPES)
        credentials_mock.has_scopes = lambda scopes: \
            django_settings.GOOGLE_OAUTH2_SCOPES in list(scopes)
        OAuth2Credentials.from_json.return_value = credentials_mock

        @required(scopes=['additional-scope'])
        def test_view(request):
            return "hello world"

        response = test_view(request)
        self.assertEquals(response.status_code, 302)


class Oauth2AuthorizeTest(TestWithSession):

    def test_authorize_works(self):
        request = self.factory.get('oauth2/oauth2authorize')
        request.session = self.session
        response = oauth2_authorize(request)
        self.assertTrue(isinstance(response, HttpResponseRedirect))


class Oauth2CallbackTest(TestWithSession):

    def setUp(self):
        global mycallback
        mycallback = Mock()

        super(Oauth2CallbackTest, self).setUp()
        self.CSRF_TOKEN = "token"
        self.RETURN_URL = "http://return-url.com"
        self.fake_state = {
            'csrf_token': self.CSRF_TOKEN,
            'return_url': self.RETURN_URL,
            'scopes': django_settings.GOOGLE_OAUTH2_SCOPES
        }

    @patch("oauth2client.django_util.views.pickle")
    def test_callback_works(self, pickle):
        request = self.factory.get('oauth2/oauth2callback', data={
            "state": json.dumps(self.fake_state),
            "code": 123
        })

        self.session['google_oauth2_csrf_token'] = self.CSRF_TOKEN

        flow = OAuth2WebServerFlow(
            client_id='clientid',
            client_secret='clientsecret',
            scope=['email'],
            state=json.dumps(self.fake_state),
            redirect_uri=request.build_absolute_uri("oauth2/oauth2callback"))

        self.session['google_oauth2_flow_{0}'.format(self.CSRF_TOKEN)] \
            = pickle.dumps(flow)
        flow.step2_exchange = Mock()
        pickle.loads.return_value = flow

        request.session = self.session
        response = oauth2_callback(request)
        self.assertTrue(isinstance(response, HttpResponseRedirect))
        self.assertEquals(response.status_code, 302)
        self.assertEquals(response['Location'], self.RETURN_URL)

    @patch("oauth2client.django_util.views.pickle")
    def test_callback_handles_bad_flow_exchange(self, pickle):
        request = self.factory.get('oauth2/oauth2callback', data={
            "state": json.dumps(self.fake_state),
            "code": 123
        })

        self.session['google_oauth2_csrf_token'] = self.CSRF_TOKEN

        flow = OAuth2WebServerFlow(
            client_id='clientid',
            client_secret='clientsecret',
            scope=['email'],
            state=json.dumps(self.fake_state),
            redirect_uri=request.build_absolute_uri("oauth2/oauth2callback"))

        self.session['google_oauth2_flow_{0}'.format(self.CSRF_TOKEN)]\
            = pickle.dumps(flow)

        def local_throws(code):
            raise FlowExchangeError("test")

        flow.step2_exchange = local_throws
        pickle.loads.return_value = flow

        request.session = self.session
        response = oauth2_callback(request)
        self.assertTrue(isinstance(response, HttpResponseBadRequest))

    def test_error_returns_bad_request(self):
        request = self.factory.get('oauth2/oauth2callback', data={
            "error": "There was an error in your authorization.",
        })
        response = oauth2_callback(request)
        self.assertTrue(isinstance(response, HttpResponseBadRequest))

    def test_missing_state_returns_bad_request(self):
        request = self.factory.get('oauth2/oauth2callback', data={
            "code": 123
        })
        self.session['google_oauth2_csrf_token'] = "token"
        request.session = self.session
        response = oauth2_callback(request)
        self.assertTrue(isinstance(response, HttpResponseBadRequest))

    def test_bad_state(self):
        request = self.factory.get('oauth2/oauth2callback', data={
            "code": 123,
            "state": json.dumps({"wrong": "state"})
        })
        self.session['google_oauth2_csrf_token'] = "token"
        request.session = self.session
        response = oauth2_callback(request)
        self.assertTrue(isinstance(response, HttpResponseBadRequest))

    def test_bad_csrf(self):
        request = self.factory.get('oauth2/oauth2callback', data={
            "state": json.dumps(self.fake_state),
            "code": 123
        })
        self.session['google_oauth2_csrf_token'] = "WRONG TOKEN"
        request.session = self.session
        response = oauth2_callback(request)
        self.assertTrue(isinstance(response, HttpResponseBadRequest))

    def test_no_csrf(self):
        request = self.factory.get('oauth2/oauth2callback', data={
            "state": json.dumps(self.fake_state),
            "code": 123
        })
        self.session['google_oauth2_csrf_token'] = self.CSRF_TOKEN
        self.session['google_oauth2_flow_{0}'.format(self.CSRF_TOKEN)] = None
        request.session = self.session
        response = oauth2_callback(request)
        self.assertTrue(isinstance(response, HttpResponseBadRequest))
