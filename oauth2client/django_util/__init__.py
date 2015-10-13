# Copyright 2015 Google Inc.  All rights reserved.
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


"""Utilities for the Django web framework

Provides Django views and helpers the make using the OAuth2 web server
flow easier. It includes a ``required`` decorator to automatically ensure
that user credentials are available.


Configuration
=============

First, add the helper to your INSTALLED_APPS:

INSTALLED_APPS = (
    # other apps
    "oauth2client.django_util"
)

To configure, you'll need a set of OAuth2 web application credentials from
`Google Developer's Console <https://console.developers.google.com/project/_/\
apiui/credential>`__.

.. code-block:: python
   :caption: settings.py
   :name: settings-file

   GOOGLE_OAUTH2_CLIENT_SECRETS_JSON=client-secret.json file

Or,

.. code-block:: python
   :caption: settings.py


   GOOGLE_OAUTH2_CLIENT_ID=client-id-field
   GOOGLE_OAUTH2_CLIENT_SECRET=client-secret-field

By default, the default scopes for the required decorator only contains the
(email) scopes. You can change that default in the settings.

GOOGLE_OAUTH2_SCOPES = ('https://www.googleapis.com/auth/calendar',)


then in your urls.py

.. code-block:: python
   :caption: urls.py

   from oauth2client.django_util.site import urls as oauth2_urls

   urlpatterns += [url(r'^oauth2/', include(oauth2_urls))]

Finally, on any of your views add the decorator

from oauth2client.django_util.decorators import required


@required:
def requires_default_scopes(request):
   email = request.credentials.id_token['email']

If a view needs a scope not explicitly set by the decorator, you can specify
in the decorator arguments.

@required(scopes=['https://www.googleapis.com/auth/calendar')
def requires_calendar_view(request):
  http = request.credentials.authorize(httplib2.Http())
  service = build(serviceName='calendar', version='v3', http=http,
                    developerKey=YOUR_API_KEY)
  events = service.events().list(calendarId='primary').execute()['items']


"""
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from oauth2client import clientsecrets

GOOGLE_OAUTH2_DEFAULT_SCOPES = ('email', )


def _load_client_secrets(filename):
    """Loads client secrets from the given filename."""
    client_type, client_info = clientsecrets.loadfile(filename)

    if client_type != clientsecrets.TYPE_WEB:
        raise ValueError(
            'The flow specified in %s is not supported.' % client_type)
    return client_info['client_id'], client_info['client_secret']


def _get_oauth2_client_id_and_secret(settings_instance):
    if getattr(settings, 'GOOGLE_OAUTH2_CLIENT_SECRETS_JSON', None):
        return _load_client_secrets(
            settings_instance.GOOGLE_OAUTH2_CLIENT_SECRETS_JSON)
    elif getattr(settings_instance, "GOOGLE_OAUTH2_CLIENT_ID", None) and \
            getattr(settings_instance, "GOOGLE_OAUTH2_CLIENT_SECRET", None):
        return settings_instance.GOOGLE_OAUTH2_CLIENT_ID, \
            settings_instance.GOOGLE_OAUTH2_CLIENT_SECRET
    else:
        raise ImproperlyConfigured("Must specify either "
                                   "GOOGLE_OAUTH2_CLIENT_SECRETS_JSON,"
                                   "or both GOOGLE_OAUTH2_CLIENT_ID and "
                                   "GOOGLE_OAUTH2_CLIENT_SECRET in "
                                   "settings.py")


class UserOAuth2(object):
    def __init__(self, settings_instance):
        self.scopes = getattr(settings_instance, 'GOOGLE_OAUTH2_SCOPES',
                              GOOGLE_OAUTH2_DEFAULT_SCOPES)
        self.client_id, self.client_secret = \
            _get_oauth2_client_id_and_secret(settings_instance)

        if 'django.contrib.sessions.middleware.SessionMiddleware' not in \
                settings_instance.MIDDLEWARE_CLASSES:
            raise ImproperlyConfigured("The Google OAuth2 Helper requires "
                                       "session middleware to be installed."
                                       "Edit your MIDDLEWARE_CLASSES setting"
                                       " to include "
                                       "'django.contrib.sessions.middleware.\
                                       SessionMiddleware'.")

oauth2 = UserOAuth2(settings)
