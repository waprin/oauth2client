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

from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from oauth2client.django_util import oauth2
from oauth2client.django_util.storage import get_storage
from six import wraps


def _redirect_with_params(url_name, *args, **kwargs):
    from six.moves.urllib.parse import urlencode
    url = reverse(url_name, args=args)
    params = urlencode(kwargs)
    return HttpResponseRedirect("{0}?{1}".format(url, params))


def required(decorated_function=None, scopes=None, **decorator_kwargs):
    """ Decorator to require OAuth2 credentials for a view

    :param decorated_function: Function to decorate
    :param scopes: Scopes to require, will default
    :param decorator_kwargs: Can include return_url to specify the URL to \
    return to after OAuth2 authorization is complete
    :return: An OAuth2 Authorize view if credentials are not found or if the credentials \
    are missing the required scopes. Otherwise, the decorated view.

    """
    def curry_wrapper(wrapped_function):
        @wraps(wrapped_function)
        def required_wrapper(request, *args, **kwargs):
            return_url = decorator_kwargs.pop('return_url',
                                              request.get_full_path())
            storage = get_storage(request)
            credentials = storage.get()

            requested_scopes = set(oauth2.scopes)
            if scopes is not None:
                requested_scopes |= set(scopes)

            if credentials:
                requested_scopes |= credentials.scopes

            # If no credentials or if existing credentials but mismatching
            # scopes, redirect for incremental authorization.
            if credentials and credentials.has_scopes(requested_scopes):
                request.credentials = credentials
                return wrapped_function(request, *args, **kwargs)
            get_params = {
                'return_url': return_url,
            }
            if scopes:
                get_params['scopes[]'] = requested_scopes
            return _redirect_with_params('google_oauth:authorize',
                                         **get_params)


        return required_wrapper

    if decorated_function:
        return curry_wrapper(decorated_function)
    else:
        return curry_wrapper
