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
    import urllib
    url = reverse(url_name, args=args)
    params = urllib.urlencode(kwargs)
    return HttpResponseRedirect(url + "?%s" % params)


def required(decorated_function=None, scopes=None, **decorator_kwargs):
    def curry_wrapper(wrapped_function):
        @wraps(wrapped_function)
        def required_wrapper(request, *args, **kwargs):
            return_url = decorator_kwargs.pop('return_url',
                                              request.get_full_path())
            storage = get_storage(request)
            credentials = storage.get()

            requested_scopes = list(oauth2.scopes) + (scopes or [])
            if credentials:
                requested_scopes += list(credentials.scopes)

            # If no credentials or if existing credentials but mismatching
            # scopes, redirect for incremental authorization.
            if not credentials or not credentials.has_scopes(requested_scopes):
                get_params = {
                    'return_url': return_url,
                }
                if scopes:
                    get_params['scopes[]'] = requested_scopes
                return _redirect_with_params('google_oauth:authorize',
                                             **get_params)
            request.credentials = credentials
            return wrapped_function(request, *args, **kwargs)

        return required_wrapper

    if decorated_function:
        return curry_wrapper(decorated_function)
    else:
        return curry_wrapper
