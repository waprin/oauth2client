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

import hashlib
import json
import os
import pickle

from django.core.urlresolvers import reverse
from django.http import HttpResponseBadRequest
from django.shortcuts import redirect
from oauth2client.client import FlowExchangeError, OAuth2WebServerFlow
from oauth2client.django_util import oauth2
from oauth2client.django_util.signals import oauth2_authorized
from oauth2client.django_util.storage import get_storage


def _make_flow(request, scopes, return_url=None):
    """Creates a Web Server Flow"""
    # Generate a CSRF token to prevent malicious requests.
    csrf_token = hashlib.sha256(os.urandom(1024)).hexdigest()

    request.session['google_oauth2_csrf_token'] = csrf_token

    state = json.dumps({
        'csrf_token': csrf_token,
        'return_url': return_url,
    })

    flow = OAuth2WebServerFlow(
        client_id=oauth2.client_id,
        client_secret=oauth2.client_secret,
        scope=scopes,
        state=state,
        redirect_uri=request.build_absolute_uri(
            reverse("google_oauth:callback")))

    flow_key = 'google_oauth2_flow_{0}'.format(csrf_token)
    request.session[flow_key] = pickle.dumps(flow)
    return flow


def _get_flow_for_token(csrf_token, request):
    flow_pickle = request.session.get(
        'google_oauth2_flow_{0}'.format(csrf_token), None)
    if not flow_pickle:
        return
    return pickle.loads(flow_pickle)


def oauth2_callback(request):
    if 'error' in request.GET:
        reason = request.GET.get('error_description',
                                 request.GET.get('error', ''))
        return HttpResponseBadRequest(
            'Authorization failed failed: %s' % reason)

    encoded_state = request.GET.get('state')
    server_csrf = request.session.get('google_oauth2_csrf_token')
    code = request.GET.get('code', None)

    if not encoded_state or not code or not server_csrf:
        return HttpResponseBadRequest("Invalid Request")

    try:
        state = json.loads(encoded_state)
        client_csrf = state['csrf_token']
        return_url = state['return_url']
    except (ValueError, KeyError):
        return HttpResponseBadRequest('Invalid request state')
    if client_csrf != server_csrf:
        return HttpResponseBadRequest('Invalid request state')

    flow = _get_flow_for_token(client_csrf, request)

    if not flow:
        return HttpResponseBadRequest("Invalid request state")

    try:
        credentials = flow.step2_exchange(code)
    except FlowExchangeError as exchange_error:
        return HttpResponseBadRequest(
            "An error has occurred: {0}".format(exchange_error))
    get_storage(request).put(credentials)

    oauth2_authorized.send(sender=oauth2_authorized)
    return redirect(return_url)


def oauth2_authorize(request):
    scopes = request.GET.getlist('scopes', oauth2.scopes)
    return_url = request.GET.get('return_url', None)

    if not return_url:
        return_url = request.META.get('HTTP_REFERER', '/')
    flow = _make_flow(request=request, scopes=scopes, return_url=return_url)
    auth_url = flow.step1_get_authorize_url()
    return redirect(auth_url)
