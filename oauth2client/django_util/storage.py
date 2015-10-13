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


from oauth2client.client import OAuth2Credentials, Storage


def get_storage(request):
    return DjangoSessionStorage(request.session)


class DjangoSessionStorage(Storage):
    """Storage implementation that uses Django sessions.
    implementation.
    """

    def __init__(self, session):
        self.session = session

    def locked_get(self):
        serialized = self.session.get('google_oauth2_credentials')

        if serialized is None:
            return None

        credentials = OAuth2Credentials.from_json(serialized)
        credentials.set_store(self)

        return credentials

    def locked_put(self, credentials):
        self.session['google_oauth2_credentials'] = credentials.to_json()

    def locked_delete(self):
        if 'google_oauth2_credentials' in self.session:
            del self.session['google_oauth2_credentials']
