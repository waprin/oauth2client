# Copyright 2016 Google Inc.  All rights reserved.
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

from django.conf.urls import include, url
from polls.views import get_profile_optional, get_profile_required, index

from oauth2client.contrib.django_util.site import urls as oauth2_urls


urlpatterns = [
    url(r'^$', index),
    url(r'^profile_required$', get_profile_required),
    url(r'^profile_enabled$', get_profile_optional),
]

urlpatterns += [url(r'^oauth2/', include(oauth2_urls))]
