# Django Samples

These two sample Django apps provide a skeleton for the two main use cases of the
Django contrib helpers

## google_user

This is the simpler use case of the library and assumes you are using Google OAuth as your primary
authorization and authentication mechanism for your app. Users log in with their Google ID and 
their OAauth2 credentials are stored inside the session. Please see the core docs for 
                                                         usage examples.
 
## django_user
 
This is the use case where the application is already using the Django authorization system and
has a Django model with a `django.contrib.auth.models.User` field, and would like to attach
a Google OAuth2 credentials object to that model. Please see the core docs for usage examples.
