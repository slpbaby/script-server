import logging
import urllib.parse as urllib_parse

import tornado.auth
from tornado import gen, httpclient, escape

from auth import auth_base
from auth.auth_base import AuthFailureError, AuthBadRequestException
from model import model_helper

from utils import audit_utils
from utils.audit_utils import find_basic_auth_username

LOGGER = logging.getLogger('script_server.ProxyAuthenticator')

# noinspection PyProtectedMember
class ProxyAuthenticator(auth_base.Authenticator):
    def __init__(self, params_dict):
        super().__init__()

    def authenticate(self, request_handler):
    	return find_basic_auth_username(request_handler)

