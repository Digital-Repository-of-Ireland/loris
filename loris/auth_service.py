# -*- coding: utf-8 -*-
"""
`auth_service` -- Authenticate actions on images
================================================
"""
from logging import getLogger
from loris_exception import AuthServiceException
from urllib import unquote, quote_plus
from contextlib import closing

import constants
import hashlib
import glob
import requests
import re

logger = getLogger(__name__)

class _AbstractAuthorizationService(object):
    def __init__(self, config):
        self.config = config

    def can(self, action, ident):
        """
        
        Args:
            action (str):
                The action being performed (info, or show)
            ident (str):
                The identifier for the image.
        Returns:
            bool
        """
        cn = self.__class__.__name__
        raise NotImplementedError('can() not implemented for %s' % (cn,))

class NilAuthorizationService(_AbstractAuthorizationService):
    """
    This dumb version allows all actions.
    """

    def __init__(self, config):
        super(NilAuthorizationService, self).__init__(config)

    def can(self, action, ident):
        return True

class HttpAuthorizationService(_AbstractAuthorizationService):
    """
    Makes an HTTP HEAD call for authentication.
    """

    def __init__(self, config):
        super(HttpAuthorizationService, self).__init__(config)
        self.auth_endpoint = self.config.get('auth_endpoint', None)

    def can(self, action, ident):
      auth_fp = self.auth_endpoint + '/' + ident + '?method=' + action

      try:
           with closing(requests.head(auth_fp, verify=False)) as response:
               if response.status_code is 200:
                   return True
               else:
                   return False

      except requests.exceptions.MissingSchema as ms:
           message = 'Server Side Error: Error making authentication request.' 
           logger.error(message)
           raise AuthServiceException(500, message) 

