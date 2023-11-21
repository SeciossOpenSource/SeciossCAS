#  This code was developped by SECIOSS (http://www.secioss.co.jp/).
#
#                 (c) 2022 SECIOSS, INC.
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public License
#  as published by the Free Software Foundation.

import inspect
import json
import jwt
from traceback import format_exc
from urllib import request
from urllib.parse import urlencode


class Audit:
    TIMEOUT = 300
    
    """
    Audit Log Base Class
    """
    def __init__(self, args: dict):
        self._error = []
        self._warning = []
        self._audit = []
        for k, v in args.items():
            setattr(self, k.lower(), v)


    def content_list(self):
        return None


    def prepare(self)->bool:
        return True


    def jwt_auth(self, url: str, data: dict, certificate: bytes, **args):
        token = jwt.encode(data, certificate, algorithm="RS256").decode('utf-8')
        payload = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion': token,
        }
        if 'client_id' in args and args['client_id']:
            payload['client_id'] = args['client_id']
        if 'client_secret' in args and args['client_secret']:
            payload['client_secret'] = args['client_secret']
        if 'scope' in args and args['scope']:
            payload['scope'] = args['scope']

        headers = {'Content-Type':'application/x-www-form-urlencoded'}
        body = urlencode(payload).encode('utf-8')
        result = self.throw(url, headers, 'POST', body, json_decode=True)
        if result is None:
            return None
        if not result.get('access_token'):
            self._error.append(inspect.stack()[1].function + ' Invalid response: ' + json.dumps(result))
            return None
                    
        return result['access_token']


    def token_refresh(self, refresh_token_replace=False):
        payload = {
            'grant_type': 'refresh_token',
            'refresh_token': self.refresh_token,
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        headers = {'Content-Type':'application/x-www-form-urlencoded'}
        body = urlencode(payload).encode()
        result = self.throw(self.token_url, headers, 'POST', body, json_decode=True)
        if result is None:
            return None
        if result.get('access_token') is None:
            self._error.append(inspect.stack()[1].function + ' Invalid response: ' + json.dumps(result))
            return
        if refresh_token_replace:
            if result.get('refresh_token') is None:
                self._error.append(inspect.stack()[1].function + ' Invalid response.')
                return        
            self.refresh_token = result.get('refresh_token')
        token_type = result['token_type'].capitalize() if 'token_type' in result else 'Bearer'

        return f"{token_type} {result['access_token']}"

    
    def throw(self, url: str, header: dict, method: str, body: bytes, timeout=None, json_decode=False):
        if timeout is None:
            timeout = self.TIMEOUT
        self.response_header = None
        try:
            req = request.Request(url, headers=header, method=method)
            if not body:
                body = None

            with request.urlopen(req, body, timeout) as res:
                contents = res.read().decode()
                self.response_header = res.info()
                if json_decode:
                    contents = json.loads(contents)
                return contents
        except request.HTTPError as e:
            self._error.append(inspect.stack()[1].function + ' ' + str(e))
            return None
        except:
            self._error.append(inspect.stack()[1].function + ' ' + format_exc())
            return None
