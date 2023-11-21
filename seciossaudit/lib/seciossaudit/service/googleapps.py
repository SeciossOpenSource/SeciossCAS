#  This code was developped by SECIOSS (http://www.secioss.co.jp/).
#
#                 (c) 2022 SECIOSS, INC.
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public License
#  as published by the Free Software Foundation.

from datetime import datetime
import re
from traceback import format_exc
from urllib.parse import urlencode

from .. import Audit


class Googleapps(Audit):
    AUTH_URL = 'https://accounts.google.com/o/oauth2/token'
    SCOPE = 'https://www.googleapis.com/auth/admin.reports.audit.readonly'
    API_URL = 'https://www.googleapis.com/admin/reports/v1/activity'

    CONTENT_LIST = [
        'login',
        'admin',
        'drive',
        'mobile',
        'token'
    ]

    def __init__(self, args):
        super().__init__(args)
        if not self.check_init():
            return None


    def check_init(self) -> bool:
        try:
            self.client_id
            self.prn
            self.certificate
            return True
        except AttributeError:
            return False


    def prepare(self) -> bool:
        return self.auth()


    def content_list(self) -> list:
        return self.CONTENT_LIST


    def collect(self, start_time: datetime, **args) -> bool:
        if 'content' not in args:
            self._error.append('content not found.')
            return False

        try:
            start = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }
            payload = {
                'startTime': start
            }
            url = f'{self.API_URL}/users/all/applications/{args["content"]}'
            if 'next' in args:
                payload['pageToken'] = args['next']
            url += '?' + urlencode(payload)
            result = self.throw(url, headers, 'GET', None, json_decode=True)
            if result is None:
                return False
            if result.get('items') is None:
                return True
                
            self.set_data(result.get('items'), type=args['content'])
            page_token = result.get('nextPageToken')
            if page_token is None:
                return True
            else:
                return self.collect(start_time, content=args['content'], next=page_token)
        except:
            self._error.append(format_exc())
            return False


    def auth(self) -> bool:
        try:
            now = int(datetime.now().timestamp())
            exp = now + 3600
            data = {
                'iss':self.client_id,
                'prn':self.prn,
                'aud':self.AUTH_URL,
                'scope':self.SCOPE,
                'exp':exp,
                'iat':now
            }
            access_token = self.jwt_auth(self.AUTH_URL, data, self.certificate)
            if access_token is None:
                return False
            self.access_token = access_token
            return True
        except:
            self._error.append(format_exc())
            return False
        

    def set_data(self, logs: list, type=None):
        for log in logs:
            data = log
            timestamp = log.get('id').get('time')
            if timestamp is None:
                continue
            
            user = '-'
            if 'actor' in log and 'email' in log['actor']:
                user = log['actor']['email']
            data['user'] = user
            data['secioss_event_type'] = type
            if 'events' in log and len(log['events']) > 0:
                event = log['events'][-1]
                data['secioss_event'] = event.get('name')
            data['secioss_ip'] = log.get('ipAddress')
            data['double_check_value'] = str(log.get('etag'))
            data['@timestamp'] = re.sub(r'\.[0-9]{3}', r'', timestamp)
            self._audit.append(data)