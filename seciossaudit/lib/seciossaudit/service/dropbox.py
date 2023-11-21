#  This code was developped by SECIOSS (http://www.secioss.co.jp/).
#
#                 (c) 2022 SECIOSS, INC.
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public License
#  as published by the Free Software Foundation.

from datetime import datetime
import hashlib
import json
from traceback import format_exc

from .. import Audit


class Dropbox(Audit):
    API_URL = 'https://api.dropboxapi.com/2/team_log/get_events'

    def __init__(self, args):
        super().__init__(args)
        if not self.check_init():
            return None


    def check_init(self) -> bool:
        try:
            self.client_id
            self.client_secret
            self.refresh_token
            self.token_url
            return True
        except AttributeError:
            return False


    def prepare(self) -> bool:
        return self.auth()
    

    def collect(self, start_time: datetime, **args) -> bool:
        try:
            headers = {
                'Content-Type': 'application/json; charset=utf-8',
                'Authorization': self.auth_token
            }
            if 'next' in args:
                payload = {'cursor': args['next']}
                url = f'{self.API_URL}/continue'
            else:
                payload = {
                    'limit': 1000,
                    'time':{'start_time': start_time.strftime('%Y-%m-%dT%H:%M:%SZ')}
                }
                url = self.API_URL
            body = json.dumps(payload).encode()
            result = self.throw(url, headers, 'POST', body, json_decode=True)
            if result is None:
                return False
            if 'events' not in result:
                self._error.append('Invalid response: ' + json.dumps(result))
                return False
            if len(result['events']) == 0:
                return True

            self.set_data(result['events'])
            if 'has_more' not in result or not result['has_more']:
                return True
            else:
                return self.collect(start_time, next=result['cursor'])
        except:
            self._error.append(format_exc())
            return False



    def auth(self) -> bool:
        try:
            auth_token = self.token_refresh()
            if auth_token is None:
                return False
            else:
                self.auth_token = auth_token
                return True
        except:
            self._error.append(format_exc())
            return False


    def set_data(self, logs: list):
        for log in logs:
            data = log
            if 'actor' in log and '.tag' in log['actor']:
                if log['actor']['.tag'] == 'dropbox':
                    continue
                display_name = log['actor'][log['actor']['.tag']]['display_name']
                if log['actor']['.tag'] == 'app':
                    detail_name = log['actor']['app']['app_id']
                else:
                    detail_name = log['actor'][log['actor']['.tag']]['email']
                data['user'] = f'{display_name}({detail_name})'

            data['@timestamp'] = log['timestamp']
            if log['@timestamp'] is None:
                continue
            if 'event_category' in log and '.tag' in log['event_category']:
                data['secioss_event_type'] = log['event_category']['.tag']
            if 'event_type' in log and '.tag' in log['event_type']:
                data['secioss_event'] = log['event_type']['.tag']
            if 'origin' in log and 'geo_location' in log['origin'] and 'ip_address' in log['origin']['geo_location']:
                data['secioss_ip'] = log['origin']['geo_location']['ip_address']
            data['double_check_value'] = hashlib.md5(str(data).encode()).hexdigest()
            self._audit.append(data)
