#  This code was developped by SECIOSS (http://www.secioss.co.jp/).
#
#                 (c) 2022 SECIOSS, INC.
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public License
#  as published by the Free Software Foundation.

from datetime import datetime
from dateutil.parser import parse
from dateutil.tz import gettz
import json
from urllib.parse import urlencode
from traceback import format_exc

from .. import Audit


class Box(Audit):
    API_URL = 'https://api.box.com/2.0/events'

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
        
        
    def prepare(self)->bool:
        return self.auth()


    def collect(self, start_time:datetime, **args)->bool:
        try:
            headers = {
                'Content-Type': 'application/json; charset=utf-8',
                'Authorization': self.auth_token
            }
            if 'next' in args:
                payload = {'next_stream_position': args['next']}
            else:
                payload = {
                    'stream_type': 'admin_logs',
                    'limit': 500,
                    'created_after':start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
                }

            url = self.API_URL + '?' + urlencode(payload)
            result = self.throw(url, headers, 'GET', None, json_decode=True)
            if result is None:
                return False
            if result.get('entries') is None:
                self._error.append('Invalid response: ' + json.dumps(result))
                return False

            if len(result.get('entries')) == 0:
                return True
            else:
                self.set_data(result['entries'])
                if result.get('next_stream_position'):
                    return self.collect(start_time, next=result.get('next_stream_position'))
                else:
                    return True
        except:
            self._error.append(format_exc())
            return False


    def auth(self)->bool:
        try:
            auth_token = self.token_refresh(refresh_token_replace=True)
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
            if 'source' in log:
                if 'type' in log['source']:
                    data['secioss_event_type'] = log['source']['type']
                elif 'item_type' in log['source']:
                    data['secioss_event_type'] = log['source']['item_type']                    
            data['secioss_event'] = log.get('event_type')
            data['secioss_ip'] = log.get('ip_address')
            if 'created_by' in log:
                user = None
                if 'name' in log['created_by']:
                    user = log['created_by']['name']
                if 'login' in log['created_by']:
                    user += '(' + log['created_by']['login'] + ')'
                data['user'] = user
            data['double_check_value'] = log.get('event_id')
            data['@timestamp'] = parse(log.get('created_at')).astimezone(gettz('UTC')).strftime('%Y-%m-%dT%H:%M:%SZ')
            if '@timestamp' not in data:
                continue
            self._audit.append(data)
