#  This code was developped by SECIOSS (http://www.secioss.co.jp/).
#
#                 (c) 2022 SECIOSS, INC.
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public License
#  as published by the Free Software Foundation.

from datetime import datetime
import json
import base64
from traceback import format_exc
from urllib.parse import urlencode

from .. import Audit


class Zendesk(Audit):
    def __init__(self, args):
        super().__init__(args)
        if not self.check_init():
            return None


    def check_init(self) -> bool:
        try:
            self.admin
            self.token
            self.subdomain
            return True
        except AttributeError:
            return False


    def collect(self, start_time: datetime, **args) -> bool:
        try:
            token = base64.b64encode('{}:{}'.format(self.admin + '/token', self.token).encode('utf-8')).decode('utf-8')
            headers = {'Authorization': 'Basic ' + token}
            if 'next' in args and args['next']:
                url = args['next']
            else:
                url = 'https://{}.zendesk.com/api/v2/audit_logs.json?page[size]=100&filter[created_at][]={}&filter[created_at][]={}'.format(self.subdomain, start_time.strftime('%Y-%m-%dT%H:%M:%SZ'), datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ'))
            result = self.throw(url, headers, 'GET', None, json_decode=True)
            if result is None:
                return False
            if 'audit_logs' not in result:
                self._error.append(f'Invalid response: ' + json.dumps(result))
                return False
            self.set_data(result['audit_logs'])
            if 'meta' in result and 'has_more' in result and result['meta']['has_more']:
                if 'links' in result and 'next' in result['links']['next']:
                    self._error.append(f'Invalid response: ' + json.dumps(result))
                    return False
                return self.collect(start_time, next=result['links']['next'])
            else:
                return True
        except:
            self._error.append(format_exc())
            return False


    def set_data(self, logs: list):
        for log in logs:
            data = log
            if log.get('created_at') is None:
                continue

            data['secioss_event_type'] = log.get('source_type')
            data['secioss_event'] = log.get('action')
            data['secioss_ip'] = log.get('ip_address')
            data['double_check_value'] = log.get('id')
            data['@timestamp'] = log.get('created_at')
            data['user'] = log.get('actor_id')
            self._audit.append(data)
