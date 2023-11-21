#  This code was developped by SECIOSS (http://www.secioss.co.jp/).
#
#                 (c) 2022 SECIOSS, INC.
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public License
#  as published by the Free Software Foundation.

import csv
from datetime import datetime
from dateutil.parser import parse
from dateutil.tz import gettz
import io
import json
from traceback import format_exc
from urllib.parse import urlencode

from .. import Audit


class Salesforce(Audit):
    AUTH_URL = 'https://login.salesforce.com/services/oauth2/token'
    VERSION = '55.0'
    
    def __init__(self, args):
        super().__init__(args)
        if not self.check_init():
            return None


    def check_init(self) -> bool:
        try:
            self.client_id
            self.client_secret
            self.admin
            self.admin_password
            self.instance
            self.token
            return True
        except AttributeError:
            return False


    def prepare(self) -> bool:
        versions = self.get_versions()
        if versions is None:
            self._error.append('failed to get available versions.')
            return False
        if versions[0]['version'] > self.VERSION:
            self._error.append(f'API version {self.VERSION} is too old: required >= ' + versions[0]["version"])
            return False
        
        return self.auth()
        

    def collect(self, start_time: datetime, **args) -> bool:
        try:
            headers = {'Authorization':f'Bearer {self.access_token}'}
            start = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
            query = f'q=SELECT+Id+,+EventType+,+LogFile+,+LogDate+,+LogFileFieldNames+FROM+EventLogFile+WHERE+LogDate+>=+{start}+AND+Sequence+!=+0'
            url = f'https://{self.instance}.salesforce.com/services/data/v{self.VERSION}/query?{query}'
            result = self.throw(url, headers, 'GET', None, json_decode=True)
            if result is None:
                return False
            if 'records' not in result:
                return False

            for content in result['records']:
                if 'LogFile' in content:
                    url = f'https://{self.instance}.salesforce.com{content["LogFile"]}'
                    result = self.throw(url, headers, 'GET', None)
                    if result is None:
                        return False
                    with io.StringIO(result) as f:
                        csv_reader = csv.DictReader(f)
                        audit_logs = [row for row in csv_reader]
                        self.set_data(audit_logs)
                else:
                    self._error.append('Invalid response: ' + json.dumps(content))
                    return False
            return True
        except:
            self._error.append(format_exc())
            return False


    def auth(self) -> bool:
        try:
            headers = {'Content-Type':'application/x-www-form-urlencoded'}
            payload = {
                'grant_type':'password',
                'client_id':self.client_id,
                'client_secret':self.client_secret,
                'username':self.admin,
                'password':self.admin_password + self.token
            }
            url = self.AUTH_URL
            result = self.throw(url, headers, 'POST', urlencode(payload).encode(), json_decode=True)
            if result is None:
                return False
            if 'access_token' not in result:
                self._error.append('Invalid response: ' + json.dumps(result))
                return False
            
            self.access_token = result['access_token']
            return True
        except:
            self._error.append(format_exc())
            return False


    def get_versions(self):
        url = f'https://{self.instance}.salesforce.com/services/data/'
        return self.throw(url, {}, 'GET', None, json_decode=True)


    def set_data(self, logs: list):
        for log in logs:
            data = {}
            for k in log:
                data[k] = log.get(k)
                if k == 'EVENT_TYPE':
                    data['secioss_event_type'] = log.get(k)
                elif k == 'OPERATION' or k == 'LOGIN_STATUS':
                    data['secioss_event'] = log.get(k)
                elif k == 'SOURCE_IP':
                    data['secioss_ip'] = log.get(k)
                elif 'secioss_ip' not in data and k == 'CLIENT_IP':
                    data['secioss_ip'] = log.get(k)
                elif k == 'USER_NAME':
                    data['user'] = log.get(k)
                elif 'user' not in data and k == 'USER_ID':
                    data['user'] = log.get(k)
                elif k == 'REQUEST_ID':
                    data['double_check_value'] = log.get(k)
                elif k == 'TIMESTAMP_DERIVED':
                    # TIMESTAMP_DERIVED are assumed to be the utc time
                    data['@timestamp'] = parse(log.get(k)).astimezone(gettz('UTC')).strftime('%Y-%m-%dT%H:%M:%SZ')
            if '@timestamp' not in data or data['@timestamp'] is None:
                continue

            self._audit.append(data)
