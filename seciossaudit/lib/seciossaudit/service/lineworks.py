#  This code was developped by SECIOSS (http://www.secioss.co.jp/).
#
#                 (c) 2022 SECIOSS, INC.
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public License
#  as published by the Free Software Foundation.

import csv
from datetime import datetime
from dateutil.tz import gettz
from hashlib import md5
import io
import json
from urllib.parse import urlencode
from traceback import format_exc

from .. import Audit


class Lineworks(Audit):
    API_URL = 'https://www.worksapis.com/v1.0/audits/logs/download'
    AUTH_URL = 'https://auth.worksmobile.com/oauth2/v2.0/token'

    CONTENT_LIST = [
        'auth',
        'home',
        'drive',
        'calendar',
        'contact',
        'form',
        'share',
        'note',
        'received-mail',
        'message',
        'sent-mail'
    ]
    # CSV Format
    csv_format = {
        "admin":{
            'Date':'date',
            'Service':'service',
            'Event target':'event_target',
            'Service Type':'service_type',
            'Task':'task',
            'Status':'status',
            'User':'user',
            'IP Address':'ip_address'
        },
        'auth':{
            'Date':'date',
            'User':'user',
            'Description':'description',
            'Service Type':'service_type',
            'IP Address':'ip_address'
        },
        'home':{
            'Date':'date',
            'User':'user',
            'Service Type':'service_type',
            'Task':'task',
            'Subject':'subject',
            'Board Name':'board_name',
            'Status':'status'
        },
        'drive':{
            'Date':'date',
            'User':'user',
            'Service Type':'service_type',
            'Task':'task',
            'Original':'original',
            'Updates':'updates',
            'Status':'status'
        },
        'calendar':{
            'Date':'date',
            'User':'user',
            'Service Type':'service_type',
            'Task':'task',
            'Subject':'subject',
            'Calendar ID':'calendar_id',
            'Status':'status'
        },
        'contact':{
            'Date':'date',
            'User':'user',
            'Service Type':'service_type',
            'Task':'task',
            'Target':'target',
            'Status':'status'
        },
        'form':{
            'Date':'date',
            'User':'user',
            'Service Type':'service_type',
            'Task':'task',
            'Form Title':'form_title',
            'Status':'status'
        },
        'share':{
            'Date':'date',
            'User':'user',
            'Shared by':'shared_by',
            'Task':'participant',
            'Service Type':'service_type',
            'Task':'task',
            'Shared with':'shared_with'
        },
        'note':{
            'Date':'date',
            'User':'user',
            'Service Type':'service_type',
            'Task':'task',
            'Subject':'subject',
            'Board Name':'board_name',
            'Team/Group':'team_groups',
            'Status':'status'
        },
        'received-mail':{
            'Received Time':'date',
            'Reception Results':'reception_results',
            'Sent server IP':'sent_server_ip',
            'Subject':'subject',
            'Sender':'sender',
            'Recipient':'recipient',
            'Mail Size(Bytes)':'mail_size_bytes'
        },
        'message':{
            'Date':'date',
            'Sender':'sender',
            'Recipient':'recipient',
            'Message':'message'
        },
        'sent-mail':{
            'Sent Time':'date',
            'Subject':'subject',
            'Sender':'sender',
            'Recipient':'recipient',
            'Status':'status',
            'Attachment':'attachment',
            'Mail Size(Bytes)':'mail_size_bytes'
        }
    }


    def __init__(self, args):
        super().__init__(args)
        if not self.check_init():
            return None


    def check_init(self) -> bool:
        try:
            self.client_id
            self.domain_id
            self.service_account
            self.client_secret
            self.certificate
            return True
        except AttributeError:
            return False


    def prepare(self):
        return self.auth()


    def content_list(self) -> list:
        return self.CONTENT_LIST


    def collect(self, start_time: datetime, **args)->bool:
        try:
            if 'content' not in args or args['content'] is None:
                self._error.append('content not found.')
                return False

            end_time = datetime.now()
            headers = {
                'Authorization': f'Bearer {self.access_token}',
            }
            payload = {
                'service': args['content'],
                'startTime': start_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
                'endTime': end_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
                'domainId': self.domain_id
            }
            url = self.API_URL + '?' + urlencode(payload)
            result = self.throw(url, headers, 'GET', None)
            if result is None:
                return False
            if result[0] == '\ufeff':
                result = result[1:]
            with io.StringIO(result) as f:
                csv_reader = csv.DictReader(f)
                audit_logs = [row for row in csv_reader]
                self.set_data(audit_logs, type=args['content'])
                
            return True
        except:
            self._error.append(format_exc())
            return False


    def auth(self) -> bool:
        try:
            now = int(datetime.now().timestamp())
            exp = now + 3600
            data = {
                'iss':self.client_id,
                'sub':self.service_account,
                'exp':exp,
                'iat':now
            }
            access_token = self.jwt_auth(self.AUTH_URL, data, self.certificate, client_id=self.client_id, client_secret=self.client_secret, scope='audit.read')
            if access_token is None:
                return False
            self.access_token = access_token
            return True
        except:
            self._error.append(format_exc())
            return False
        

    def set_data(self, logs: list, type=None):
        csv_format = self.csv_format[type]

        for log in logs:
            data = {}
            for key, value in csv_format.items():
                if key not in log:
                    continue
                data[value] = log.get(key)
                if key == 'Date' or key == 'Received Time' or key == 'Sent Time':
                    # Date are assumed to be the local time of the system
                    dt = datetime.strptime(log.get(key), '%Y-%m-%d %H:%M:%S')
                    data['@timestamp'] = dt.astimezone(gettz('UTC')).strftime('%Y-%m-%dT%H:%M:%SZ')
                if key == 'Task' or key == 'Description':
                    data['secioss_event'] = log.get(key)
                if key == 'IP Address' or key == 'Sent server IP':
                    data['secioss_ip'] = log.get(key)
                if type == 'received-mail' and key == 'Recipient':
                    data['user'] = log.get(key)
                if (type == 'message' or type == 'sent-mail') and key == 'Sender':
                    data['user'] = log.get(key)
            if '@timestamp' not in data:
                continue
            data['secioss_event_type'] = type
            data['double_check_value'] = md5(json.dumps(log).encode()).hexdigest()
            self._audit.append(data)