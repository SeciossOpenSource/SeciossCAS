#  This code was developped by SECIOSS (http://www.secioss.co.jp/).
#
#                 (c) 2022 SECIOSS, INC.
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public License
#  as published by the Free Software Foundation.

from datetime import datetime, timedelta
from dateutil.parser import parse
from dateutil.tz import gettz
import json
import re
from traceback import format_exc
from urllib.parse import urlencode

from .. import Audit


class Office365(Audit):
    AUTH_URL = 'https://login.microsoftonline.com'
    API_URL = 'https://manage.office.com'
    CONTENT_LIST = ['Audit.AzureActiveDirectory', 'Audit.Exchange', 'Audit.SharePoint', 'Audit.General']

    def __init__(self, args):
        super().__init__(args)
        if not self.check_init():
            return None


    def check_init(self) -> bool:
        try:
            self.client_id
            self.client_secret
            self.directory_id
            return True
        except AttributeError:
            return False


    def prepare(self):
        return self.auth()


    def content_list(self):
        # 有効なサブスクリプションの確認
        active_subscriptions = self.get_active_subscriptions()
        if active_subscriptions is None:
            return None
        contents = []
        for content in self.CONTENT_LIST:
            # 無効なサブスクリプションの有効化
            if content not in active_subscriptions:
                if not self.start_subscription(content):
                    self._warning.append(f"failed to start {content}")
                    continue
            contents.append(content)
        
        return contents


    def collect(self, start_time: datetime, **args)->bool:
        try:
            if 'content' not in args or args['content'] is None:
                self._error.append('content not found.')
                return False

            # 開始時間は最大7日前
            now = datetime.now()
            deadline = now - timedelta(days=7)
            if start_time < deadline:
                start_time = deadline
            # 最大１日間
            end_time = start_time + timedelta(days=1)
            deadline = now
            if end_time > deadline:
                end_time = deadline

            # 監査ログリスト取得
            if not self.get_content_list(args['content'], start_time=start_time, end_time=end_time):
                return False

            for content_uri in self.content_list:
                audit_contents = self.get_content(content_uri)
                if audit_contents is None:
                    return False
                self.set_data(audit_contents)
            return True
        except:
            self._error.append(format_exc())
            return False            


    def auth(self)->bool:
        try:
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            payload = {
                'grant_type': 'client_credentials',
                'resource': self.API_URL,
                'client_id': self.client_id,
                'client_secret': self.client_secret
            }
            url = f'{self.AUTH_URL}/{self.directory_id}/oauth2/token'
            result = self.throw(url, headers, 'POST', urlencode(payload).encode(), json_decode=True)
            if result is None:
                return False
            token_type = result.get('token_type')
            access_token = result.get('access_token')
            if token_type is None or access_token is None:
                self._error.append('Invalid response: ' + json.dumps(result))
                return False
            self.auth_token = f"{token_type} {access_token}"
            return True
        except:
            self._error.append(format_exc())
            return False


    def get_active_subscriptions(self):
        headers = {'Authorization': self.auth_token}
        url = f'{self.API_URL}/api/v1.0/{self.directory_id}/activity/feed/subscriptions/list'
        result = self.throw(url, headers, 'GET', None, json_decode=True)
        if result is None:
            return None
        subscriptions = []
        for s in result:
            subscriptions.append(s.get('contentType'))
        return subscriptions


    def start_subscription(self, content_type: str)->bool:
        headers = {'Authorization': self.auth_token}
        payload = {
            'PublisherIdentifier':self.directory_id,
            'contentType':content_type
        }
        url = f'{self.API_URL}/api/v1.0/{self.directory_id}/activity/feed/subscriptions/start'
        url += '?' + urlencode(payload)
        result = self.throw(url, headers, 'POST', None)
        if result is None:
            return False
        else:
            return True


    def get_content_list(self, content_type: str, start_time=None, end_time=None, next_page_uri=None)->bool:
        headers = {'Authorization': self.auth_token}
        payload = {
            'contentType': content_type,
            'PublisherIdentifier': self.directory_id
        }
        if next_page_uri is not None:
            url = next_page_uri
        else:
            self.content_list = []
            url = f'{self.API_URL}/api/v1.0/{self.directory_id}/activity/feed/subscriptions/content'
            if start_time is not None:
                payload['startTime'] = start_time.strftime('%Y-%m-%dT%H:%M:%S')
            if end_time is not None:
                payload['endTime'] = end_time.strftime('%Y-%m-%dT%H:%M:%S')

        url += '?' + urlencode(payload)
        result = self.throw(url, headers, 'GET', None, json_decode=True)
        if result is None:
            return False

        for content in result:
            if content.get('contentUri'):
                self.content_list.append(content.get('contentUri'))
        
        if self.response_header.get('NextPageUri') is not None:
            return self.get_content_list(content_type, next_page_uri=self.response_header.get('NextPageUri'))

        return True


    def get_content(self, url: str):
        headers = {'Authorization': self.auth_token}
        payload = {'PublisherIdentifier':self.directory_id}
        return self.throw(url + '?' + urlencode(payload), headers, 'GET', None, json_decode=True)


    def set_data(self, logs: list):
        ip_irregular_pattern = re.compile(r'\[(.+)\]:')
        ip_irregular_pattern2 = re.compile(r'^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):')

        for log in logs:
            data = log
            if log.get('CreationTime') is None:
                continue
            if log.get('UserAgent') is None and log.get('ExtendedProperties'):
                for i in enumerate(log.get('ExtendedProperties')):
                    if log.get('ExtendedProperties')[i[0]]['Name'] == 'UserAgent':
                        log['userAgent'] = log.get('ExtendedProperties')[i[0]]['Value']
                        break
            
            data['secioss_event_type'] = log.get('Workload')
            data['secioss_event'] = log.get('Operation')
            ip = log.get('ActorIpAddress') if log.get('ActorIpAddress') is not None else log.get('ClientIP');
            if ip is not None:
                result = re.search(ip_irregular_pattern, ip)
                if result:
                    ip = result.group(1)
                result = re.search(ip_irregular_pattern2, ip)
                if result:
                    ip = result.group(1)
                data['secioss_ip'] = ip
            data['user'] = log.get('UserId')
            data['double_check_value'] = log.get('Id')
            dt = parse(log.get('CreationTime'))
            if log.get('Workload') == 'MicrosoftTeams' and  log.get('Operation') == 'MeetingParticipantDetail':
                # Services displayed in local time are assumed to be the local time of the system
                pass
            else:
                # CreationTime are assumed to be the utc time
                dt = dt.replace(tzinfo=gettz('UTC'))
            dt = dt.astimezone(gettz('UTC'))
            data['@timestamp'] = dt.strftime('%Y-%m-%dT%H:%M:%SZ')
            self._audit.append(data)
