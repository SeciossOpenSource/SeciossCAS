#  This code was developped by SECIOSS (http://www.secioss.co.jp/).
#
#                 (c) 2022 SECIOSS, INC.
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public License
#  as published by the Free Software Foundation.

from datetime import datetime
import json
import boto3
from traceback import format_exc

from .. import Audit


class AWS(Audit):
    """
    AWS Audit Class
    """
    def __init__(self, args):
        super().__init__(args)
        if not self.check_init():
            return None


    def check_init(self) -> bool:
        try:
            self.access_key
            self.secret_key
            self.region
            return True
        except AttributeError:
            return False


    def collect(self, start_time: datetime, **args)->bool:
        try:
            client = boto3.client(
                service_name='cloudtrail',
                region_name=self.region,
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key
            )
            lookup_attributes_list = [
                [
                    {'AttributeKey': 'ReadOnly', 'AttributeValue': 'false'}
                ],
                [
                    {'AttributeKey': 'EventSource', 'AttributeValue': 's3.amazonaws.com'},
                    {'AttributeKey': 'ReadOnly', 'AttributeValue': 'true'}
                ]
            ]
            logs = []
            paginator = client.get_paginator('lookup_events')
            for lookup_attributes in lookup_attributes_list:
                for page in paginator.paginate(LookupAttributes=lookup_attributes, StartTime=start_time):
                    if 'Events' not in page:
                        continue
                    logs.extend([json.loads(row['CloudTrailEvent']) for row in page['Events']])
            if len(logs) > 0:
                self.set_data(logs)
        except:
            self._error.append(format_exc())
            return False

        return True


    def set_data(self, logs: list):
        for log in logs:
            data = log
            user = '-'
            if 'userIdentity' in log:
                if 'type' in log['userIdentity'] and log['userIdentity']['type'] == 'AWSService' and 'invokeBy' in log['userIdentity']:
                    user = log['userIdentity']['invokeBy']
                elif 'arn' in log['userIdentity']:
                    user = log['userIdentity']['arn']
                elif 'userName' in log['userIdentity']:
                    user = log['userIdentity']['userName']
                elif 'sessionContext' in log['userIdentity'] and 'sessionIssuer' in log['userIdentity']['sessionContext']:
                    if 'arn' in log['userIdentity']['sessionContext']['sessionIssuer']:
                        user = log['userIdentity']['sessionContext']['sessionIssuer']['arn']
                    elif 'userName' in log['userIdentity']['sessionContext']['sessionIssuer']:
                        user = log['userIdentity']['sessionContext']['sessionIssuer']['arn']
            data['user'] = user
            data['secioss_event_type'] = log.get('eventSource')
            data['secioss_event'] = log.get('eventName')
            data['secioss_ip'] = log.get('sourceIPAddress')
            data['double_check_value'] = log.get('eventID')
            data['@timestamp'] = log.get('eventTime')
            if '@timestamp' not in data:
                continue
            self._audit.append(data)
