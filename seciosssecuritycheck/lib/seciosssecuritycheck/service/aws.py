#  This code was developped by SECIOSS (http://www.secioss.co.jp/).
#
#                 (c) 2022 SECIOSS, INC.
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public License
#  as published by the Free Software Foundation.

# -*- coding: utf-8 -*-
import boto3
import csv
import io
from traceback import format_exc
from .. import SecurityCheck
from . import AWS_API


class AWS(SecurityCheck):
    """
    AWS Class
    SecurityCheck Child Class
    """
    
    
    def __init__(self, *regions, **opt):
        opt2 = opt.copy()
        super().__init__(**opt2)

        accesskey = opt2.pop('accesskey', None)
        secretkey = opt2.pop('secretkey', None)
        region = regions[0] if regions and len(regions) > 0 and regions[0] is not None else 'us-east-1'

        if 'time' not in opt:
            if 'accesskey' not in opt or 'secretkey' not in opt:
                self.set_error('Invalid Parameters.')
                return
            self.accesskey = accesskey
            self.secretkey = secretkey

        self.service = 'aws'
        self.region = region
        self.region_param = [['AvailabilityZone'],['Placement','AvailabilityZone']]


    def fetch(self):
        try:
            if self.accesskey is None or self.secretkey is None:
                self.set_error('Error in fetch: accesskey or secretkey not found.')
                return

            if not self.generate_report():
                return

            for service in ['ec2', 'rds', 's3', 'lightsail', 'elb', 'iam']:
                client = self.get_client(service)
                if client is None:
                    return
                target_list = [ s for s, info in AWS_API.items() if info.get('service') == service]
                for name in target_list:
                    if 'service' not in AWS_API[name] or 'method' not in AWS_API[name]:
                        continue
                    paginate = AWS_API[name]['paginate'] if 'paginate' in AWS_API[name] else True
                    method = AWS_API[name]['method']
                    container = AWS_API[name]['container'] if 'container' in AWS_API[name] else None
                    if name == 'bucketacl':
                        data = []
                        buckets = self.load('bucket')
                        buckets = [bucket['Name'] for bucket in buckets if 'Name' in bucket]
                        for bucket in buckets:
                            if not bucket:
                                continue
                            d = self.get_list(client, method, bucket=bucket)
                            if d:
                                del d['ResponseMetadata']
                                d['bucket'] = bucket
                                data.append(d)
                        if len(data) == 0:
                            continue                        
                    else:
                        data = self.get_list(client, method, container=container, paginate=paginate)
                        if data is None:
                            return
                        if name == 'report':
                            data = self.parse_report(data)
                            if data is None:
                                return
                        elif name == 'instance':
                            tmp = []
                            for reservation in data:
                                if 'Instances' in reservation:
                                    tmp.append(reservation['Instances'])
                            data = tmp
                        
                    self.save(name, data)
        except:
            self.set_error(f'Error in fetch: ' + format_exc())
            return None


    def get_client(self, service):
        try:
            return boto3.client(
                service_name=service,
                region_name=self.region,
                aws_access_key_id=self.accesskey,
                aws_secret_access_key=self.secretkey
            )
        except:
            self.set_error(f'Error in get_client {service}: ' + format_exc())
            return None


    def get_list(self, client, method: str, container=None, paginate=False, bucket=None):
        try:
            result = None
            if paginate:
                paginator = client.get_paginator(method)
                result = []
                for page in paginator.paginate():
                    if container is None:
                        result.extend(page)
                    elif container in page:
                        result.extend(page[container])
            else:
                if bucket is None:
                    response = eval(f'client.{method}')()
                else:
                    response = eval(f'client.{method}')(Bucket=bucket)
                if container is None:
                    result = response
                elif container in response:
                    result = response[container]

            return result
        except:
            self.set_error(f'Error in get_list {method}: ' + format_exc())
            return None


    def generate_report(self)->bool:
        try:
            client = self.get_client('iam')
            if client is None:
                return False
            result = self.get_list(client, 'generate_credential_report', container='State', paginate=False)
            if result is None:
                return False
            return True
        except:
            self.set_error('Error in generate_report: ' + format_exc())
            return False


    def parse_report(self, data: bytes):
        try:
            report = []
            with io.StringIO(data.decode()) as f:
                reader = csv.DictReader(f)
                headers = reader.fieldnames
                for row in reader:
                    info = {}
                    for name in headers:
                        info[name] = row[name]
                    report.append(info)
            return report
        except:
            self.set_error('Error in parse_report: ' + format_exc())
            return None

