#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime, timedelta
from configparser import ConfigParser
import time
from os.path import isfile
from sys import exit


if not isfile('sample.ini'):
    print('sample.ini missing')
    exit(1)

config = ConfigParser()
config.read('sample.ini', 'UTF-8')

start = datetime.now() - timedelta(days = 7)
for service in config.sections():
    logs = []
    info = {}
    sconfig = config[service]
    if service == 'AWS':
        if None in (sconfig.get('access_key'), sconfig.get('secret_key')):
            print('aws settings is invalid')
            continue

        info['region'] = sconfig.get('region')
        info['access_key'] = sconfig.get('access_key')
        info['secret_key'] = sconfig.get('secret_key')
    elif service == 'Box' or service == 'Dropbox':
        if None in (sconfig.get('client_id'), sconfig.get('client_secret'), sconfig.get('refresh_token'), sconfig.get('token_url')):
            print(f'{service} settings is invalid')
            continue

        info['client_id'] = sconfig.get('client_id')
        info['client_secret'] = sconfig.get('client_secret')
        info['refresh_token'] = sconfig.get('refresh_token')
        info['token_url'] = sconfig.get('token_url')
    elif service == 'Googleapps':
        if None in (sconfig.get('client_id'), sconfig.get('prn'), sconfig.get('certificate')):
            print(f'{service} settings is invalid')
            continue

        info['client_id'] = sconfig.get('client_id')
        info['prn'] = sconfig.get('prn')
        info['certificate'] = sconfig.get('certificate')
    elif service == 'Lineworks':
        if None in (sconfig.get('client_id'), sconfig.get('domain_id'), sconfig.get('service_account'), sconfig.get('client_secret'), sconfig.get('certificate')):
            print(f'{service} settings is invalid')
            continue

        info['client_id'] = sconfig.get('client_id')
        info['client_secret'] = sconfig.get('client_secret')
        info['domain_id'] = sconfig.get('domain_id')
        info['service_account'] = sconfig.get('service_account')
        info['certificate'] = sconfig.get('certificate')
    elif service == 'Office365':
        if None in (sconfig.get('client_id'), sconfig.get('client_secret'), sconfig.get('directory_id')):
            print(f'{service} settings is invalid')
            continue

        info['client_id'] = sconfig.get('client_id')
        info['client_secret'] = sconfig.get('client_secret')
        info['directory_id'] = sconfig.get('directory_id')
    elif service == 'Salesforce':
        if None in (sconfig.get('client_id'), sconfig.get('client_secret'), sconfig.get('admin'), sconfig.get('admin_password'), sconfig.get('instance'), sconfig.get('token')):
            print(f'{service} settings is invalid')
            continue

        info['client_id'] = sconfig.get('client_id')
        info['client_secret'] = sconfig.get('client_secret')
        info['admin'] = sconfig.get('domain_id')
        info['admin_password'] = sconfig.get('admin_password')
        info['instance'] = sconfig.get('instance')
        info['token'] = sconfig.get('token')
    elif service == 'Zendesk':
        if None in (sconfig.get('admin'), sconfig.get('token'), sconfig.get('subdomain')):
            print(f'{service} settings is invalid')
            continue

        info['admin'] = sconfig.get('admin')
        info['token'] = sconfig.get('token')
        info['subdomain'] = sconfig.get('subdomain')
    else:
        continue

    mod = __import__('seciossaudit', fromlist=[service])
    class_def = getattr(mod, service)
    audit = class_def(info)
    if audit is None:
        print(f'Failed to create {service} object.')
        continue
    if not audit.prepare():
        print(audit._error)
        continue
        
    if service == 'Box':
        if audit.refresh_token is None:
            continue
        config.set('Box', audit.refresh_token)
    content_list = audit.content_list()
    if content_list is None:
        content_list = [None]

    filtered = []
    for content in content_list:
        if not audit.collect(start, content=content):
            print(audit._error)
            continue
        else:
            if len(audit._warning) > 0:
                print(audit._warning)

        logs = audit._audit
        audit._audit = []

        if len(logs) > 0:
            logs = sorted(logs, key=lambda x: x['@timestamp'])

        if service == 'Lineworks':
            time.sleep(60)
                
    print(logs)
