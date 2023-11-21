#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from configparser import ConfigParser
from os.path import isfile, isdir
from sys import exit
from seciosssecuritycheck import AWS, Azure, Gcp


CONFIG_DIR = '/opt/secioss/etc/securitycheck/'

if not isdir(CONFIG_DIR):
    print('config directory missing')
    exit(1)
if not isfile(CONFIG_DIR + 'aws.json'):
    print('aws.json missing')
    exit(1)
if not isfile(CONFIG_DIR + 'azure.json'):
    print('azure.json missing')
    exit(1)
if not isfile(CONFIG_DIR + 'gcp.json'):
    print('gcp.json missing')
    exit(1)

with open(CONFIG_DIR + 'aws.json', 'r') as f:
    AWS_RULE = json.load(f)
with open(CONFIG_DIR + 'azure.json', 'r') as f:
    AZURE_RULE = json.load(f)
with open(CONFIG_DIR + 'gcp.json', 'r') as f:
    GCP_RULE = json.load(f)


if not isfile('sample.ini'):
    print('sample.ini missing')
    exit(1)
config = ConfigParser()
config.read('sample.ini')

for service in config.sections():
    obj = None
    setting = None
    sconfig = config[service]
    if service == 'AWS':
        if None in (sconfig.get('accesskey'), sconfig.get('secretkey')):
            print('AWS settings is invalid')
            continue

        obj = AWS(sconfig.get('region'), accesskey=sconfig.get('accesskey'), secretkey=sconfig.get('secretkey'))
        setting = AWS_RULE
    elif service == 'Azure':
        if None in (sconfig.get('directory_id'), sconfig.get('client_id'), sconfig.get('client_secret'), sconfig.get('refresh_token')):
            print('Azure settings is invalid')
            continue
        
        obj = Azure(directory_id=sconfig.get('directory_id'), client_id=sconfig.get('client_id'), client_secret=sconfig.get('client_secret'), refresh_token=sconfig.get('refresh_token'))
        setting = AZURE_RULE
    elif service == 'Gcp':
        if None in (sconfig.get('prn'), sconfig.get('iss'), sconfig.get('certificate')):
            print('Gcp settings is invalid')
            continue

        obj = Gcp(prn=sconfig.get('prn'), iss=sconfig.get('iss'), certificate=sconfig.get('certificate'))
        setting = GCP_RULE

    if obj is None:
        continue
    elif obj.error():
        print(f'failed to generate {service} object')
        print(obj.error())
        continue

    refresh_token = obj.refresh_token()
    if refresh_token is not None:
        config.set(service, 'refresh_token')
        continue

    obj.fetch()
    if obj.error():
        print(f'failed to fetch {service} settings')
        print(obj.error())
        obj.clear()
        continue
        
    report = obj.check(setting)
    print(report)
