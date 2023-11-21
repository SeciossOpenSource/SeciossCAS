#  This code was developped by SECIOSS (http://www.secioss.co.jp/).
#
#                 (c) 2022 SECIOSS, INC.
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public License
#  as published by the Free Software Foundation.

# -*- coding: utf-8 -*-
import jwt
import json
from traceback import format_exc
from urllib import error
from datetime import datetime
from .. import SecurityCheck, throw
from . import GCP_TOKEN_EP, GCP_SCOPE, GCP_API, GCP_JWT, GCP_REGIONS



class Gcp(SecurityCheck):
    """
    Gcp Class
    SecurityCheck Child Class
    """


    def __init__(self, *regions, **opt):
        opt2 = opt.copy()
        super().__init__(**opt2)

        prn = opt2.pop('prn', None)
        iss = opt2.pop('iss', None)
        certificate = opt2.pop('certificate', None)

        if 'time' not in opt:
            if 'prn' not in opt or 'iss' not in opt or 'certificate' not in opt:
                self.set_error('Invalid Parameters.')
                return

            # Authentication
            now = int(datetime.now().timestamp())
            exp = now + GCP_JWT['expire']
            payload = {
                'iss':iss,
                'scope':GCP_SCOPE,
                'aud':GCP_TOKEN_EP,
                'exp':exp,
                'iat':now,
                'prn':prn
            }
            try:
                token = jwt.encode(payload,certificate,GCP_JWT['algorithm'],{'typ':'JWT'}).decode('utf-8')
                data = {'grant_type':GCP_JWT['grant_type'],'assertion':token}
                header = {'Content-Type':'application/json; charset=utf-8'}
                body = json.dumps(data).encode()
                contents = throw(GCP_TOKEN_EP, header, 'POST', body, self.timeout)
                if 'access_token' not in contents:
                    self.set_error('Error in authentication: access_token not found.')
                    return
                self.token = contents['access_token']
            except error.URLError as e:
                self.set_error('Error in authentication: ' + str(e))
            except Exception as e:
                self.set_error('Error in authentication: ' + format_exc())

        self.service = 'gcp'
        self.regions = regions
        self.region_param = [['region'], ['zone']]


    def fetch(self):
        try:
            if not self.token:
                self.set_error('Error in fetch: token not found.')
                return

            if self.regions and len(self.regions) > 0:
                regions = {}
                for r in self.regions:
                    if r in GCP_REGIONS:
                        regions[r] = GCP_REGIONS[r]
            else:
                regions = GCP_REGIONS
                
            projects = self.get_list('project')
            if projects:
                self.save('project', projects)
                pids = [p.get('projectId') for p in projects]
                for pid in pids:
                    iam = self.get_list('iam', project=pid)
                    if iam:
                        iams = [{**i, **{'projectId':pid}} for i in iam]
                        self.save('iam', iams)
                    net = self.get_list('network', project=pid)
                    if net:
                        nets = [{**n, **{'projectId':pid}} for n in net]
                        self.save('network', nets)
                    fw = self.get_list('firewall', project=pid)
                    if fw:
                        fws = [{**f, **{'projectId':pid}} for f in fw]
                        self.save('firewall', fws)
                    sa = self.get_list('serviceaccount', project=pid)
                    if sa:
                        sas = [{**s, **{'projectId':pid}} for s in sa]
                        self.save('serviceaccount', sas)
                        snames = [s.get('name') for s in sa]
                        for s in snames:
                            key = self.get_list('serviceaccountkey', serviceaccount=s)
                            if key:
                                keys = [{**k, **{'projectId':pid, 'serviceaccount':s}} for k in key]
                                self.save('serviceaccountkey', keys)
                    buk = self.get_list('bucket', project=pid)
                    if buk:
                        buks = [{**b, **{'projectId':pid}} for b in buk]
                        self.save('bucket', buks)
                        bnames = [b.get('name') for b in buk]
                        for b in bnames:
                            bp = self.get_list('bucketpolicy', project=pid, bucket=b)
                            if bp:
                                bps = [{**b, **{'projectId':pid, 'bucket':b}} for b in bp]
                                self.save('bucketpolicy', bps)
                    
                    for r, azs in regions.items():
                        snet = self.get_list('subnetwork', project=pid, region=r)
                        if snet:
                            snets = [{**s, **{'projectId':pid, 'region':r}} for s in snet]
                            self.save('subnetwork', snets)
                        for az in azs:
                            z = r + '-' + az
                            ist = self.get_list('instance', project=pid, zone=z)
                            if ist:
                                ists = [{**i, **{'projectId':pid, 'zone':z}} for i in ist]
                                self.save('instance', ists)
                            cl = self.get_list('cluster', project=pid, zone=z)
                            if cl:
                                culs = [{**c, **{'projectId':pid, 'zone':z}} for c in cl]
                                self.save('cluster', culs)
            return
        except:
            self.set_error(f'Error in fetch: ' + format_exc())
            return None


    def get_list(self, source, **opt):
        project = opt['project'] if 'project' in opt else None
        zone = opt['zone'] if 'zone' in opt else None
        region = opt['region'] if 'region' in opt else None
        bucket = opt['bucket'] if 'bucket' in opt else None
        serviceaccount = opt['serviceaccount'] if 'serviceaccount' in opt else None

        url = None
        method = None
        data = None
        content_name = None
        if source == 'project':
            url = GCP_API['project']
            content_name = 'projects'
        elif source == 'iam':
            if not project:
                self._warning.append('Error in get_list iam: project not found.')
                return

            url = GCP_API['project'] + '/' + project + ':getIamPolicy'
            method = 'POST'
            data = {'options': {'requestedPolicyVersion': 0}}
            content_name = 'bindings'
        elif source == 'network':
            if not project:
                self._warning.append('Error in get_list network: project not found.')
                return

            url = GCP_API['compute'] + '/' + project + '/global/networks'
            content_name = 'items'
        elif source == 'firewall':
            if not project:
                self._warning.append('Error in get_list firewall: project not found.')
                return

            url = GCP_API['compute'] + '/' + project + '/global/firewalls'
            content_name = 'items'
        elif source == 'serviceaccount':
            if not project:
                self._warning.append('Error in get_list serviceaccount: project not found.')
                return

            url = GCP_API['iam'] + '/projects/' + project + '/serviceAccounts'
            content_name = 'accounts'
        elif source == 'bucket':
            if not project:
                self._warning.append('Error in get_list bucket: project not found.')
                return

            url = GCP_API['storage'] + '?project=' + project
            content_name = 'items'
        elif source == 'instance':
            if not project or not zone:
                self._warning.append('Error in get_list instance: project or zone not found.')
                return

            url = GCP_API['compute'] + '/' + project + '/zones/' + zone + '/instances'
            content_name = 'items'
        elif source == 'cluster':
            if not project or not zone:
                self._warning.append('Error in get_list cluster: project or zone not found.')
                return

            url = GCP_API['container'] + '/' + project + '/zones/' + zone + '/clusters'
            content_name = 'clusters'
        elif source == 'subnetwork':
            if not project or not region:
                self._warning.append('Error in get_list subnetwork: project or region not found.')
                return

            url = GCP_API['compute'] + '/' + project + '/regions/' + region + '/subnetworks'
            content_name = 'items'
        elif source == 'bucketpolicy':
            if not bucket:
                self._warning.append('Error in get_list bucketpolicy: bucket not found.')
                return

            url = GCP_API['storage'] + '/' + bucket + '/iam'
            content_name = 'bindings'
        elif source == 'serviceaccountkey':
            if not serviceaccount:
                self._warning.append('Error in get_list serviceaccountkey: serviceaccount not found.')
                return

            url = GCP_API['iam'] + '/' + serviceaccount + '/keys'
            content_name = 'keys'
        else:
            self._warning.append('Error in get_list ' + source + ': source is invalid.')
            return

        header = {'Content-Type':'application/json','Authorization':'Bearer ' + self.token}
        method = method if method is not None else 'GET'
        try:
            if data:
                body = json.dumps(data).encode()
            else:
                body = None
            contents = throw(url, header, method, body, self.timeout)
            if contents and content_name in contents:
                return contents[content_name]
        except error.URLError as e:
            self._warning.append('Error in get_list ' + str(project) + ' ' + source + ': ' + str(e))
        except Exception as e:
            self._warning.append('Error in get_list ' + str(project) + ' ' + source + ': ' + format_exc())
        return