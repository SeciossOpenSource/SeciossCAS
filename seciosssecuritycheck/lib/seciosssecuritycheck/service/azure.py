#  This code was developped by SECIOSS (http://www.secioss.co.jp/).
#
#                 (c) 2022 SECIOSS, INC.
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public License
#  as published by the Free Software Foundation.

# -*- coding: utf-8 -*-
from traceback import format_exc
from urllib import error, parse
from .. import SecurityCheck, throw
from . import AZURE_TOKEN_EP, AZURE_API_EP, AZURE_API


class Azure(SecurityCheck):
    """
    Azure Class
    SecurityCheck Child Class
    """
    
    
    def __init__(self, **opt):
        opt2 = opt.copy()
        super().__init__(**opt2)

        dirid = opt2.pop('directory_id', None)
        client = opt2.pop('client_id', None)
        secret = opt2.pop('client_secret', None)
        refresh_token = opt2.pop('refresh_token', None)
        self._refresh_token = None
        
        if 'time' not in opt:
            if 'directory_id' not in opt or 'client_id' not in opt or 'client_secret' not in opt or 'refresh_token' not in opt:
                self.set_error('Invalid Parameters.')
                return

            # Authentication
            data = {
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token,
                'client_id': client,
                'client_secret': secret
            }
            header = {'Content-Type':'application/x-www-form-urlencoded; charset=utf-8'}
            url = AZURE_TOKEN_EP
            url = url.replace('{tenant_id}', dirid)
            try:
                body = parse.urlencode(data).encode()
                contents = throw(url, header, 'POST', body, self.timeout)
                if 'access_token' not in contents or 'token_type' not in contents or 'refresh_token' not in contents:
                    self.set_error('Error in authentication: access_token or token_type not found.')
                    return
                self.token = contents['token_type'] + ' ' + contents['access_token']
                self._refresh_token = contents['refresh_token']
            except error.URLError as e:
                self.set_error('Error in authentication: ' + str(e))
            except Exception as e:
                self.set_error('Error in authentication: ' + format_exc())

        self.service = 'azure'
        self.region_param = [['subscriptionId']]


    def fetch(self):
        try:
            if not self.token:
                self.set_error('Error in fetch: token not found.')
                return
                
            subs = self.get_list('subscription')
            if not subs:
                self.set_error('Error in fetch: subscription not found.')
                return
            
            self.save('subscription', subs)
            subids = [s.get('subscriptionId') for s in subs]
            resources = AZURE_API.keys()
            for subid in subids:
                for resource in resources:
                    if resource == 'subscription':
                        continue
                    
                    rs = self.get_list(resource, subscriptionId=subid)
                    if rs:
                        rss = [{**r, **{'subscriptionId':subid}} for r in rs]
                        self.save(resource, rss)
                
            return
        except:
            self.set_error(f'Error in fetch: ' + format_exc())
            return None


    def get_list(self, resource: str, **opt):
        subid = opt['subscriptionId'] if 'subscriptionId' in opt else None

        url = self.api_url(resource)
        if not url:
            self._warning.append('Error in get_list ' + resource + ': ' + resource + ' is invalid.')

        if resource != 'subscription':
            if not subid:
                self._warning.append('Error in get_list ' + resource + ': subscriptionId not found.')
                return
            url = url.replace('{subid}', subid)    
            
        header = {'Content-Type':'application/x-www-form-urlencoded; charset=utf-8','Authorization':self.token}
        try:
            contents = throw(url, header, 'GET', None, self.timeout)
            if not contents or 'value' not in contents:
                self._warning.append('Error in get_list ' + str(subid) + ' ' + resource + ': value not found.')
            return contents['value']
        except error.URLError as e:
            self._warning.append('Error in get_list ' + str(subid) + ' ' + resource + ': ' + str(e))
        except Exception:
            self._warning.append('Error in get_list ' + str(subid) + ' ' + resource + ': ' + format_exc())
        return
    
    
    def api_url(self, resource: str):
        if 'path' not in AZURE_API[resource] or 'version' not in AZURE_API[resource]:
            return

        url = AZURE_API_EP + AZURE_API['subscription']['path']
        if resource == 'subscription':
            url += '?api-version=' + AZURE_API['subscription']['version']
        else:
            url += '/{subid}' + AZURE_API[resource]['path'] + '?api-version=' + AZURE_API[resource]['version']
            
        return url
    
    
    def refresh_token(self):
        return self._refresh_token