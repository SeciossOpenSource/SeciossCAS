#  This code was developped by SECIOSS (http://www.secioss.co.jp/).
#
#                 (c) 2022 SECIOSS, INC.
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public License
#  as published by the Free Software Foundation.

# -*- coding: utf-8 -*-
import json
import pickle
from re import search, IGNORECASE
from os import path, makedirs, listdir, rmdir
from shutil import rmtree
from ipaddress import IPv4Network, ip_network
from time import sleep
from traceback import format_exc
from urllib import request
from datetime import datetime
from dateutil.parser import parse
from . import TIMEOUT, DATA_DIR


def throw(url, header, method, body, timeout):
    req = request.Request(url, headers=header, method=method)
    if not body:
        body = None

    with request.urlopen(req, body, timeout) as res:
        contents = json.loads(res.read())
        return contents


class SecurityCheck:

    timeout = TIMEOUT
    _time = int(datetime.now().timestamp())

    def __init__(self, **opt):
        if 'time' in opt:
            self._time = opt['time']
        if 'timeout' in opt:
            self.timeout = opt['timeout']

        self.service = None
        self.tenant = None
        self._detail = ''
        self._err = []
        self._warning = []
        self.result = {}
        self.tenant = opt.pop('tenant','')


    def check(self, check_list):
        dir = path.join(DATA_DIR + str(self._time), self.service)
        if not path.isdir(dir):
            self.set_error('time is invalid.')
            return

        if self.tenant:
            dir = path.join(dir, self.tenant)
            if not path.isdir(dir):
                self.set_error('tenant is invalid.')
                return

        self._detail = ''
        self._err = []
        self._warning = []
        self.result = {}

        for cid, c in check_list.items():
            if 'display' not in c or 'name' not in c['display']:
                self.set_error(str(cid) + ' settings(display) is invalid.')
                continue

            data = self.load(c['object'])
            if not data:
                continue

            if 'foreign' in c:
                data = self.set_foreign(c['foreign'], data)
                if data is None:
                    self.set_error(str(cid) + ' settings(foreign) is invalid.')
                    continue

            if 'condition' in c:
                data = self.apply_conditions(c['condition'], data)
                if data is None:
                    self.set_error(str(cid) + ' settings(condition) is invalid.')
                    continue
                    
                if len(data) == 0:
                    continue

            risks = {}
            for d in data:
                if 'value' in c:
                    values = self.get_value(c['value'], d)
                    if values is None:
                        self.set_error(str(cid) + ' settings(value) is invalid.')
                        continue
                        
                    if len(values) == 0:
                        continue
                else:
                    values = None
                    
                risk = self.set_report(c['display'], d, values)
                if risk:
                    if risk['region'] not in risks:
                        risks[risk['region']] = []
                    risks[risk['region']].append(risk)
            
            self.result[cid] = risks

        return self.result


    def apply_conditions(self, conditions: list, data: list):
        m = []
        for d in data:
            match = False
            for c1 in conditions:
                if not self.dtype_check('list', c1):
                    return
                
                for c2 in c1:
                    if not self.dtype_check('dict', c2):
                        return
                    
                    if 'variable' in c2:
                        c2 = self.set_variable(c2, d)
                                        
                    if 'object' in c2:
                        objects = self.get_object(c2['object'], d)
                        if objects is None:
                            continue
                            
                        m1 = self.apply_condition_objects(c2, objects)
                        if m1 is None:
                            return
                        
                        if len(m1) > 0:
                            match = True
                        else:
                            match = False
                    else:
                        match = self.is_condition(c2['check'], d)
                        if match is None:
                            return
                    if not match:
                        break
                    
                if match:
                    break
            
            if match:
                m.append(d)
        
        return m
    
    
    def set_foreign(self, foreign, data):
        if not self.param_check(foreign, ['object', 'param', 'map']) or not self.param_check(foreign['map'], ['foreign', 'self']) or  not self.param_check(foreign['map']['self'], ['param']):
            return
    
        fdata = self.load(foreign['object'])
        if not fdata:
            return data
        
        p = foreign['param']
        n = foreign['displayname'] if 'displayname' in foreign else p
        fp = foreign['map']['foreign']
        
        fv = {f.get(fp):f.get(p) for f in fdata}
        
        s = foreign['map']['self']
        
        m = []
        for d in data:
            if 'object' in s:
                d1 = self.get_object(s['object'], d)
            else:
                d1 = [d]
            
            for d2 in d1:
                if not s['param'] in d2:
                    continue
                
                if d2[s['param']] in fv:
                    d[n] = fv[d2[s['param']]]
                    break
            
            m.append(d)

        return m


    def get_value(self, vcond: dict, obj: dict):
        if not self.param_check(vcond, ['param']):
            return

        p = vcond['param']

        if 'parent' in vcond:
            value = self.get_object(vcond['parent'], obj)
        else:
            value = obj

        if self.value_type(value) != 'list':
            value = [value]

        m = []
        for v in value:
            if p not in v:
                continue

            v1 = v[p]
            if self.value_type(v1) != 'list':
                v1 = [v1]
                               
            if 'condition' in vcond:
                m1 = self.apply_conditions_list(vcond['condition'], v1)
                if m1 is None:
                    return

                if m1:
                    m.extend(m1)

            else:
                m.extend(v1)
                    
        m = set(m)
        m = list(m)

        
        if 'count' in vcond:
            threshold = vcond['count']
        else:
            threshold = 1
        
        if len(m) >= threshold:
            return m
        
        else:
            if 'condition' in vcond or 'count' in vcond:
                return []
            else:
                return [None]
            

    def set_report(self, display, data, value):

        if not self.param_check(data, [display['name']]):
            return

        info = {"name":data[display['name']]}        

        if value:
            info['value'] = value
            
        if 'category' in display:
            for c in display['category']:
                if c in data:
                    info[c] = data[c]
                    
        info['region'] = self.get_region(data)
                    
        return info


    def apply_condition_objects(self, condition: dict, objects: list):
        if not self.param_check(condition, ['check']) or not self.dtype_check('list', condition['check']):
            return
        
        m = []
        for obj in objects:
            match = True
            for c in condition['check']:
                if not self.param_check(c, ['param', 'type']):
                    return

                match = self.is_condition(c, obj)
                if match is None:
                    return
                
                if not match:
                    break
                
            if match:
                m.append(obj)
    
        if len(m) > 0 and 'child' in condition:
            if 'object' in condition['child']:
                m1 = [self.get_object(condition['child']['object'], tmp) for tmp in m]
                m2 = []
                for tmp in m1:
                    if tmp:
                        m2.extend(tmp)
                
                return self.apply_condition_objects(condition['child'], m2)
            else:
                return [m1 for m1 in m if self.is_condition(condition['child']['check'], m1)]
            
        return m
    
    
    def apply_conditions_list(self, conditions: list, values: list):
        m = []
        for v in values:
            for c1 in conditions:
                match = True
                for c2 in c1:
                    if not self.param_check(c2, ['check']):
                        return

                    match = self.is_condition(c2['check'], v)
                    if match is None:
                        return
                    
                    if not match:
                        break
                
                if match:
                    m.append(v)
                
        return m    


    def is_condition(self, condition: dict, value):
        if not self.param_check(condition, ['type']):
            return

        ctype = condition['type']
        neg = condition['negative'] if 'negative' in condition else False
        
        if ctype == 'exists':
            if not self.param_check(condition, ['param']):
                return

            if value and condition['param'] in value and value[condition['param']]:
                return True != neg
            else:
                return False != neg

        else:
            if not self.param_check(condition, ['value']):
                return
            
            test = condition['value']

            if 'param' in condition:
                if 'parent' in condition:
                    v = self.get_object(condition['parent'], value)
                    if v is None:
                        return False != neg
                    
                else:
                    v = value
                    
                if not v or condition['param'] not in v:
                    return False != neg
                
                v = v[condition['param']]
            else:
                v = value

            if 'list' in condition:
                ltype = condition['list']
                r = self.list_match(ltype, ctype, test, v)

            else:
                r = self.is_match(ctype, test, v)

        if r is None:
            return

        return r != neg


    def list_match(self, ltype: str, ctype: str, test, value: list):
        m = []
        for v in value:
            match = self.is_match(ctype, test, v)
            if match is None:
                return
            
            if match:
                m.append(v)
        
        if ltype == 'one':
            return len(m) > 0
        elif ltype == 'all':
            return len(m) == len(value)
        elif ltype.isdecimal():
            return len(m) >= int(ltype)
        else:
            self.set_detail(ltype + ' is invalid list check type.')
            return
            

    def is_match(self, ctype: str, test, value):
        if ctype == 'no_check':
            return True
        
        elif ctype == 'value':
            if not test:
                r = not value
            else:
                r = test == value
                
        elif ctype == 'regex':
            r = search(test, value, IGNORECASE) is not None
            
        elif ctype == 'datetime':
            dt = parse(value)
            r = self._time - dt.timestamp() > test
            
        elif ctype == 'cidr':
            try:
                r = IPv4Network(value).prefixlen == test
            except:
                r = False
                
        elif ctype == 'in_network':
            try:
                r = ip_network(test).subnet_of(ip_network(value))
            except:
                r = False
                
        else:
            self.set_detail(ctype + ' is invalid check type.')
            return

        return r


    def get_object(self, params: list, obj: dict):
    
        d0 = obj

        for p in params:
            if not self.dtype_check('dict', d0):
                return
            
            if p in d0:
                d0 = d0[p]
            
        return d0
    

    def set_variable(self, condition: dict, obj: dict):
        if not self.dtype_check('list', condition['variable']):
            return
        
        vs = {}
        for c in condition['variable']:
            if not self.param_check(c, ['type', 'value']):
                return
            
            if c['type'] == 'self':
                if c['value'] in obj:
                    vs[c['value']] = obj[c['value']]
                    
        return self.set_vars_rec(condition, vs)


    def set_vars_rec(self, c: dict, vars: dict):
        c0 = c
        for k, v in c0.items():
            if k == 'child':
                c0[k] = self.set_vars_rec(v, vars)

            if k != 'check':
                continue
            
            if self.value_type(v) == 'list':
                for v1 in v:
                    tmp = []
                    if 'variable' in v1:
                        v1['value'] = vars[v1['variable']]
                        
                    tmp.append(v1)
                    
            else:
                if 'variable' in v:                   
                    v['value'] = vars[v['variable']]
                
            c0[k] = v                                

        return c0
    

    def get_region(self, info: dict):
        if not self.region_param or self.value_type(self.region_param) != 'list':
            return
    
        params = self.region_param
        i = info
        for ps in params:
            match = True
            for p in ps:
                if self.value_type(i) != 'dict':
                    match = False
                    break
                
                if p not in i:
                    match = False
                    break
                
                i = i[p]
                
            if match:
                break

        if match:
            return i
        else:
            return


    def save(self, file: str, data):
        try:
            d = path.join(DATA_DIR + str(self._time), self.service)
            if self.tenant:
                d = path.join(d, self.tenant)
            makedirs(d, exist_ok=True)
            p = path.join(d, file)
            tmp = data
            if path.isfile(p):
                with open(p, 'rb') as f:
                    data0 = pickle.load(f)
                    tmp.extend(data0)
            with open(p, 'wb') as f:
                pickle.dump(tmp, f)
                return True
        except:
            self.set_error(f'[save {file}] ' + format_exc())
            return False


    def load(self, file: str):
        try:
            d = path.join(DATA_DIR + str(self._time), self.service)
            if self.tenant:
                d = path.join(d, self.tenant)
            p = path.join(d, file)
            if path.isfile(p):
                with open(p, 'rb') as f:
                    return pickle.load(f)
        except:
            self.set_error(f'[load {file}] ' + format_exc())
            return None


    def dir_empty(self, dir: str):
        l = listdir(dir)
        l = [f for f in l if not f.startswith(".")]
        if not l:
            return True
        else:
            return False


    def clear(self) -> None:
        b = path.join(DATA_DIR + str(self._time))
        d = path.join(b, self.service)
        if self.tenant:
            if path.isdir(path.join(d, self.tenant)):
                rmtree(path.join(d, self.tenant))
                sleep(1)
            if path.isdir(d) and self.dir_empty(d):
                rmdir(d)
                sleep(1)
        else:
            if path.isdir(d):
                rmtree(d)
                sleep(1)

        if path.isdir(b) and self.dir_empty(b):
            rmdir(b)


    def param_check(self, data, params: list):
        for param in params:
            if param not in data:
                self.set_detail(param + ' not in data ' + json.dumps(data))
                return False
        
        return True

    
    def dtype_check(self, dtype: str, value):
        if self.value_type(value) != dtype:
            self.set_detail('data is not ' + dtype + ' ' + json.dumps(value))
            return False
        
        return True


    def value_type(self, value):
        if isinstance(value, list):
            t = 'list'
        elif isinstance(value, dict):
            t = 'dict'
        else:
            t = None

        return t
    

    def set_detail(self, msg: str):
        self._detail = msg
        return
            

    def set_error(self, msg: str):
        if self._detail:
            msg += ': ' + self._detail
        self._detail = ''
        
        self._err.append(msg)
        return
            

    def fetch(self):
        return


    def get_list(self, source, **opt):
        return


    def refresh_token(self):
        return


    def error(self):
        return self._err


    def warning(self):
        return self._warning
    
    
    def time(self):
        return self._time
