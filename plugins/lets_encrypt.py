#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: lets_encrypt.py
# Author:      Rene Fa
# Date:        23.07.2018
# Version:     0.7
#
# Copyright:   Copyright (C) 2018  Rene Fa
#
#              This program is free software: you can redistribute it and/or modify
#              it under the terms of the GNU Affero General Public License as published by
#              the Free Software Foundation, either version 3 of the License, or any later version.
#
#              This program is distributed in the hope that it will be useful,
#              but WITHOUT ANY WARRANTY; without even the implied warranty of
#              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#              GNU Affero General Public License for more details.
#
#              You should have received a copy of the GNU Affero General Public License
#              along with this program.  If not, see https://www.gnu.org/licenses/agpl-3.0.de.html.
#
# Note:        Based on the work of acme_dns_tiny (MIT Licence) from Adrien Dorsaz
#              https://projects.adorsaz.ch/adrien/acme-dns-tiny/
#


import sys
sys.path.append("..")
from api_plugin import * # Essential Plugina
import os
import requests
import json
import copy
import subprocess
import hashlib
import binascii
import base64
import shutil
import glob
import re
import dns.resolver
import time
import datetime

plugin = api_plugin()
plugin.name = "lets_encrypt"
plugin.version = "0.1"
plugin.essential = False
plugin.info['f_name'] = {
    'EN': 'Let\'s Encrypt'
}

plugin.info['f_description'] = {
    'EN': 'This plugin is to request certificates from Let\'s Encrypt.',
    'DE': 'Dieses Plugin ermöglicht Let\'s Encrypt Zertifikate anzufordern.'
}

plugin.depends = [
    {
        'name': 'auth',
        'required': True
    },
    {
        'name': 'time',
        'required': True
    },
    {
        'name': 'job',
        'required': True
    }
]

plugin.config_defaults = {
    plugin.name: {
        'acme_directory': "https://acme-staging-v02.api.letsencrypt.org/directory",
        'base_key_directory': "/etc/pythapi/lets_encrypt",
        'termsOfUse_accepted': False,
        'rsa_keysize': 4096,
        'contact_data': "",
        'cert_country_name': "",
        'cert_state_name': "",
        'cert_locality_name' : "",
        'cert_organisation_name': "",
        'cert_organisationunit_name': "",
        'autorefresh_minute': "0",
        'autorefresh_hour': "3",
        'autorefresh_dayofweek': "*",
        'autorefresh_dayofmonth': "*",
        'autorefresh_month': "*",
        'autorefresh_year': "*",
        'autorefresh_mindaysreaming': 1,
        'dns_verification_servers': [],
        'wildcard_replace_character': "*"
    }
}
plugin.translation_dict = {
    'LE_CERT_EXIST': {
        'EN': "Certificate already exists.",
        'DE': "Zertifikat existiert bereits."
    },
    'LE_CERT_NOT_FOUND': {
        'EN': "Certificate not found.",
        'DE': "Zertifikat nicht gefunden."
    },
    'LE_RENEWAL_RUNNING': {
        'EN': "Renewal is already running.",
        'DE': "Die Anforderung des neuen Zertifikats ist bereits in Bearbeitung."
    },
    'LE_DOMAIN_NOT_FOUND': {
        'EN': "No certificate with this domain exists.",
        'DE': "Es existiert kein Zertifikat mit dieser Domain."
    }
}

acme_config = None
jws_nonce = None
jws_header = None
adtheaders = None
joseheaders = None
dns_resolver = None

cert_dict = {}
preverification_handler_list = []
postverification_handler_list = []
write_through_cache_enabled = False

def _b64(b):
    return base64.urlsafe_b64encode(b).decode("utf8").rstrip("=")

def i_domains_to_punycode(domain_list):
    return_list = []
    for i, domain in enumerate(domain_list):
        domain_r = domain.strip('.').split('.')
        
        for j, level in enumerate(domain_r):
            plain_punycode = level.encode('punycode').decode('utf8')
            
            if plain_punycode[-1] != '-':
                converted_level = 'xn--' +plain_punycode
            else:
                converted_level = plain_punycode.rstrip('-')

            domain_r[j] = converted_level

        return_list.append('.'.join(domain_r))

    return return_list

def i_get_cert_id(domains):
    domain_str = json.dumps(sorted(domains), sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha1(domain_str.encode('utf8')).digest()
    b64_str = base64.urlsafe_b64encode(digest).decode('utf8')
    return b64_str.rstrip('=')

def ir_delete_directory_tree(path):
    path_list = glob.glob(os.path.join(path, '*'))
    for i_path in path_list:
        if os.path.islink(i_path) or os.path.isfile(i_path):
            os.remove(i_path)
        else:
            ir_delete_directory_tree(i_path)
    os.rmdir(path)

def _send_signed_request(url, payload):
    global jws_nonce
    global acme_config
    global jws_header
    
    config = api_config()[plugin.name]
    keyfile_path = os.path.join(config['base_key_directory'], 'account/keyfile.pem')
    payload64 = _b64(json.dumps(payload).encode("utf8"))
    protected = copy.deepcopy(jws_header)
    protected["nonce"] = jws_nonce or requests.get(acme_config["newNonce"]).headers['Replay-Nonce']
    protected["url"] = url
    if url == acme_config["newAccount"]:
        del protected["kid"]
    else:
        del protected["jwk"]
    protected64 = _b64(json.dumps(protected).encode("utf8"))
    signature = i_exec_openssl(["dgst", "-sha256", "-sign", keyfile_path], "{0}.{1}".format(protected64, payload64).encode("utf8"))
    jose = {
        "protected": protected64, "payload": payload64,"signature": _b64(signature)
    }
    try:
        resp = requests.post(url, json=jose, headers=joseheaders)
    except requests.exceptions.RequestException as error:
        resp = error.response
    finally:
        jws_nonce = resp.headers['Replay-Nonce']
        if resp.text != '':
            return resp.status_code, resp.json(), resp.headers
        else:
            return resp.status_code, json.dumps({}), resp.headers

def i_init_lets_encrypt():
    global adtheaders
    global joseheaders
    global acme_config

    config = api_config()[plugin.name]

    adtheaders =  {'User-Agent': "pythapi-lets_encrypt/{}".format(plugin.version),
        'Accept-Language': 'en'
    }
    joseheaders = copy.deepcopy(adtheaders)
    joseheaders['Content-Type']='application/jose+json'

    directory = requests.get(config['acme_directory'], headers=adtheaders)

    acme_config = directory.json()

def i_setup_signatures():
    global jws_header
    global jws_nonce
    global thumbprint
        
    config = api_config()[plugin.name]
    keyfile_path = os.path.join(config['base_key_directory'], 'account/keyfile.pem')

    sysout = i_exec_openssl([ 'rsa', '-in', keyfile_path, '-noout', '-text'])
    
    if sysout == None:
        api_log().error('Can\'t read generated keyfile.')
        return 0
    
    accountkey = sysout
    pub_hex, pub_exp = re.search(
        r"modulus:\r?\n\s+00:([a-f0-9\:\s]+?)\r?\npublicExponent: ([0-9]+)",
        accountkey.decode("utf8"), re.MULTILINE | re.DOTALL).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    jws_header = {
        "alg": "RS256",
        "jwk": {
            "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
            "kty": "RSA",
            "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
        },
        "kid": None,
    }
    accountkey_json = json.dumps(jws_header["jwk"], sort_keys=True, separators=(",", ":"))
    thumbprint = _b64(hashlib.sha256(accountkey_json.encode("utf8")).digest())
    jws_nonce = None

def i_exec_openssl(parameter, communicate = None):
    openssl = subprocess.Popen(['openssl'] +parameter, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sysout, syserr = openssl.communicate(communicate)
    
    if openssl.returncode != 0:
        api_log().error("OpenSSL Error: {0}".format(syserr))
        return None
    
    return sysout

def i_domain_permission_validator(ruleset, rule_section, target_domain):
    if not rule_section in ruleset:
        return 0    

    domain_list = ruleset[rule_section]

    if '*' in domain_list:
        return 1

    domain_r = target_domain.split('.')

    for i_domain in domain_list:
        i_domain_r = i_domain.split('.')

        if target_domain == i_domain:
            return 1

        elif i_domain_r[0] == '*' and '.'.join(domain_r[1:]) == '.'.join(i_domain_r[1:]):
            return 1

    return 0

def i_le_permission_reduce_handler(ruleset):

    if not 'lets_encrypt_allowed_domains' in ruleset:
        return ruleset

    ruleset['lets_encrypt_allowed_domains'] = list(set(ruleset['lets_encrypt_allowed_domains']))

    if '*' in ruleset['lets_encrypt_allowed_domains']:
        ruleset['lets_encrypt_allowed_domains'] = ['*']

    for rule in list(ruleset['lets_encrypt_allowed_domains']):
        if rule[0] != '*':
            continue

        prefix = rule[1:]
        for sub_rule in list(ruleset['lets_encrypt_allowed_domains']):
            if re.search(re.escape(prefix) +r'$', sub_rule) and len(rule) != len(sub_rule):
                ruleset['lets_encrypt_allowed_domains'].remove(sub_rule)

    return ruleset

def i_le_subset_intersection_handler(ruleset, subset):
    section_name = 'lets_encrypt_allowed_domains'
    section = ruleset[section_name]
    return_subset = {}

    if '*' in ruleset[section_name] or not section_name in subset:
        return copy.deepcopy(subset)

    for rule in list(subset[section_name]):
        if rule in ruleset[section_name] or '*' +rule[rule.find('.'):] in ruleset[section_name]:
            if not section_name in return_subset:
                return_subset[section_name] = []

            return_subset[section_name].append(rule)

    return return_subset

@api_external_function(plugin)
def e_list_certificates():
    if write_through_cache_enabled:
        return list(cert_dict.keys())

    else:
        config = api_config()[plugin.name]
        
        certdir_path = os.path.join(config['base_key_directory'], 'certs')
        certpath_list = glob.glob(certdir_path +'/*')

        certname_list = []
        for cert_path in certpath_list:
            cert_name = re.search(r'^.*\/([^\/]+)$', cert_path).group(1)
            certname_list.append(cert_name)

        return certname_list

def i_get_direct_certificate(cert_id):
    config = api_config()[plugin.name]

    cert_path = os.path.join(config['base_key_directory'], 'certs', cert_id)

    domain_path = os.path.join(config['base_key_directory'], 'certs', cert_id)
    if not os.path.isdir(domain_path):
        raise WebRequestException(400, 'error', 'LE_CERT_NOT_FOUND')

    return_json = {}
    
    with open(os.path.join(cert_path, 'domains.json'), 'r') as domain_file:
        return_json['domains'] = json.loads(domain_file.read())

    tokenfile_path = os.path.join(cert_path, 'token.json')
    if os.path.isfile(tokenfile_path):
        with open(tokenfile_path, 'r') as token_file:
            return_json['tokens'] = json.loads(token_file.read())

    certfile_path = os.path.join(cert_path, 'certfile.pem')
    if os.path.isfile(certfile_path):
        cert = i_exec_openssl(['x509', '-in', certfile_path, '-noout', '-text']).decode('utf8')
    
        datestr = re.search(r'Not After \: (.*) GMT\n', cert).group(1)
        date = datetime.datetime.strptime(datestr, '%b %d %H:%M:%S %Y')
        delta = date - datetime.datetime.now()
    
        return_json['expires'] = date.strftime('%H:%M:%S %d.%m.%Y')

        if delta.days < 0:
            return_json['status'] = 'expired'
        
        else:
            return_json['status'] = 'valid'

    else:
        return_json['status'] = 'not found'

    return return_json


@api_external_function(plugin)
def e_get_certificate(cert_id):

    if write_through_cache_enabled:
        if not cert_id in cert_dict:
            raise WebRequestException(400, 'error', 'LE_CERT_NOT_FOUND')

        return_json = cert_dict[cert_id]

        if 'expires' in return_json:
            date = datetime.datetime.strptime(return_json['expires'], '%H:%M:%S %d.%m.%Y')
            delta = date - datetime.datetime.now()

            if delta.days < 0:
                return_json['status'] = 'expired'

    else:
        return_json = i_get_direct_certificate(cert_id)

    job = api_plugins()['job']
    
    try:
        running_job = job.e_get_raw_job('le_request:{}'.format(cert_id))
        running_job_status = running_job.status
    except KeyError:
        running_job_status = 'none'

    return return_json

@api_external_function(plugin)
def e_add_preverfication_handler(f):
    preverification_handler_list.append(f)

@api_external_function(plugin)
def e_add_postverfication_handler(f):
    postverification_handler_list.append(f)

def it_complete_challenges(domain_list, order, order_location, **kwargs):
    global jws_nonce
    config = api_config()[plugin.name]
    cert_id = i_get_cert_id(domain_list)
    cert_path = os.path.join(config['base_key_directory'], 'certs', cert_id)

    token_dict = {}
    for authz in order["authorizations"]:
        
        # get new challenge
        resp = requests.get(authz, headers=adtheaders)
        authorization = resp.json()
        if resp.status_code != 200:
            raise ValueError("Error fetching challenges: {0} {1}".format(resp.status_code, authorization))

        domain = authorization["identifier"]["value"]
        
        challenge = [c for c in authorization["challenges"] if c["type"] == "dns-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge["token"])
        keyauthorization = "{0}.{1}".format(token, thumbprint)
        keydigest64 = _b64(hashlib.sha256(keyauthorization.encode("utf8")).digest())
        record_name = '_acme-challenge.{}'.format(domain)

        if not record_name in token_dict:
            token_dict[record_name] = []
        token_dict[record_name].append(keydigest64)

        if authorization['status'] == 'valid':
            continue

        api_log().info("Register this: {} at _acme-challenge.{}".format(keydigest64, domain))
    
    cert_dict[cert_id]['tokens'] = token_dict
    with open(os.path.join(cert_path, 'token.json'), 'w') as tokenfile:
        tokenfile.write(json.dumps(token_dict))

    if order['status'] == 'pending':

        for v_handler in preverification_handler_list:
            cert_dict[cert_id]['status'] = 'running_pre_verify_handler:' +v_handler.__name__
            v_handler(domain_list, token_dict)

        # Pre-verification
        # Check via DNS resolver before Let's Encrypt verification
        cert_dict[cert_id]['status'] = 'waiting_for_local_verification'
        for name, keydigest64 in token_dict.items():
            
            api_log().debug("Pre-verification: Waiting for correct key of {}...".format(name))
            while True:
                preVerified = 0
                for dns_server in config['dns_verification_servers']:
                    try:
                        dns_resolver.nameservers = [dns_server]
                        dns_results = dns_resolver.query(name, 'TXT')
        
                    except dns.resolver.NoAnswer:
                        dns_results = []
        
                    except dns.resolver.NXDOMAIN:
                        dns_results = []
                    
                    for dns_result in dns_results:
                        if str(dns_result).strip('"') in keydigest64:
                            preVerified += 1
                            break
    
                if preVerified >= len(config['dns_verification_servers']):
                    break
    
                kwargs['_t_event'].wait(2)
                if kwargs['_t_event'].is_set():
                    cert_dict[cert_id]['status'] = 'job_terminated'
                    return

        cert_dict[cert_id]['status'] = 'waiting_for_acme_verification'
        jws_nonce = None
        for authz in order["authorizations"]:
    
            # get new challenge
            resp = requests.get(authz, headers=adtheaders)
            authorization = resp.json()
            if resp.status_code != 200:
                cert_dict[cert_id]['status'] = 'verification_failed'
                raise ValueError("Error fetching challenges: {0} {1}".format(resp.status_code, authorization))
    
            domain = authorization["identifier"]["value"]
            
            challenge = [c for c in authorization["challenges"] if c["type"] == "dns-01"][0]
            token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge["token"])
            keyauthorization = "{0}.{1}".format(token, thumbprint)
    
            # Start Let's Encrypt verification
            api_log().debug("Asking ACME server to validate challenge.")
            code, result, headers = _send_signed_request(challenge["url"], {"keyAuthorization": keyauthorization})
            if code != 200:
                cert_dict[cert_id]['status'] = 'verification_failed'
                raise ValueError("Error triggering challenge: {0} {1}".format(code, result))
    
            while True:
                try:
                    resp = requests.get(challenge["url"], headers=adtheaders)
                    challenge_status = resp.json()
                except requests.exceptions.RequestException as error:
                    cert_dict[cert_id]['status'] = 'verification_failed'
                    raise ValueError("Error during challenge validation: {0} {1}".format(
                        error.response.status_code, error.response.text()))
                if challenge_status["status"] == "pending":
                    kwargs['_t_event'].wait(2)
                    if kwargs['_t_event'].is_set():
                        cert_dict[cert_id]['status'] = 'job_terminated'
                        return
    
                elif challenge_status["status"] == "valid":
                    api_log().info("ACME has verified challenge for domain: {0}".format(domain))
                    break
                else:
                    cert_dict[cert_id]['status'] = 'verification_failed'
                    raise ValueError("Challenge for domain {0} did not pass: {1}".format(
                        domain, challenge_status))

        cert_dict[cert_id]['status'] = 'running_post_verification_handlers'
        for v_handler in postverification_handler_list:
            cert_dict[cert_id]['status'] = 'running_post_verify_handler:' +v_handler.__name__
            v_handler(domain_list, token_dict)

    else:
        api_log().debug("Challenges are already satisfied. Skipping verification.")
    
    cert_dict[cert_id]['status'] = 'finalizing_order'
    csrfile_path = os.path.join(cert_path, 'certfile.csr')

    csr_der = _b64(i_exec_openssl(['req', '-in', csrfile_path, '-outform', 'DER']))
    code, result, headers = _send_signed_request(order["finalize"], {"csr": csr_der})
    if code != 200:
        cert_dict[cert_id]['status'] = 'sending_csr_failed'
        raise ValueError("Error while sending the CSR: {0} {1}".format(code, result))

    while True:
        try:
            resp = requests.get(order_location, headers=adtheaders)
            resp.raise_for_status()
            finalize = resp.json()
        except requests.exceptions.RequestException as error:
            cert_dict[cert_id]['status'] = 'finalizing_error'
            raise ValueError("Error finalizing order: {0} {1}".format(
                error.response.status_code, error.response.text()))

        if finalize["status"] == "processing":
            if resp.headers["Retry-After"]:
                time.sleep(resp.headers["Retry-After"])
            else:
                time.sleep(2)
        elif finalize["status"] == "valid":
            break

        else:
            cert_dict[cert_id]['status'] = 'finalizing_error'
            raise ValueError("Finalizing order {0} got errors: {1}".format(
                domain, finalize))
    
    resp = requests.get(finalize["certificate"], headers=adtheaders)
    if resp.status_code != 200:
        cert_dict[cert_id]['status'] = 'finalizing_error'
        raise ValueError("Finalizing order {0} got errors: {1}".format(
            resp.status_code, resp.json()))

    certfile_path = os.path.join(cert_path, 'certfile.pem')

    with open(certfile_path, 'w') as certfile:
        certfile.write(resp.text)

    i_rebuild_domain_links(domain_list)
    cert_dict[cert_id] = i_get_direct_certificate(cert_id)

    api_log().info("Certificate signed and chain received: {0}".format(finalize["certificate"]))

@api_external_function(plugin)
def e_renew_certificate(cert_id):
    job = api_plugins()['job']
    
    try:
        running_job = job.e_get_raw_job('le_request:{}'.format(cert_id))
        running_job_status = running_job.status
    except KeyError:
        running_job_status = 'none'

    if not running_job_status in ['none', 'done', 'terminated']:
        raise WebRequestException(400, 'error', 'LE_RENEWAL_RUNNING')

    cert_dict[cert_id]['status'] = 'initializing_verification'

    config = api_config()[plugin.name]
    cert_path = os.path.join(config['base_key_directory'], 'certs', cert_id)
    
    with open(os.path.join(cert_path, 'domains.json'), 'r') as domains_file:
        domain_list = json.loads(domains_file.read())
    
    # new order
    new_order = {
        "identifiers": [
            {"type": "dns", "value": domain} for domain in domain_list
        ]
    }

    code, result, headers = _send_signed_request(acme_config["newOrder"], new_order)
    order = result
    if code == 201:
        order_location = headers['Location']

        if not order["status"] in ['pending', 'ready']:
            raise ValueError("Order status is not pending, we can't use it: {0}".format(order))
    else:
        raise ValueError("Error getting new Order: {0} {1}".format(code, result))

    job.e_create_job('le_request:{}'.format(cert_id), it_complete_challenges, [domain_list, order, order_location])

@api_external_function(plugin)
def et_check_certificates():
    api_log().info("Checking certificates...")
    config = api_config()[plugin.name]
    
    certdir_path = os.path.join(config['base_key_directory'], 'certs')

    cert_list = glob.glob(certdir_path +'/*')
    for cert_path in cert_list:
        cert_id = re.search(r'^.*\/([^\/]+)$', cert_path).group(1)
        certfile_path = os.path.join(cert_path, 'certfile.pem')

        api_log().debug("Checking {}...".format(cert_id))
        
        if not os.path.isfile(os.path.join(certfile_path)):
            api_log().info("Renewing {}...".format(cert_id))

            try:
                e_renew_certificate(cert_id)
            except WebRequestException:
                api_log().warning("Renewing already running for {}.".format(cert_id))
            continue
        
        else:
            cert = i_exec_openssl(['x509', '-in', certfile_path, '-noout', '-text']).decode('utf8')
    
            datestr = re.search(r'Not After \: (.*) GMT\n', cert).group(1)
            date = datetime.datetime.strptime(datestr, '%b %d %H:%M:%S %Y')
            delta = date - datetime.datetime.now()

            if delta.days < config['autorefresh_mindaysreaming']:

                if delta.days < 0:
                    api_log().warning("Expired Certificate {}...".format(cert_id))
                    cert_dict[cert_id]['status'] = 'expired'

                api_log().info("Renewing {}...".format(cert_id))
                try:
                    e_renew_certificate(cert_id)
                except WebRequestException:
                    api_log().warning("Renewing already running for {}.".format(cert_id))
        
    api_log().debug("Done checking certificates.")
    pass

def it_add_certificate(domain_list, **kwargs):
    config = api_config()[plugin.name]
    account_path = os.path.join(config['base_key_directory'], 'account/keyfile.pem')
    baseconf_path = os.path.join(config['base_key_directory'], 'openssl.cnf')
    tmpconf_path = os.path.join(config['base_key_directory'], 'tmp/openssl.cnf')
    
    cert_id = i_get_cert_id(domain_list)
    new_domain_path = os.path.join(config['base_key_directory'], 'certs', cert_id)
    keyfile_path = os.path.join(new_domain_path, 'keyfile.pem')

    os.makedirs(new_domain_path)

    i_entry = {}
    i_entry['domains'] = domain_list
    i_entry['status'] = 'generating_keyfile'
    cert_dict[cert_id] = i_entry


    api_log().debug("Generating keyfile....")
    sysout = i_exec_openssl(['genrsa', '-out', keyfile_path, str(config['rsa_keysize']), '-nodes'])
    
    if sysout == None:
        api_log().error("Can\'t generate keyfile.")
        return 0
    
    os.chmod(keyfile_path, 0o600)

    with open(os.path.join(new_domain_path, 'domains.json'), 'w') as domainsfile:
        domainsfile.write(json.dumps(domain_list))

    subject_str = "/CN={cn}"
    
    if config['cert_country_name'] != "":
        subject_str += "/C={c}"

    if config['cert_state_name'] != "":
        subject_str += "/ST={st}"

    if config['cert_locality_name'] != "":
        subject_str += "/L={l}"

    if config['cert_organisation_name'] != "":
        subject_str += "/O={o}"

    if config['cert_organisationunit_name'] != "":
        subject_str += "/OU={ou}"
    
    subject_str = subject_str.format(
                      cn = domain_list[0],
                      c  = config['cert_country_name'],
                      st = config['cert_state_name'],
                      l  = config['cert_locality_name'],
                      o  = config['cert_organisation_name'],
                      ou = config['cert_organisationunit_name']
    )
    
    shutil.copyfile(baseconf_path, tmpconf_path)
    with open(tmpconf_path, 'a') as tmpconf:
        tmpconf.write("[alt_names]\n")
        
        i = 0
        for domain_name in domain_list:
            i += 1
            tmpconf.write("DNS.{} = {}\n".format(i, domain_name))
    
    csrfile_path = os.path.join(new_domain_path, 'certfile.csr')
    sysout = i_exec_openssl(['req', '-config', tmpconf_path, '-new', '-key', keyfile_path, '-subj' , subject_str, '-out', csrfile_path])
    
    api_log().debug("Requesting new certificate...")
    e_renew_certificate(cert_id)

@api_external_function(plugin)
def e_add_certificate(domain_list):
    config = api_config()[plugin.name]

    cert_id = i_get_cert_id(domain_list)
    new_domain_path = os.path.join(config['base_key_directory'], 'certs', cert_id)

    if write_through_cache_enabled:
        if cert_id in cert_dict:
            raise WebRequestException(400, 'error', 'LE_CERT_EXIST')

    else:
        if os.path.isdir(new_domain_path):
            raise WebRequestException(400, 'error', 'LE_CERT_EXIST')

    job = api_plugins()['job']
    job.e_create_job('add_crt:{}'.format(cert_id), it_add_certificate, [domain_list])

    return cert_id

def i_revoke_certificate(cert_id):
    config = api_config()[plugin.name]
    certfile_path = os.path.join(config['base_key_directory'], 'certs', cert_id, 'certfile.pem')

    if not os.path.isfile(certfile_path):
        return

    cert64 = _b64(i_exec_openssl(['x509', '-in', certfile_path, '-outform', 'DER']))
    code, result, headers = _send_signed_request(acme_config["revokeCert"], {'certificate': cert64})
    if code != 200:
        raise ValueError("Error while revoking the certificate: {0} {1}".format(code, result))

    api_log().debug("Certificate revoked.")

@api_external_function(plugin)
def e_delete_certificate(cert_id):
    config = api_config()[plugin.name]

    domain_path = os.path.join(config['base_key_directory'], 'certs', cert_id)
    if not os.path.isdir(domain_path):
        raise WebRequestException(400, 'error', 'LE_CERT_NOT_FOUND')

    job = api_plugins()['job']
    
    try:
        running_job = job.e_get_raw_job('le_request:{}'.format(cert_id))
        running_job_status = running_job.status
    except KeyError:
        running_job_status = 'none'

    # If there is a renewal of this cert running, terminate it
    if running_job_status == 'running':
        running_job.terminate()

    if write_through_cache_enabled:
        domain_list = cert_dict[cert_id]['domains']
        del cert_dict[cert_id]

    else:
        domain_list = i_get_direct_certificate(cert_id)

    i_rebuild_domain_links(domain_list)
    i_revoke_certificate(cert_id)
    ir_delete_directory_tree(domain_path)

def i_search_best_cert(domain_name):
    score_dict = {}
    
    domain_r = domain_name.split('.')
    
    for cert_id, cert_data in cert_dict.items():
        cert_score = 0
        hit = False
        for i_domain_name in cert_data['domains']:
            i_domain_r = i_domain_name.split('.')

            if domain_r == i_domain_r:
                hit = True

            elif i_domain_r[0] == '*' and '.'.join(domain_r[1:]) == '.'.join(i_domain_r[1:]):
                hit = True
                cert_score += 99

            else:
                if i_domain_r[0] == '*':
                    cert_score += 100
                else:
                    cert_score += 1

        if hit:
            score_dict[cert_score] = cert_id
    
    if not score_dict:
        raise WebRequestException(400, 'error', 'LE_CERT_NOT_FOUND', {
            'domain': domain_name
        })

    return score_dict[min(score_dict.keys())]


def i_rebuild_domain_links_p2(domain_list, certId_list):
    config = api_config()[plugin.name]
    domaindir_path = os.path.join(config['base_key_directory'], 'domains')
    certdir_path = os.path.join(config['base_key_directory'], 'certs')
    wc_replace_char = config['wildcard_replace_character']

    for domain, cert_id in zip(domain_list, certId_list):
        domainlink_path = os.path.join(domaindir_path, domain.replace('*', wc_replace_char))

        target_path = os.path.join('../certs', cert_id)

        if os.path.islink(domainlink_path):
            if os.readlink(domainlink_path) != target_path:
                os.remove(domainlink_path)
            else:
                continue
        
        if cert_id != 'null':
            os.symlink(target_path, domainlink_path)

def i_rebuild_domain_links(domain_list):
    certId_list = []
    for domain in domain_list:
        try:
            certId_list.append(i_search_best_cert(domain))
        except WebRequestException:
            certId_list.append('null')

    i_rebuild_domain_links_p2(domain_list, certId_list)

@api_event(plugin, 'check')
def check():
    config = api_config()[plugin.name]
    keyfile_path = os.path.join(config['base_key_directory'], 'account/keyfile.pem')
    certs_path = os.path.join(config['base_key_directory'], 'certs')
    tmp_path = os.path.join(config['base_key_directory'], 'tmp')

    if not os.path.isdir(certs_path):
        return 0

    if not os.path.isfile(keyfile_path):
        return 0

    if not os.path.isdir(tmp_path):
        return 0

    return 1

@api_event(plugin, 'install')
def install():
    config = api_config()[plugin.name]

    auth = api_plugins()['auth']

    auth.e_create_role( plugin.name +'_admin', {
        plugin.name +'_allowed_domains':  [
            '*'
        ]
    })

    ruleset = auth.e_get_role('admin')['ruleset']

    try:
        if not plugin.name +'_admin' in ruleset['inherit']:
            ruleset['inherit'].append(plugin.name +'_admin')

        auth.e_edit_role('admin', ruleset)
        log.debug("Permissions applied.")
    except WebRequestException as e:
        api_log().error('Editing the admin role failed!')
        return 0

    # Generating directory structure
    try:
        os.makedirs(config['base_key_directory'])
        os.makedirs(os.path.join(config['base_key_directory'], 'account'))
        os.makedirs(os.path.join(config['base_key_directory'], 'certs'))
        os.makedirs(os.path.join(config['base_key_directory'], 'tmp'))
        os.makedirs(os.path.join(config['base_key_directory'], 'domains'))

    except:
        api_log().error("Path already exists.")
        return 0
    
    shutil.copyfile('./lets_encrypt/openssl.cnf', os.path.join(config['base_key_directory'], 'openssl.cnf'))
    
    i_init_lets_encrypt()

    directory = requests.get(config['acme_directory'])
    acme_config = directory.json()
    terms_service = acme_config.get('meta', {}).get('termsOfService', '')
    
    if str.lower(config['termsofuse_accepted']):
        api_log().info("Terms of use accepted in configuration file.")

    else:
        print("Please read the terms of use at: {}".format(terms_service))
        choice = input("Did you read and agree with the terms of service? [Y/n]: ")
        
        if str.lower(choice) == 'n':
            api_log().error("You have to accept the terms of use to continue.")
            return 0

    api_log().debug("Generating keyfile....")
    keyfile_path = os.path.join(config['base_key_directory'], 'account/keyfile.pem')
    sysout = i_exec_openssl(['genrsa', '-out', keyfile_path, str(config['rsa_keysize']), '-nodes'])
    
    if sysout == None:
        api_log().error("Can\'t generate keyfile.")
        return 0
    
    os.chmod(keyfile_path, 0o600)
    
    i_setup_signatures()

    api_log().debug("Register ACME account...")
    account_request = {}
    if 'termsOfService' in acme_config.get('meta', {}):
        account_request["termsOfServiceAgreed"] = True
    account_request["contact"] = config["contact_data"].split(';')
    if account_request["contact"] == "":
        del account_request["contact"]
    code, result, headers = _send_signed_request(acme_config["newAccount"], account_request)
    if code != 201:
        api_log().error("Error registering account: {0} {1}".format(code, result))
        return 0
    
    api_log().debug("Registered a new account with id: '{0}'".format(result['id']))

    keyid_path = os.path.join(config['base_key_directory'], 'account/key_id.txt')
    with open(keyid_path, 'w') as key_id:
        key_id.write(headers['Location'])

    os.chmod(keyid_path, 0o600)
    return 1

@api_event(plugin, 'uninstall')
def uninstall():
    config = api_config()[plugin.name]

    auth = api_plugins()['auth']
    if auth.events['check']():
        ruleset = auth.e_get_role('admin')['ruleset']

        try:
            ruleset['inherit'].remove(plugin.name +'_admin')
            auth.e_edit_role('admin', ruleset)
        except: pass

        try:
            auth.e_delete_role(plugin.name +'_admin')
        except: pass

        api_log().debug('Ruleset deleted.')

    ir_delete_directory_tree(config['base_key_directory'])
    return 1

def i_format_time_value(config, key, minv, maxv):
    if config[key] == "*":
        return [-1]

    try:
        val_list = []
        for val in config[key].split(','):
            val = int(config[key])

            if val > maxv or val < minv:
                raise ValueError("Error in Configuration: {} is out of range.".format(key))
            
            val_list.append(val)

        return val_list
    
    except:
        raise ValueError("Can't convert {} to a number".format(key))

@api_event(plugin, 'load')
def load():
    global dns_resolver
    global write_through_cache_enabled

    config = api_config()[plugin.name]
    account_path = os.path.join(config['base_key_directory'], 'account')

    i_init_lets_encrypt()
    i_setup_signatures()

    with open(os.path.join(account_path, 'key_id.txt'), 'r') as keyid_file:
        jws_header['kid'] = keyid_file.read()

    dns_resolver = dns.resolver.Resolver()
    
    # Initialize cache
    certdir_path = os.path.join(config['base_key_directory'], 'certs')
    certpath_list = glob.glob(certdir_path +'/*')

    for cert_path in certpath_list:
        cert_id = re.search(r'^.*\/([^\/]+)$', cert_path).group(1)
        cert_dict[cert_id] = i_get_direct_certificate(cert_id)

    # Create scheduled timer
    time_dict = {
        'minute': i_format_time_value(config, 'autorefresh_minute', 0, 59),
        'hour': i_format_time_value(config, 'autorefresh_hour', 0, 23),
        'day_of_week': i_format_time_value(config, 'autorefresh_dayofweek', 1, 7),
        'day_of_month': i_format_time_value(config, 'autorefresh_dayofmonth', 1, 31),
        'month': i_format_time_value(config, 'autorefresh_month', 1, 12),
        'year': i_format_time_value(config, 'autorefresh_year', 0, 9999)
    }

    time_plugin = api_plugins()['time']
    time_plugin.e_register_timed_static_event('_lets_encrypt_job', et_check_certificates, [], enabled=1, repeat=1, **time_dict)

    auth = api_plugins()['auth']
    auth.e_add_permission_reduce_handler(i_le_permission_reduce_handler)
    auth.e_add_subset_intersection_handler(i_le_subset_intersection_handler)

    write_through_cache_enabled = True

    return 1

@api_action(plugin, {
    'path': 'cert/list',
    'method': 'GET',
    'args': {
        'verbose': {
            'type': bool,
            'default': False,
            'f_name': {
                'EN': "Verbose",
                'DE': "Ausführlich"
            }
        }
    },
    'f_name': {
        'EN': 'List certificates',
        'DE': 'Liste Zertifikate auf'
    },

    'f_description': {
        'EN': 'Returns a list of all certificates.',
        'DE': 'Gibt eine Liste mit allen Zertifiaten zurück.'
    }
})
def list_certificates(reqHandler, p, args, body):
    cert_list = e_list_certificates()

    auth = api_plugins()['auth']
    current_user = auth.e_get_current_user()

    # Checking permissions
    for cert_id in list(cert_list):
        domain_list = e_get_certificate(cert_id)['domains']
        for domain in domain_list:
            if not auth.e_check_custom_permissions_of_current_user(plugin.name +'_allowed_domains', domain, i_domain_permission_validator):
                cert_list.remove(cert_id)
                break

    if args['verbose']:
        return_json = []
        for cert_id in cert_list:
            i_entry = {}
            i_entry['id'] = cert_id
            i_entry.update(e_get_certificate(cert_id))
            return_json.append(i_entry)

        return {
            'data': return_json
        }
    
    else:
        return {
            'data': cert_list
        }

@api_action(plugin, {
    'path': 'cert/*',
    'method': 'GET',
    'params': [
        {
            'name': "cert_id",
            'type': str,
            'f_name': {
                'EN': "Certificate ID",
                'DE': "Zertifikats ID"
            }
        }
    ],
    'f_name': {
        'EN': 'Get certificate',
        'DE': 'Zeige Zertifikat'
    },

    'f_description': {
        'EN': 'Returns informations about a single certificate.',
        'DE': 'Gibt Informationen über ein einzelnes Zertifikat zurück.'
    }
})
def get_certificate(reqHandler, p, args, body):

    cert_data = e_get_certificate(p[0])

    auth = api_plugins()['auth']
    current_user = auth.e_get_current_user()
    domain_list = cert_data['domains']

    # Checking permissions
    for domain in domain_list:
        if not auth.e_check_custom_permissions_of_current_user(plugin.name +'_allowed_domains', domain, i_domain_permission_validator):
            raise WebRequestException(401, 'unauthorized', 'AUTH_PERMISSIONS_DENIED')

    return {
        'data': cert_data
    }

@api_action(plugin, {
    'path': 'cert',
    'method': 'POST',
    'body': {
        'domains': {
            'type': list,
            'f_name': {
                'EN': "Domain list",
                'DE': "Domainliste"
            },
            "allow_empty": False,
            'childs': {
                'type': str
            }
        }
    },
    'f_name': {
        'EN': 'Add new certificate',
        'DE': 'Neues Zertifikat hinzufügen'
    },

    'f_description': {
        'EN': 'Adds a new certificate to the certpool and request it.',
        'DE': 'Fügt ein neues Zertifikat zum Pool hinzu und fordert es an.'
    }
})
def add_certificate(reqHandler, p, args, body):

    auth = api_plugins()['auth']
    current_user = auth.e_get_current_user()
    domain_list = body['domains']

    # Checking permissions
    for domain in domain_list:
        if not auth.e_check_custom_permissions_of_current_user(plugin.name +'_allowed_domains', domain, i_domain_permission_validator):
            raise WebRequestException(401, 'unauthorized', 'AUTH_PERMISSIONS_DENIED')

    log.access('{} certificate with the domains {} requested'.format(api_environment_variables()['transaction_id'], domain_list))

    return {
        'cert_id': e_add_certificate(i_domains_to_punycode(domain_list))
    }

@api_action(plugin, {
    'path': 'cert/*',
    'method': 'DELETE',
    'params': [
        {
            'name': "cert_id",
            'type': str,
            'f_name': {
                'EN': "Certificate ID",
                'DE': "Zertifikats ID"
            }
        }
    ],
    'f_name': {
        'EN': 'Delete certificate',
        'DE': 'Zertifikat löschen'
    },

    'f_description': {
        'EN': 'Deletes a certificate and it linked domains.',
        'DE': 'Löscht ein Zertifikat und die verlinkten Domains.'
    }
})
def delete_certificate(reqHandler, p, args, body):

    cert_data = e_get_certificate(p[0])

    auth = api_plugins()['auth']
    current_user = auth.e_get_current_user()
    domain_list = cert_data['domains']

    # Checking permissions
    for domain in domain_list:
        if not auth.e_check_custom_permissions_of_current_user(plugin.name +'_allowed_domains', domain, i_domain_permission_validator):
            raise WebRequestException(401, 'unauthorized', 'AUTH_PERMISSIONS_DENIED')
            
    e_delete_certificate(p[0])
    return {}

@api_action(plugin, {
    'path': 'check',
    'method': 'POST',
    'f_name': {
        'EN': 'Check certificates',
        'DE': 'Prüfe Zertifikate'
    },

    'f_description': {
        'EN': 'Checks all certificates and renew them if necessary.',
        'DE': 'Prüft alle Zertifikate und erneuert sie wenn nötig.'
    }
})
def check_certificates(reqHandler, p, args, body):
    et_check_certificates()
    return {}

@api_action(plugin, {
    'path': 'request',
    'method': 'POST',
    'body': {
        'domains': {
            'type': list,
            'f_name': {
                'EN': "Domain list",
                'DE': "Domainliste"
            },
            "allow_empty": False,
            'childs': {
                'type': str
            }
        },
        'fingerprints': {
            'type': list,
            'f_name': {
                'EN': "Domain list",
                'DE': "Domainliste"
            },
            'default': [],
            'childs': {
                'type': dict,
                'childs': {
                    'cert': {
                        'type': str
                    },
                    'key': {
                        'type': str
                    }
                }
            }
        }
    },
    'f_name': {
        'EN': 'Request Certificates',
        'DE': 'Zertifikate anfordern'
    },

    'f_description': {
        'EN': 'Requests stored certificates.',
        'DE': 'Fragt gespeicherte Zertifikate an.'
    }
})
def request_certificates(reqHandler, p, args, body):
    auth = api_plugins()['auth']
    current_user = auth.e_get_current_user()
    
    domain_list = i_domains_to_punycode(body['domains'])

    # Checking permissions
    for domain in domain_list:
        if not auth.e_check_custom_permissions_of_current_user(plugin.name +'_allowed_domains', domain, i_domain_permission_validator):
            raise WebRequestException(401, 'unauthorized', 'AUTH_PERMISSIONS_DENIED')

    config = api_config()[plugin.name]
    domaindir_path = os.path.join(config['base_key_directory'], 'domains')

    # Build cert- and key-fingerprint-lists
    certfp_list = []
    keyfp_list = []
    for fp in body['fingerprints']:
        certfp_list.append(fp['cert'])
        keyfp_list.append(fp['key'])

    tmp_cert_dict = {}
    for domain in domain_list:
        wc_replace_char = config['wildcard_replace_character']
        cert_path = os.path.join(domaindir_path, domain.replace('*', wc_replace_char))
        if not os.path.islink(cert_path):
            raise WebRequestException(400, 'error', 'LE_DOMAIN_NOT_FOUND', {
                'domain': domain
            })

        with open(os.path.join(cert_path, 'domains.json')) as domainfile:
            cert_domain_list = json.loads(domainfile.read())

        cert_id = i_get_cert_id(cert_domain_list)

        if cert_id in tmp_cert_dict:
            tmp_cert_dict[cert_id]['domains'].append(domain)
            continue
        
        tmp_cert_dict[cert_id] = {}
        tmp_cert_dict[cert_id]['domains'] = [domain]

        with open(os.path.join(cert_path, 'certfile.pem')) as certfile:
            cert = certfile.read()

        cert_fingerprint = hashlib.sha256(cert.encode('ascii')).hexdigest()
        if cert_fingerprint in certfp_list:
            tmp_cert_dict[cert_id]['cert'] = cert_fingerprint
            cert_valid = True
        else:
            tmp_cert_dict[cert_id]['certfile'] = cert
            cert_valid = False
        
        with open(os.path.join(cert_path, 'keyfile.pem')) as keyfile:
            key = keyfile.read()

        key_fingerprint = hashlib.sha256(key.encode('ascii')).hexdigest()
        if key_fingerprint in keyfp_list:
            tmp_cert_dict[cert_id]['key'] = key_fingerprint
            key_valid = True
        else:
            tmp_cert_dict[cert_id]['keyfile'] = key
            key_valid = False

        if cert_valid != key_valid:
            tmp_cert_dict[cert_id]['status'] = 'update'
        elif cert_valid == True:
            tmp_cert_dict[cert_id]['status'] = 'ok'
        else:
            tmp_cert_dict[cert_id]['status'] = 'new'

    return_json = []
    for cert_id in tmp_cert_dict.keys():
        return_json.append(tmp_cert_dict[cert_id])

    return {
        'data': return_json
    }
