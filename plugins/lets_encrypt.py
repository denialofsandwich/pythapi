#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: lets_encrypt.py
# Author:      Rene Fa
# Date:        06.07.2018
# Version:     0.1
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
    }
]

plugin.config_defaults = {
    plugin.name: {
        'acme_directory': "https://acme-staging-v02.api.letsencrypt.org/directory",
        'base_key_directory': "/etc/pythapi/lets_encrypt",
        'termsOfUse_accepted': 'false',
        'rsa_keysize': "4096",
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
        'autorefresh_mindaysreaming': "1"
    }
}
plugin.translation_dict = {
    'LE_CERT_EXIST': {
        'EN': "Certificate already exists.",
        'DE': "Zertifikat existiert bereits."
    }
}

acme_config = None
jws_nonce = None
jws_header = None
adtheaders = None
joseheaders = None

def _b64(b):
    return base64.urlsafe_b64encode(b).decode("utf8").rstrip("=")

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

def i_delete_directory_tree(path):
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            os.remove(os.path.join(root, name))
        for name in dirs:
            os.rmdir(os.path.join(root, name))
    try: os.rmdir(path)
    except: pass

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

@api_external_function(plugin)
def e_renew_certificate(certificate_name):
    api_log().debug("I would renew this certificate now.")
    pass

@api_external_function(plugin)
def et_check_certificates():
    api_log().info("Checking certificates...")
    config = api_config()[plugin.name]
    
    certdir_path = os.path.join(config['base_key_directory'], 'certs')

    cert_list = glob.glob(certdir_path +'/*')
    for cert_path in cert_list:
        cert_name = re.search(r'^.*\/([^\/]+)$', cert_path).group(1)
        certfile_path = os.path.join(cert_path, 'certfile.pem')

        api_log().debug("Checking {}...".format(cert_name))
        
        if not os.path.isfile(os.path.join(certfile_path)):
            e_renew_certificate(cert_name)
            continue
        
        else:
            with open(certfile_path, 'r') as certfile:
                cert = certfile.read()

            datestr =  re.search(r'Not After \: (.*) GMT\n', cert).group(1)
            date = datetime.datetime.strptime(datestr, '%b %d %H:%M:%S %Y')
            delta =  date - datetime.datetime.now()

            if delta.days == int(config['autorefresh_mindaysreaming']):
                e_renew_certificate(cert_name)

    api_log().debug("Done checking certificates.")
    pass

@api_external_function(plugin)
def e_add_certificate(domain_list):
    config = api_config()[plugin.name]
    account_path = os.path.join(config['base_key_directory'], 'account/keyfile.pem')
    baseconf_path = os.path.join(config['base_key_directory'], 'openssl.cnf')
    tmpconf_path = os.path.join(config['base_key_directory'], 'tmp/openssl.cnf')
    
    new_domain_path = os.path.join(config['base_key_directory'], 'certs', domain_list[0])
    keyfile_path = os.path.join(new_domain_path, 'keyfile.pem')

    if os.path.isdir(new_domain_path):
        raise WebRequestException(400, 'error', 'LE_CERT_EXIST')

    os.makedirs(new_domain_path)

    api_log().debug("Generating keyfile....")
    sysout = i_exec_openssl(['genrsa', '-out', keyfile_path, config['rsa_keysize'], '-nodes'])
    
    if sysout == None:
        api_log().error("Can\'t generate keyfile.")
        return 0
    
    os.chmod(keyfile_path, 0o600)

    with open(os.path.join(new_domain_path, 'domains.txt'), 'w') as domainsfile:
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
    e_renew_certificate(domain_list[0])

@api_external_function(plugin)
def e_list_available_certificates():
    return 1

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
    
    if str.lower(config.get('termsofuse_accepted', 'true')) == 'true':
        api_log().info("Terms of use accepted in configuration file.")

    else:
        print("Please read the terms of use at: {}".format(terms_service))
        choice = input("Did you read and agree with the terms of service? [Y/n]: ")
        
        if str.lower(choice) == 'n':
            api_log().error("You have to accept the terms of use to continue.")
            return 0

    api_log().debug("Generating keyfile....")
    keyfile_path = os.path.join(config['base_key_directory'], 'account/keyfile.pem')
    sysout = i_exec_openssl(['genrsa', '-out', keyfile_path, config['rsa_keysize'], '-nodes'])
    
    if sysout == None:
        api_log().error("Can\'t generate keyfile.")
        return 0
    
    os.chmod(keyfile_path, 0o600)
    
    i_setup_signatures()

    api_log().debug("Register ACME account...")
    account_request = {}
    if 'termsOfService' in acme_config.get('meta', {}):
        account_request["termsOfServiceAgreed"] = True
    account_request["contact"] = config['contact_data'].split(';')
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
    i_delete_directory_tree(config['base_key_directory'])
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
    i_init_lets_encrypt()
    i_setup_signatures()
    
    config = api_config()[plugin.name]

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

    return 1

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
    'path': 'cert',
    'method': 'POST',
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
    e_add_certificate(body['domains'])
    return {}

@api_action(plugin, {
    'path': 'cert/list',
    'method': 'GET',
    'f_name': {
        'EN': 'List available certificates',
        'DE': 'Zeige verfügbare Zertifikate'
    },

    'f_description': {
        'EN': 'Returns a list of all currently available certificates.',
        'DE': 'Gibt eine Liste mit allen zurzeit verfügbaren Zertifiaten zurück.'
    }
})
def list_available_certificates(reqHandler, p, args, body):
    return {
        'data': "Nothing there."
    }
