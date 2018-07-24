#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: alert_mail.py
# Author:      Rene Fa
# Date:        24.07.2018
# Version:     0.5
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

import sys
sys.path.append("..")
from api_plugin import *
import smtplib
from email.mime.text import MIMEText
from threading import Thread
import socket
import time
import re

plugin = api_plugin()
plugin.name = 'alert_mail'
plugin.version = '0.5'
plugin.essential = False
plugin.info['f_name'] = {
    'EN': "E-Mail alerts",
    'DE': "E-Mail Alerts"
}

plugin.info['f_description'] = {
    'EN': "A simple mail alerter.",
    'DE': "Ein simpler E-Mail Alerter."
}

plugin.depends = []

plugin.config_defaults = {
    plugin.name: {
        'recievers': [],
        'sender': "pythapi_alerter",
        'target_loglevel': 2,
        'regex_filter': ".*",
        'subject': "Pythapi error {hostname}",
        'body': """
            <font face="verdana">
            <h2>Pythapi returned an error.</h2><br>
            <table>
                <tr>
                    <td>Time:</td>
                    <td>{}</td>
                </tr>
                <tr>
                    <td>Hostname:</td>
                    <td>{}</td>
                </tr>
                <tr>
                    <td>Process ID:</td>
                    <td>{}</td>
                </tr>
                <tr>
                    <td>Severity:</td>
                    <td>{}</td>
                </tr>
                <tr>
                    <td>Message:</td>
                    <td>{}</td>
                </tr>
            </table></font>
        """
    }
}

plugin.translation_dict = {}

tr_loglevel = {
    0: 50,
    1: 40,
    2: 30,
    3: 25,
    4: 20,
    5: 15,
    6: 10
}

regex_filter_list = []

def it_send_mail(record):
    config = api_config()[plugin.name]
    for reciever in config['recievers']:

        hostname = socket.gethostname()
        time_str = time.strftime('%H:%M:%S %d.%m.%Y', time.localtime(record.created))
        severity = record.levelname.replace(r'\\033\[[0-9+]\m', '')
        msg_str = config['body'].format(time=time_str, hostname=hostname, processid=record.process, severity=severity, message=record.msg)

        msg = MIMEText(msg_str)
        msg['Subject'] = config['subject'].format(time=time_str, hostname=hostname, processid=record.process, severity=severity, message=record.msg)
        msg['From'] = config['sender']
        msg['To'] = reciever
        msg['Content-type'] = 'text/html'

        smtpserver = smtplib.SMTP('localhost')
        smtpserver.sendmail(config['sender'], reciever, msg.as_string())
        smtpserver.quit()

def i_debug_logging_interposer(record, handler):
    if record.levelno >= tr_loglevel[api_config()[plugin.name]['target_loglevel']]:
        hit = False
        for c_re in regex_filter_list:
            if c_re.search(record.msg):
                hit = True
                break
        
        if hit:
            Thread(target=it_send_mail, args=(record,)).start()

@api_event(plugin, 'load')
def load():
    global smtpserver

    for regex_str in api_config()[plugin.name]['regex_filter'].split('\n'):
        regex_filter_list.append(re.compile(regex_str))

    api_log().addInterposer(i_debug_logging_interposer)
    return 1
