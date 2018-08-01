#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Name:        pythapi: telegram-bot.py
# Author:      Rene Fa
# Date:        10.07.2018
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
import MySQLdb # MySQL
from api_plugin import * # Essential Plugin
import tornado # For POST Body decoding

import telegram
from telegram.ext import Updater
from telegram.ext import CommandHandler
from telegram.ext import MessageHandler, Filters

plugin = api_plugin()
plugin.name = "telegram"
plugin.version = "0.5"
plugin.essential = False
plugin.info['f_name'] = "Telegram-bot plugin"
plugin.info['f_description'] = "This plugin can control a telegram bot."
plugin.info['f_name'] = {
    'EN': 'Telegram-bot plugin',
    'DE': 'Telegram-Bot Plugin'
}

plugin.info['f_description'] = {
    'EN': 'This plugin can control a telegram bot.',
    'DE': 'Dieses Plugin ermöglicht die Steuerung eines Telegram Bots.'
}

plugin.depends = [
    {
        'name': 'auth',
        'required': False
    }
]

plugin.config_defaults = {
    plugin.name: {
        'bot_token': 'no_string_given',
        'input_handler_enabled': True
    }
}

plugin.translation_dict = {
    'TELEGRAM_CHANNEL_NOT_FOUND': {
        'EN': 'Channel not found.',
        'DE': 'Channel nicht gefunden.'
    },
    
    'TELEGRAM_CHAT_IS_NOT_IN_CHANNEL': {
        'EN': 'Chat ID is not a member of this channel.',
        'DE': 'Chat ID ist kein ein Mitglied dieses Channels.'
    },
    
    'TELEGRAM_CHAT_IS_IN_CHANNEL': {
        'EN': 'Chat ID is already a member of this channel.',
        'DE': 'Chat ID ist bereits ein Mitglied dieses Channels.'
    },
    
    'TELEGRAM_CHAT_OR_CHANNEL_NOT_FOUND': {
        'EN': 'Channel or chat ID not found.',
        'DE': 'Channel oder Chat ID nicht gefunden.'
    },
    
    'TELEGRAM_MESSAGE_MISSING': {
        'EN': 'No message text specified.',
        'DE': 'Nachrichtentext nicht gefunden.'
    },
    
    'TELEGRAM_IMAGE_MISSING': {
        'EN': 'No image specified.',
        'DE': 'Bild nicht gefunden.'
    }
}

used_tables = ["telegram_bot_channel"]

bot = None
updater = None
dispatcher = None
channel_dict = {}
write_trough_cache_enabled = False

def i_get_db_channel(channel_name):
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    sql = """
        SELECT * FROM """ +db_prefix +"""telegram_bot_channel WHERE channel_name = %s;
    """
    
    try:
        dbc.execute(sql, [channel_name])
    
    except MySQLdb.IntegrityError as e:
        api_log().error("i_get_db_channel: {}".format(api_tr('GENERAL_SQL_ERROR')))
        raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')
    
    if dbc.rowcount <= 0:
        raise WebRequestException(400, 'error', 'TELEGRAM_CHANNEL_NOT_FOUND')
    
    return dbc.fetchall()

def i_get_local_channel(channel_name):
    if not channel_name in channel_dict:
        raise WebRequestException(400, 'error', 'TELEGRAM_CHANNEL_NOT_FOUND')
        
    return {
        'members': list(channel_dict[channel_name])
    }

@api_external_function(plugin)
def e_get_channel(channel_name):
    if write_trough_cache_enabled:
        return i_get_local_channel(channel_name)
    
    else:
        return_json = {}
        return_json['members'] = []
        
        for row in i_get_db_channel(channel_name):
            return_json['members'].append(row[2])
        
        return return_json

def i_list_db_channels():
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    sql = """
        SELECT * FROM """ +db_prefix +"""telegram_bot_channel;
    """
    
    try:
        dbc.execute(sql)
    
    except MySQLdb.IntegrityError as e:
        api_log().error("i_list_db_channels: {}".format(api_tr('GENERAL_SQL_ERROR')))
        raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')
    
    return dbc.fetchall()

def i_list_local_channels():
    return_json = []
    for channel_name in channel_dict:
        
        i_entry = i_get_local_channel(channel_name)
        i_entry['channel_name'] = channel_name
        
        return_json.append(i_entry)
    
    return return_json

@api_external_function(plugin)
def e_list_channels():
    if write_trough_cache_enabled:
        return i_list_local_channels()
    
    else:
        tmp_channel_tree = {}
        for row in i_list_db_channels():
            if not row[1] in tmp_channel_tree:
                tmp_channel_tree[row[1]] = []
            
            tmp_channel_tree[row[1]].append(row[2])
        
        return_json = []
        for channel_name in tmp_channel_tree:
            
            i_entry = {}
            i_entry['channel_name'] = channel_name
            i_entry['members'] = tmp_channel_tree[channel_name]
            
            return_json.append(i_entry)
    
    return return_json
            

@api_external_function(plugin)
def e_add_reciever_to_channel(channel_name, t_chat_id):
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    with db:
        sql = """
            INSERT INTO """ +db_prefix +"""telegram_bot_channel (
                    channel_name, chat_id
                )
                VALUES (%s, %s);
        """
        
        try:
            dbc.execute(sql,[channel_name, t_chat_id])
            db.commit()
            
        except MySQLdb.IntegrityError as e:
            raise WebRequestException(400, 'error', 'TELEGRAM_CHAT_IS_IN_CHANNEL')
    
    if write_trough_cache_enabled:
        if not channel_name in channel_dict:
            channel_dict[channel_name] = []
        
        channel_dict[channel_name].append(t_chat_id)

@api_external_function(plugin)
def e_remove_reciever_from_channel(channel_name, t_chat_id):
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    if write_trough_cache_enabled:
        if not channel_name in channel_dict:
            raise WebRequestException(400, 'error', 'TELEGRAM_CHANNEL_NOT_FOUND')
        
        if t_chat_id != '*' and not t_chat_id in channel_dict[channel_name]:
            raise WebRequestException(400, 'error', 'TELEGRAM_CHAT_IS_NOT_IN_CHANNEL')
    
    with db:
        if t_chat_id == '*':
            sql = """
                DELETE FROM """ +db_prefix +"""telegram_bot_channel 
                    WHERE channel_name = %s;
            """
        
        else:
            sql = """
                DELETE FROM """ +db_prefix +"""telegram_bot_channel 
                    WHERE channel_name = %s AND chat_id = %s;
            """
        
        try:
            dbc.execute(sql,[channel_name, t_chat_id])
            db.commit()
            
            if dbc.rowcount == 0:
                raise WebRequestException(400, 'error', 'TELEGRAM_CHAT_OR_CHANNEL_NOT_FOUND')
            
        except MySQLdb.IntegrityError as e:
            api_log().error("e_remove_reciever_from_channel: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')
    
    if write_trough_cache_enabled:
        if t_chat_id == '*':
            del channel_dict[channel_name]
        
        else:
            channel_dict[channel_name].remove(t_chat_id)
            if len(channel_dict[channel_name]) == 0:
                del channel_dict[channel_name]

@api_external_function(plugin)
def e_send_text_to_channel(channel_name, message):
    
    for member in e_get_channel(channel_name)['members']:
        try: bot.send_message(member, message)
        except telegram.error.TimedOut:
            api_log().warning("e_send_text_to_channel: Timed out.")
            pass

@api_external_function(plugin)
def e_send_image_to_channel(channel_name, image_path):
    image = open(image_path, 'rb')
    
    for member in e_get_channel(channel_name)['members']:
        image.seek(0)
        try: bot.send_photo(member, photo=image)
        except telegram.error.TimedOut:
            api_log().warning("e_send_text_to_channel: Timed out.")
            pass
    
    image.close()

def i_dump_db_table():
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    with db:
        sql = """
            SELECT *
                FROM """ +db_prefix +"""telegram_bot_channel;
        """
        
        try:
            dbc.execute(sql)
            
        except MySQLdb.IntegrityError as e:
            api_log().error("i_dump_db_table: {}".format(api_tr('GENERAL_SQL_ERROR')))
            raise WebRequestException(501, 'error', 'GENERAL_SQL_ERROR')
        
        return dbc.fetchall()

@api_event(plugin, 'check')
def check():
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    with db:
        # Checks if all tables exist.
        result = 1
        for table in used_tables:
            sql = "SHOW TABLES LIKE '" +db_prefix +table +"'"
            result *= dbc.execute(sql)
    
    if(result == 0):
        return 0
    
    return 1

@api_event(plugin, 'install')
def install():
    
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    api_log().info("Create new Tables...")
    
    sql = """
        CREATE TABLE """ +db_prefix +"""telegram_bot_channel (
            id INT NOT NULL AUTO_INCREMENT,
            channel_name VARCHAR(64) NOT NULL,
            chat_id VARCHAR(16) NOT NULL,
            PRIMARY KEY (id),
            UNIQUE (channel_name, chat_id)
        ) ENGINE = InnoDB;
        """
    dbc.execute(sql)
    api_log().debug("Table: '" +db_prefix +"telegram_bot_channel' created.")

    dbc.close()
    
    if 'auth' in api_plugins():
        api_log().info('auth installed. Apply ruleset...')
        
        auth = api_plugins()['auth']
        
        auth.e_create_role('telegram_default', {
            'permissions':  [
                'telegram.get_personal_channel',
                'telegram.add_reciever',
                'telegram.remove_reciever',
                'telegram.send_text',
                'telegram.send_image'
            ]
        })
        
        ruleset = auth.e_get_role('default')['ruleset']
        
        try:
            if not 'telegram_default' in ruleset['inherit']:
                ruleset['inherit'].append('telegram_default')
                
            auth.e_edit_role('default', ruleset)
        except WebRequestException as e:
            api_log().error('Editing the default role failed!')
            return 0
    
    return 1

@api_event(plugin, 'uninstall')
def uninstall():
    db_prefix = api_config()['core.mysql']['prefix']
    db = api_mysql_connect()
    dbc = db.cursor()
    
    if 'auth' in api_plugins() and api_plugins()['auth'].events['check']():
        
        auth = api_plugins()['auth']
        
        ruleset = auth.e_get_role('default')['ruleset']
        
        try:
            ruleset['inherit'].remove('telegram_default')
            auth.e_edit_role('default', ruleset)
        except: pass
        
        try:
            auth.e_delete_role('telegram_default')
        except: pass
    
        api_log().debug('Ruleset deleted.')
    
    api_log().info("Delete old Tables...")
    
    for table in reversed(used_tables):
        sql = "DROP TABLE " +db_prefix +table +";"
        
        try: dbc.execute(sql)
        except MySQLdb.Error: continue
    
        api_log().debug("Table: '" +db_prefix +table +"' deleted.")
    
    dbc.close()
    return 1

def tc_start(bot, update):
    api_log().debug("Discovered a new chat_id: {}".format(str(update.message.chat_id)))
    update.message.reply_text("Hello. This is your chat_id: {}".format(str(update.message.chat_id)))

@api_event(plugin, 'load')
def load():
    global bot
    global updater
    global dispatcher
    global write_trough_cache_enabled
    
    try: bot = telegram.Bot(api_config()[plugin.name]['bot_token'])
    except:
        api_log().error('Invalid API token.')
        return 0
    
    if api_config()[plugin.name]['input_handler_enabled']:
        updater = Updater(token=api_config()[plugin.name]['bot_token'])
        dispatcher = updater.dispatcher
        
        start_handler = CommandHandler('start', tc_start)
        dispatcher.add_handler(start_handler)
        
        updater.start_polling()
        api_log().info('Telegam bot started.')
    
    for row in i_dump_db_table():
        if not row[1] in channel_dict:
            channel_dict[row[1]] = []
        
        channel_dict[row[1]].append(row[2])
    
    write_trough_cache_enabled = True
    
    return 1

@api_event(plugin, 'terminate')
def terminate():
    
    if api_config()[plugin.name]['input_handler_enabled']:
        api_log().info('Stopping telegam bot...')
        updater.stop()
        api_log().debug('Telegram bot stopped.')
    
    return 1

#@api_action(plugin, {
#    'path': 'debug1',
#    'method': 'GET',
#    'f_name': {
#        'EN': 'Debug1'
#    },
#
#    'f_description': {
#        'EN': 'Debug.'
#    }
#})
#def debug1(reqHandler, p, args, body):
#    return {
#        'channel_dict': channel_dict
#    }
#
#@api_action(plugin, {
#    'path': 'debug2/*',
#    'method': 'GET',
#    'f_name': {
#        'EN': 'Debug2'
#    },
#
#    'f_description': {
#        'EN': 'Debug.'
#    }
#})
#def debug2(reqHandler, p, args, body):
#    
#    chat = bot.getChat(p[0])
#    
#    return {
#        'data': {
#            'username': chat.username,
#            'first_name': chat.first_name,
#            'last_name': chat.last_name,
#            'type': chat.type
#        }
#    }

@api_action(plugin, {
    'path': 'channel/list',
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
        'EN': 'List channel',
        'DE': 'Channel auflisten'
    },

    'f_description': {
        'EN': 'Lists all channels.',
        'DE': 'Listet alle Channel auf.'
    }
})
def list_channels(reqHandler, p, args, body):
    if args['verbose']:
        return {
            'data': e_list_channels()
        }
    
    else:
        return {
            'data': list(channel_dict.keys())
        }

@api_action(plugin, {
    'path': 'channel/*',
    'method': 'GET',
    'params': [
        {
            'name': "channel_name",
            'type': str,
            'f_name': {
                'EN': "Channel name",
                'DE': "Channel Name"
            }
        }
    ],
    'f_name': {
        'EN': 'Get channel',
        'DE': 'Zeige Channel'
    },

    'f_description': {
        'EN': 'Returns a single channel.',
        'DE': 'Gibt einen einzelnen Channel zurück.'
    }
})
def get_channel(reqHandler, p, args, body):
    
    return {
        'data': e_get_channel(p[0])
    }

@api_action(plugin, {
    'path': 'channel',
    'method': 'GET',
    'f_name': {
        'EN': 'Get own channel',
        'DE': 'Zeige eigenen Channel'
    },

    'f_description': {
        'EN': 'Returns all members of your channel.',
        'DE': 'Gibt alle Mitglieder des eigenen Channels zurück.'
    }
})
def get_personal_channel(reqHandler, p, args, body):
    auth = api_plugins()['auth']
    current_user = auth.e_get_current_user()
    
    return {
        'data': e_get_channel(current_user)
    }

@api_action(plugin, {
    'path': 'channel/*/*',
    'method': 'POST',
    'params': [
        {
            'name': "channel_name",
            'type': str,
            'f_name': {
                'EN': "Channel name",
                'DE': "Channel Name"
            }
        },
        {
            'name': "username",
            'type': str,
            'f_name': {
                'EN': "Username",
                'DE': "Benutzername"
            }
        }
    ],
    'f_name': {
        'EN': 'Add reciever to channel',
        'DE': 'Füge Empfänger zu Channel hinzu'
    },

    'f_description': {
        'EN': 'Adds a new reciever to a channel. A new channel will automatically created.',
        'DE': 'Fügt einen neuen Empfänger zu einem Channel hinzu. Existiert der Channel nicht, wird er automatisch erstellt.'
    }
})
def add_reciever_to_channel(reqHandler, p, args, body):
    
    e_add_reciever_to_channel(p[0], p[1])
    return {}

@api_action(plugin, {
    'path': 'channel/*',
    'method': 'POST',
    'params': [
        {
            'name': "username",
            'type': str,
            'f_name': {
                'EN': "Username",
                'DE': "Benutzername"
            }
        }
    ],
    'f_name': {
        'EN': 'Add reciever to your channel',
        'DE': 'Füge Empfänger zu eigenem Channel hinzu'
    },

    'f_description': {
        'EN': 'Adds a new reciever to your channel',
        'DE': 'Fügt einen neuen Empfänger zum eigenen Channel hinzu.'
    }
})
def add_reciever(reqHandler, p, args, body):
    auth = api_plugins()['auth']
    current_user = auth.e_get_current_user()
    
    e_add_reciever_to_channel(current_user, p[0])
    return {}

@api_action(plugin, {
    'path': 'channel/*/*',
    'method': 'DELETE',
    'params': [
        {
            'name': "channel_name",
            'type': str,
            'f_name': {
                'EN': "Channel name",
                'DE': "Channel Name"
            }
        },
        {
            'name': "username",
            'type': str,
            'f_name': {
                'EN': "Username",
                'DE': "Benutzername"
            }
        }
    ],
    'f_name': {
        'EN': 'Remove reciever from channel',
        'DE': 'Entferne Empfänger aus Channel'
    },

    'f_description': {
        'EN': 'Removes a reciever from a channel.',
        'DE': 'Entfernt einen Empfänger aus einem Channel.'
    }
})
def remove_reciever_from_channel(reqHandler, p, args, body):
    
    e_remove_reciever_from_channel(p[0], p[1])
    return {}

@api_action(plugin, {
    'path': 'channel/*',
    'method': 'DELETE',
    'params': [
        {
            'name': "username",
            'type': str,
            'f_name': {
                'EN': "Username",
                'DE': "Benutzername"
            }
        }
    ],
    'f_name': {
        'EN': 'Remove reciever from your channel',
        'DE': 'Entferne Empfänger aus eigenem Channel'
    },

    'f_description': {
        'EN': 'Removes a reciever from your channel.',
        'DE': 'Entfernt einen Empfänger aus dem eigenem Channel.'
    }
})
def remove_reciever(reqHandler, p, args, body):
    auth = api_plugins()['auth']
    current_user = auth.e_get_current_user()
    
    e_remove_reciever_from_channel(current_user, p[0])
    return {}

@api_action(plugin, {
    'path': 'send/*/text',
    'method': 'POST',
    'params': [
        {
            'name': "channel_name",
            'type': str,
            'f_name': {
                'EN': "Channel name",
                'DE': "Channel Name"
            }
        }
    ],
    'body': {
        'message': {
            'type': str,
            'f_name': {
                'EN': "Message",
                'DE': "Nachricht"
            }
        }
    },
    'f_name': {
        'EN': 'Send text to channel',
        'DE': 'Sende Text an Channel'
    },

    'f_description': {
        'EN': 'Sends a text message to a channel.',
        'DE': 'Sendet eine Textnachricht an einen Channel.'
    }
})
def send_text_to_channel(reqHandler, p, args, body):
    
    if not 'message' in body:
        raise WebRequestException(400, 'error', 'TELEGRAM_MESSAGE_MISSING')
    
    e_send_text_to_channel(p[0], body['message'])
    return {}

@api_action(plugin, {
    'path': 'send/text',
    'method': 'POST',
    'body': {
        'message': {
            'type': str,
            'f_name': {
                'EN': "Message",
                'DE': "Nachricht"
            }
        }
    },
    'f_name': {
        'EN': 'Send text',
        'DE': 'Sende Text'
    },

    'f_description': {
        'EN': 'Sends a text message to your channel.',
        'DE': 'Sendet eine Textnachricht an den eigenen Channel.'
    }
})
def send_text(reqHandler, p, args, body):
    auth = api_plugins()['auth']
    current_user = auth.e_get_current_user()
    
    if not 'message' in body:
        raise WebRequestException(400, 'error', 'TELEGRAM_MESSAGE_MISSING')
    
    e_send_text_to_channel(current_user, body['message'])
    return {}

@api_action(plugin, {
    'path': 'send/*/image',
    'method': 'POST',
    'params': [
        {
            'name': "channel_name",
            'type': str,
            'f_name': {
                'EN': "Channel name",
                'DE': "Channel Name"
            }
        }
    ],
    'f_name': {
        'EN': 'Send image to channel',
        'DE': 'Sende Bild an Channel'
    },

    'f_description': {
        'EN': 'Sends an image to a channel.',
        'DE': 'Sendet ein Bild an einen Channel.'
    },
    'request_content_type': 'image/jpeg'
})
def send_image_to_channel(reqHandler, p, args, body):
    
    if not 'image' in reqHandler.request.files:
        raise WebRequestException(400, 'error', 'TELEGRAM_IMAGE_MISSING')
    
    f = open('downloads/tmp_telegram.jpg', 'wb')
    f.write(reqHandler.request.files["image"][0]["body"])
    f.close()
    
    e_send_image_to_channel(p[0], 'downloads/tmp_telegram.jpg')
    return {}

@api_action(plugin, {
    'path': 'send/image',
    'method': 'POST',
    'f_name': {
        'EN': 'Send image',
        'DE': 'Sende Bild'
    },

    'f_description': {
        'EN': 'Sends an image to your channel.',
        'DE': 'Sendet ein Bild an den eigenen Channel.'
    },
    'request_content_type': 'image/jpeg'
})
def send_image(reqHandler, p, args, body):
    auth = api_plugins()['auth']
    current_user = auth.e_get_current_user()
    
    if not 'image' in reqHandler.request.files:
        raise WebRequestException(400, 'error', 'TELEGRAM_IMAGE_MISSING')
    
    f = open('downloads/tmp_telegram.jpg', 'wb')
    f.write(reqHandler.request.files["image"][0]["body"])
    f.close()
    
    e_send_image_to_channel(current_user, 'downloads/tmp_telegram.jpg')
    return {}
