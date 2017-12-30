"""
Concord 4 Server for Smartthings

This program works with the superbus 2000 automation module over a serial port to send and receive
events to a Concord 4 alarm system.   Events are sent up to a smartthings SmartApp to update a virtual
concord device status.  The server also runs a REST API to receive arm/disarm commands back from the
Smartthings hub or any other device with the API key.

Scott Dozier
4/1/2016


Developed from py-concord Copyright (c) 2013, Douglas S. J. De Couto, decouto@alum.mit.edu


"""

import os
import sys
import asyncore, asynchat
import time
import asyncore, asynchat
import socket
import time
from threading import Thread
from collections import deque
import datetime
import traceback
import os, socket, string, httplib, urllib, urlparse, ssl
import StringIO, mimetools
import json
import base64
import logging,logging.handlers
import requests
import ConfigParser
from concord import concord, concord_commands, concord_alarm_codes
from concord.concord_commands import STAR, HASH, TRIPPED, FAULTED, ALARM, TROUBLE, BYPASSED

log = logging.getLogger('root')
version = 2.0

def dict_merge(a, b):
    c = a.copy()
    c.update(b)
    return c

def start_logger():
    FORMAT = "%(asctime)-15s [%(filename)s:%(funcName)1s()] - %(levelname)s - %(message)s"
    logging.basicConfig(format=FORMAT)
    if 'DEBUG' in config.LOGLEVEL.upper():
        log.setLevel(logging.DEBUG)
    elif 'INFO' in config.LOGLEVEL.upper():
        log.setLevel(logging.INFO)
    elif 'ERR' in config.LOGLEVEL.upper():
        log.setLevel(logging.ERROR)
    else :
        log.setLevel(logging.INFO)
    handler = logging.handlers.RotatingFileHandler('concordsvr.log',
                                           maxBytes=2000000,
                                           backupCount=2,
                                           )
    formatter = logging.Formatter(FORMAT)
    handler.setFormatter(formatter)
    log.addHandler(handler)
    log.info('Logging started [LEVEL: '+str(config.LOGLEVEL.upper())+']'+'...')
    if True:
        try:
            import http.client as http_client
        except ImportError:
            # Python 2
            import httplib as http_client
        # Disable debugging of HTTP calls. If there's an issue, re-enable this to see the trace of what is coming in / out
        #http_client.HTTPConnection.debuglevel = 1
        #requests_log = logging.getLogger("requests.packages.urllib3")
        #requests_log.setLevel(logging.DEBUG)
        #requests_log.propagate = True


def logger(message, level = 'info'):
    if 'info' in level:
        log.info(message)
    elif 'error' in level:
        log.error(message)
    elif 'debug' in level:
        log.debug(message)
    elif 'critical' in level:
        log.critical(message)
    elif 'warn' in level:
        log.warn(message)


#
# Send e-mail over GMAIL
#
def send_email(user, pwd, recipient, subject, body):
    import smtplib

    gmail_user = user
    gmail_pwd = pwd
    FROM = user
    TO = recipient if type(recipient) is list else [recipient]
    SUBJECT = subject
    TEXT = body

    # Prepare actual message
    message = """From: %s\nTo: %s\nSubject: %s\n\n%s
    """ % (FROM, ", ".join(TO), SUBJECT, TEXT)
    try:
        server_ssl = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server_ssl.ehlo()
        server_ssl.login(gmail_user, gmail_pwd)
        server_ssl.sendmail(FROM, TO, message)
        server_ssl.close()
        log.info("E-mail notification sent")
    except Exception, ex:
        log.error("E-mail notification failed to send: %s" % str(ex))

def zonekey(zoneDev):
    """ Return internal key for supplied Indigo zone device. """
    #assert zoneDev.deviceTypeId == 'zone'
    return (int(zoneDev.pluginProps['partitionNumber']),
            int(zoneDev.pluginProps['zoneNumber']))
    
def partkey(partDev):
    """ Return internal key for supplied Indigo partition or touchpad device. """
    #assert partDev.deviceTypeId in ('partition', 'touchpad')
    return int(partDev.address)

def any_if_blank(s):
    if s == '': return 'any'
    else: return s

def isZoneErrState(state_list):
    for err_state in [ ALARM, FAULTED, TROUBLE, BYPASSED ]:
        if err_state in state_list:
            return True
    return False

def zoneStateChangedExceptTripped(old, new):
    old = list(sorted(old)).remove(TRIPPED)
    new = list(sorted(new)).remove(TRIPPED)
    return old != new
    

#
# Touchpad display when no data available
#
NO_DATA = '<NO DATA>'

#
# Keypad sequences for various actions
#
KEYPRESS_SILENT = [ 0x05 ]
KEYPRESS_ARM_STAY = [ 0x28 ]
KEYPRESS_ARM_AWAY = [ 0x27 ]
KEYPRESS_ARM_STAY_LOUD = [ 0x02 ]
KEYPRESS_ARM_AWAY_LOUD = [ 0x03 ]
KEYPRESS_DISARM = [ 0x20 ]
KEYPRESS_BYPASS = [ 0xb ] # '#'
KEYPRESS_TOGGLE_CHIME = [ 7, 1 ]

KEYPRESS_EXIT_PROGRAM = [ STAR, 0, 0, HASH ]


#
# XML configuration filters
# 
PART_FILTER = [(str(p), str(p)) for p in range(1, concord.CONCORD_MAX_ZONE+1)]
PART_FILTER_TRIGGER = [('any', 'Any')] + PART_FILTER

PART_STATE_FILTER = [ 
    ('unknown', 'Unknown'),
    ('ready', 'Ready'), # aka 'off'
    ('unready', 'Not Ready'), # Not actually a Concord state 
    ('zone_test', 'Phone Test'),
    ('phone_test', 'Phone Test'),
    ('sensor_test', 'Sensor Test'),
    ('stay', 'Armed Stay'),
    ('away', 'Armed Away'),
    ('night', 'Armed Night'),
    ('silent', 'Armed Silent'),
    ]
PART_STATE_FILTER_TRIGGER = [('any', 'Any')] + PART_STATE_FILTER

# Different messages (i.e. PART_DATA and ARM_LEVEL) may
# provide different sets of partitiion arming states; this dict
# unifies them and translates them to the states our Partitiion device
# supports.
PART_ARM_STATE_MAP = {
    # Original arming code -> Partition device state
    -1: 'unknown', # Internal to plugin
    0: 'zone_test', # 'Zone Test', ARM_LEVEL only
    1: 'ready', # 'Off',
    2: 'stay', # 'Home/Perimeter',
    3: 'away', # 'Away/Full',
    4: 'night', # 'Night', ARM_LEVEL only
    5: 'silent', # 'Silent', ARM_LEVEL only
    8: 'phone_test', # 'Phone Test', PART_DATA only
    9: 'sensor_test', # 'Sensor Test', PART_DATA only
}


# Custom dictionary to give friendly names to zones for display
# Fill in your zone names here
FRIENDLY_ZONE_NAME_MAP = {
    1: "Zone 1",
    2: "Zone 2",
    3: "Zone 3",
    4: "Zone 4",
    5: "Zone 5",
    6: "Zone 6",
    7: "Zone 7",
    8: "Zone 8",
    9: "Zone 9",
    10: "Zone 10",
    11: "Zone 11",
    12: "Zone 12",
    13: "Zone 13",
    14: "Zone 14",
    15: "Zone 15"
}

class Concord4ServerConfig():
    def __init__(self, configfile):

        self._config = ConfigParser.ConfigParser()
        self._config.read(configfile)

        self.SERIALPORT = self.read_config_var('main', 'serialport', '', 'str')
        self.LOGLEVEL = self.read_config_var('main', 'loglevel', '', 'str')
        self.PORT = self.read_config_var('main', 'port', 443, 'int')
        self.USETLS = self.read_config_var('main', 'use_tls', False, 'bool')
        self.CERTFILE = self.read_config_var('main', 'certfile', 'server.crt', 'str')
        self.KEYFILE = self.read_config_var('main', 'keyfile', 'server.key', 'str')
        self.CALLBACKURL_BASE = self.read_config_var('main', 'callbackurl_base', '', 'str')
        self.CALLBACKURL_APP_ID = self.read_config_var('main', 'callbackurl_app_id', '', 'str')
        self.CALLBACKURL_ACCESS_TOKEN = self.read_config_var('main', 'callbackurl_access_token', '', 'str')
        self.CALLBACKURL_CONCORD_DEVICE_ID = self.read_config_var('main', 'callbackurl_concord_device_id', '', 'str')

        self.RESTAPIPW = self.read_config_var('main', 'rest_api_auth_password', '', 'str')


    def defaulting(self, section, variable, default, quiet = False):
        if quiet == False:
            print('Config option '+ str(variable) + ' not set in ['+str(section)+'] defaulting to: \''+str(default)+'\'')

    def read_config_var(self, section, variable, default, type = 'str', quiet = False):
        try:
            if type == 'str':
                return self._config.get(section,variable)
            elif type == 'bool':
                return self._config.getboolean(section,variable)
            elif type == 'int':
                return int(self._config.get(section,variable))
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            self.defaulting(section, variable, default, quiet)
            return default
    def read_config_sec(self, section):
        try:
            return self._config._sections[section]
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            return {}


class ConcordSvr(object):

    def __init__(self):
        self.panel = None
        self.panelDev = None
        self.panelInitialQueryDone = False
        self.StopThread = False
        self.armed = False
        self.event_send_time = int(time.time())
        self.serialPortUrl = config.SERIALPORT

        # Zones are keyed by (partitition number, zone number)
        self.zones = { } # zone key -> dict of zone info, i.e. output of cmd_zone_data
        self.zoneDevs = { } # zone key -> active Indigo zone device
        self.zoneKeysById = { } # zone device ID -> zone key

        # Partitions are keyed by partition number
        self.parts = { } # partition number -> partition info
        self.partDevs = { } # partition number -> active Indigo partition device
        self.partKeysById = { } # partition device ID -> partition number
        
        # Touchpads don't actually have any of their own internal
        # data; they just mirror their configured partition.  To aid
        # that, we will attach touchpad display information to the
        # internal partition state.
        self.touchpadDevs = { } # partition number -> (touchpad device ID -> Indigo touchpad device)

        # We maintain a regular event log, and an 'error' event log
        # with only exception-type information.  Each has an
        # associated number of days for which it retains events (from
        # oldest to most recent event in log).
        #
        # These are logs of events kept internally as
        # opposed to the log messages which are printed
        # and controlled by the 'log level'
        self.eventLog = deque()
        self.errLog = deque()
        self.eventLogDays = 0
        self.errLogDays = 0

    #
    # Internal event log
    #
    def _logEvent(self, eventInfo, eventTime, q, maxAge):
        pair = (eventTime, eventInfo)
        q.append(pair)
        while len(q) > 0:
            dt = eventTime - q[0][0]
            if dt.days > maxAge:
                q.popleft()
            else:
                break

    def logEvent(self, eventInfo, isErr=False):
        event_time = datetime.datetime.now()
        self._logEvent(eventInfo, event_time, self.eventLog, self.eventLogDays)

        # Send an e-mail if we're armed and we have a zone update
        # This would mean the alarm has detected something
        if self.armed and 'zone_name' in eventInfo:
            email_subject = "--- ALARM EVENT: ZONE " + eventInfo['zone_name']
            email_message = "NEW STATE: " + str(eventInfo['zone_state']) + "\nPREVIOUS STATE: " + str(eventInfo['prev_zone_state']) + "\nCOMMAND: " + str(eventInfo['command'] + "\nDATE: " + str(event_time))
            log.info("Sending Email... ")
            log.debug("Email Contents:" + email_subject + "\n" + email_message)
            send_email("my_send_email_as_base_64@gmail.com".decode('base64'), "my_password_as_base_64".decode('base64'), "target_email_as_base_64@somewhere.com".decode('base64'), email_subject, email_message)

        if isErr:
            self._logEvent(eventInfo, event_time, self.errLog, self.errLogDays)

    def logEventZone(self, zoneName, zoneState, prevZoneState, logMessage, cmd, cmdData, isErr=False):
        d = { 'zone_name': zoneName,
              'zone_state': zoneState,
              'prev_zone_state': prevZoneState,
              'message': logMessage,
              'command': cmd,
              'command_data': cmdData }
        self.logEvent(d, isErr)


    def updateStateOnServer(self,item,variable,state):
        log.debug(str(item)+' | '+str(variable)+':'+str(state))
        if 'panel' in item:
            log.info('Panel Information: '+str(variable)+': '+str(state))
        if 'zone' in item:
            pass

    def startup(self):
        try:
            self.panel = concord.AlarmPanelInterface(self.serialPortUrl, 0.5, log)
        except Exception, ex:
            self.updateStateOnServer("panel","state", "faulted")
            log.error("Unable to start alarm panel interface: %s" % str(ex))
            return

        self.updateStateOnServer('panel','panelState', 'connecting')

        # Set the plugin object to handle all incoming commands
        # from the panel via the messageHandler() method.
        self.panel_command_names = { } # code -> display-friendly name
        for code, cmd_info in concord_commands.RX_COMMANDS.iteritems():
            cmd_id, cmd_name = cmd_info[0], cmd_info[1]
            self.panel_command_names[cmd_id] = cmd_name
            self.panel.register_message_handler(cmd_id, self.panelMessageHandler)

        self.refreshPanelState("Concord 4 panel device startup")
        st_request = SmartThingsUpdate('armstatus/disarmed',self,senddelay=0)
        st_request.start()
    def refreshPanelState(self, reason):
        """
        Ask the panel to tell us all about itself.  We do this on
        startup, and when the panel asks us to (e.g. under various
        error conditions, or even just periodically).
        """
        log.info("Querying panel for state (%s)" % reason)
        self.updateStateOnServer("panel","state", "exploring")
        self.panel.request_all_equipment()
        self.panel.request_dynamic_data_refresh()
        self.panelInitialQueryDone = False
        

    def isReadyToArm(self, partition_num=1):
        """ 
        Returns pair: first element is True if it's ok to arm;
        otherwise the first element is False and the second element is
        the (string) reason why it is not possible to arm.
        """
        if self.panel is None:
            return False, "The panel is not active"

        # TODO: check all the zones, etc.
        return True, "Partition ready to arm"

    def send_key_press(self,code=[],partition_num=1):
        try:
            self.panel.send_keypress(code, partition_num)
        except Exception, ex:
            log.error("Problem trying to send key=%s" % \
                                  (str(code)))
            log.error(str(ex))
            return False

    def ArmDisarm(self, action='stay', arm_silent = True, bypasszone='',partition_num=1):
        log.debug("Menu item: Arm/Disarm: %s" % str(action))

        errors = {}

        log.info("Concord4 Arm/Disarm to %s, bypass=%s, silent=%s" % (action, str(bypasszone), str(arm_silent)))

        can_arm, reason = self.isReadyToArm(partition_num)
        can_arm, reason = self.isReadyToArm(partition_num)
        if not can_arm:
            errors['partition'] = reason
            log.error('Panel not ready to arm')

        if self.panel is None:
            errors['partition'] = "The alarm panel is not active"

        if len(errors) > 0:
            return False, errors

        keys = [ ]
        if arm_silent and 'disarm' not in action:
            keys += KEYPRESS_SILENT
        elif arm_silent and 'disarm' in action:
            keys += KEYPRESS_SILENT
            keys += KEYPRESS_ARM_STAY
        if action == 'stay':
            if not arm_silent:
                keys += KEYPRESS_ARM_STAY_LOUD
            else:
                keys += KEYPRESS_ARM_STAY
        elif action == 'away':
            if not arm_silent:
                keys += KEYPRESS_ARM_AWAY_LOUD
            else:
                keys += KEYPRESS_ARM_AWAY
        elif action == 'disarm':
            keys += KEYPRESS_DISARM
        else:
            pass
        if bypasszone:
            keys += KEYPRESS_BYPASS

        try:
            self.panel.send_keypress(keys, partition_num)
        except Exception, ex:
            log.error("Problem trying to arm action=%s, silent=%s, bypass=%s" % \
                                  (action, str(arm_silent), str(bypasszone)))
            log.error(str(ex))
            errors['partition'] = str(ex)
            return False, errors
        
        return True


    def strToCode(self, s):
        if len(s) != 4:
            raise ValueError("Too short, must be 4 characters")
        v = [ ]
        for c in s:
            n = ord(c) - ord('0')
            if n < 0 or n > 9:
                raise ValueError("Non-numeric digit")
            v += [ n ]
        return v


    def getPartitionState(self, part_key):
        #assert part_key in self.parts
        part_data = self.parts[part_key]
        arm_level = part_data.get('arming_level_code', -1)
        part_state = PART_ARM_STATE_MAP.get(arm_level, 'unknown')
        return part_state
    
    def updateTouchpadDeviceState(self, touchpad_dev, part_key):
        if part_key not in self.parts:
            log.debug("Unable to update touchpad device %s - partition %d; no knowledge of that partition" % (touchpad_dev.name, part_key))
            self.updateStateOnServer('touchpad','partitionState', 'unknown')
            self.updateStateOnServer('touchpad','lcdLine1', NO_DATA)
            self.updateStateOnServer('touchpad','lcdLine2', NO_DATA)
            return

        part_data = self.parts[part_key]
        lcd_data = part_data.get('display_text', '%s\n%s' % (NO_DATA, NO_DATA))
        # Throw out the blink information.  Not sure how to handle it.
        lcd_data = lcd_data.replace('<blink>', '')
        lines = lcd_data.split('\n')
        if len(lines) > 0:
            self.updateStateOnServer('touchpad','lcdLine1', lines[0].strip())
        else:
            self.updateStateOnServer('touchpad','lcdLine1', NO_DATA)
        if len(lines) > 1:
            self.updateStateOnServer('touchpad','lcdLine2', lines[1].strip())
        else:
            self.updateStateOnServer('touchpad','lcdLine2', NO_DATA)
        self.updateStateOnServer('touchpad','partitionState', self.getPartitionState(part_key))

    def updatePartitionDeviceState(self, part_dev, part_key):
        if part_key not in self.parts:
            log.debug("Unable to update partition device %s - partition %d; no knowledge of that partition" % (part_dev.name, part_key))
            self.updateStateOnServer('partition','partitionState', 'unknown')
            self.updateStateOnServer('partition','armingUser', '')
            self.updateStateOnServer('partition','features', 'Unknown')
            self.updateStateOnServer('partition','delay', 'Unknown')
            return

        part_state = self.getPartitionState(part_key)
        part_data = self.parts[part_key]
        arm_user  = part_data.get('user_info', 'Unknown User')
        features  = part_data.get('feature_state', ['Unknown'])

        delay_flags = part_data.get('delay_flags')
        if not delay_flags:
            delay_str = "No delay info"
        else:
            delay_str = "%s, %d seconds" % (', '.join(delay_flags), part_data.get('delay_seconds', -1))
        self.updateStateOnServer('partition','partitionState', part_state)
        self.updateStateOnServer('partition','armingUser', arm_user)
        self.updateStateOnServer('partition','features', ', '.join(features))
        self.updateStateOnServer('partition','delay', delay_str)


    # Will be run in the concurrent thread.
    def panelMessageHandler(self, msg):
        """ *msg* is dict with received message from the panel. """
        cmd_id = msg['command_id']

        # Log about the message, but not for the ones we hear all the
        # time.  Chatterbox!
        if cmd_id in ('TOUCHPAD', 'SIREN_SYNC'):
            # These message come all the time so only print about them
            # if the user signed up for extra verbose debug logging.
            log_fn = log.debug
        else:
            log_fn = log.debug
        log_fn("Handling panel message %s, %s" % \
                   (cmd_id, self.panel_command_names.get(cmd_id, 'Unknown')))

        #
        # First set of cases by message to update plugin and device state.
        #
        if cmd_id == 'PANEL_TYPE':
            self.updateStateOnServer('panel','panelType', msg['panel_type'])
            self.updateStateOnServer('panel','panelIsConcord', msg['is_concord'])
            self.updateStateOnServer('panel','panelSerialNumber', msg['serial_number'])
            self.updateStateOnServer('panel','panelHwRev', msg['hardware_revision'])
            self.updateStateOnServer('panel','panelSwRev', msg['software_revision'])
            #self.updateStateOnServer('panel','panelZoneMonitorEnabled', self.zoneMonitorEnabled)
            #self.updateStateOnServer('panel','panelZoneMonitorSendEmail', self.zoneMonitorSendEmail)

        elif cmd_id in ('ZONE_DATA', 'ZONE_STATUS'):
            # First update our internal state about the zone
            zone_num = msg['zone_number']
            part_num = msg['partition_number']
            zk = zone_num
            zone_name = '%d' % zone_num

            old_zone_state = "Not known"
            new_zone_state = msg['zone_state']

            if zk in self.zones:
                log.debug("Updating zone %s with %s message, zone state=%r" % \
                                     (zone_name, cmd_id, msg['zone_state']))
                zone_info = self.zones[zk]
                old_zone_state = zone_info['zone_state']
                zone_info.update(msg)
                del zone_info['command_id']
            else:
                log.debug("Learning new zone %s from %s message, zone_state=%r" % \
                                     (zone_name, cmd_id, msg['zone_state']))
                zone_info = msg.copy()
                del zone_info['command_id']
                self.zones[zk] = zone_info

            # Set zone text to friendly text if none is there
            if not 'zone_text' in zone_info or zone_info['zone_text'] == '':
                zone_info['zone_text'] = FRIENDLY_ZONE_NAME_MAP[zk]

            # Determine the zone name friendly if possible
            if 'zone_text' in msg and msg['zone_text'] != '':
                zone_name = '%s - %r' % (zone_num, msg['zone_text'])
            elif zk in self.zones and self.zones[zk].get('zone_text', '') != '':
                zone_name = '%s - %r' % (zone_num, self.zones[zk]['zone_text'])

            # Next sync up any devices that might be for this
            # zone.
            if len(new_zone_state) == 0:
                zs = 'closed'
                delay = (self.event_send_time - int(time.time()))+1
                if delay < 0:
                    delay = 0
                st_request = SmartThingsUpdate('zone'+str(zone_num)+'/closed',self,senddelay=delay)
                st_request.start()
            elif FAULTED in new_zone_state or TROUBLE in new_zone_state:
                zs = 'faulted'
            elif ALARM in new_zone_state:
                zs = 'alarm'
                st_request = SmartThingsUpdate('zone'+str(zone_num)+'/open',self,senddelay=0)
                st_request.start()
            elif TRIPPED in new_zone_state:
                zs = 'open'
                delay = 0
                zone = 'zone'+str(zone_num)
                if self.armed and (('zone1' in zone) or ('zone2' in zone)):
                    self.event_send_time = int(time.time()) + 30
                    delay = 30
                st_request = SmartThingsUpdate('zone'+str(zone_num)+'/open',self,senddelay=delay)
                st_request.start()
            elif BYPASSED in new_zone_state:
                zs = 'disabled'
            else:
                zs = 'unavailable'

            log.info('Zone '+zone_name + ' | State: '+zs)
            self.updateStateOnServer('zone',str(zone_num),zs)

            # Log to internal event log.  If the zone is changed to or
            # from one of the 'error' states, we will use the error
            # log as well.  We don't normally have to check for change
            # per se, since we know it was a zone change that prompted
            # this message.  However, if a zone is in an error state,
            # we don't want to log an error every time it is change
            # between tripped/not-tripped.
            use_err_log = (isZoneErrState(old_zone_state) or isZoneErrState(new_zone_state)) \
                and zoneStateChangedExceptTripped(old_zone_state, new_zone_state)
            
            self.logEventZone(zone_name, new_zone_state, old_zone_state,
                              "Zone update message", cmd_id, msg, use_err_log)

        elif cmd_id in ('ARM_LEVEL'):
            if int(msg['arming_level_code']) == 1:
                log.info('System is DISARMED')
                self.armed = False
                self.updateStateOnServer('armstatus','arm_level','disarmed')
                st_request = SmartThingsUpdate('armstatus/disarmed',self,senddelay=0)
                st_request.start()
            elif int(msg['arming_level_code']) == 2:
                log.info('System is ARMED to STAY')
                self.armed = True
                self.updateStateOnServer('armstatus','arm_level','armed_stay')
                delay = (self.event_send_time - int(time.time()))+1
                if delay < 0:
                    delay = 0
                st_request = SmartThingsUpdate('armstatus/armed_stay',self,senddelay=delay)
                st_request.start()
            elif int(msg['arming_level_code']) == 3:
                log.info('System is ARMED to AWAY')
                self.armed = True
                delay = (self.event_send_time - int(time.time()))+1
                if delay < 0:
                    delay = 0
                self.updateStateOnServer('armstatus','arm_level','armed_away')
                st_request = SmartThingsUpdate('armstatus/armed_away',self,senddelay=delay)
                st_request.start()

        elif cmd_id in ('PART_DATA', 'FEAT_STATE', 'DELAY', 'TOUCHPAD'):
            part_num = msg['partition_number']
            old_part_state = "Unknown"
            if part_num in self.parts:
                old_part_state = self.getPartitionState(part_num)
                # Log informational message about updating the
                # partition with message info.  However, for touchpad
                # messages this could be quite frequent (every minute)
                # so log at a higher level.
                if cmd_id == 'TOUCHPAD':
                    log_fn = log.debug
                else:
                    log_fn = log.info
                log.debug("Updating partition %d with %s message" % (part_num, cmd_id))
                part_info = self.parts[part_num]
                part_info.update(msg)
                del part_info['command_id']
            else:
                log.info("Learning new partition %d from %s message" % (part_num, cmd_id))
                part_info = msg.copy()
                del part_info['command_id']
                self.parts[part_num] = part_info

            if part_num in self.partDevs:
                self.updatePartitionDeviceState(self.partDevs[part_num], part_num)
            else:
                # The panel seems to send touchpad date/time messages
                # for all partitions it supports.  User may not wish
                # to see warnings if they haven't setup the Partition
                # device in Indigo, so log this at a higher level.
                if cmd_id == 'TOUCHPAD':
                    log_fn = log.debug
                else:
                    log_fn = log.warn

            # We update the touchpad even when it's not a TOUCHPAD
            # message so that the touchpad device can track the
            # underlying partition state.  Later on we may also add
            # other features to mirror the LEDs on an actual touchpad
            # as well.
            if part_num in self.touchpadDevs:
                for dev_id, dev in self.touchpadDevs[part_num].iteritems():
                    self.updateTouchpadDeviceState(dev, part_num)

            # Write message to internal log
            if cmd_id in ('PART_DATA', 'ARM_LEVEL', 'DELAY'):
                part_state = self.getPartitionState(part_num)
                use_err_log = cmd_id != 'PART_DATA' or old_part_state != part_state or part_state != 'ready'
                self.logEvent(msg, use_err_log)


        elif cmd_id == 'EQPT_LIST_DONE':
            if not self.panelInitialQueryDone:
                self.updateStateOnServer('panel','state', 'active')
                self.panelInitialQueryDone = True

        elif cmd_id == 'ALARM':
            part_num = msg['partition_number']
            source_type = msg['source_type']
            source_num = msg['source_number']
            alarm_code_str ="%d.%d" % (msg['alarm_general_type_code'], msg['alarm_specific_type_code'])
            alarm_desc = "%s / %s" % (msg['alarm_general_type'], msg['alarm_specific_type'])
            event_data = msg['event_specific_data']

            # We really only care if its of gen type 1 (fire,police, etc)
            if msg['alarm_general_type_code'] == '1':
                zk = (part_num, source_num)
                if source_type == 'Zone' and zk in self.zones:
                    zone_name = self.zones[zk].get('zone_text', 'Unknown')
                    if zk in self.zoneDevs:
                        source_desc = "Zone %d - Zone %s, alarm zone %s" % \
                            (source_num, self.zoneDevs[zk].name, zone_name)
                    else:
                        source_desc = "Zone %d - alarm zone %s" % (source_num, zone_name)
                else:
                    source_desc = "%s, number %d" % (source_type, source_num)
                log.error("ALARM or TROUBLE on partition %d: Source details: %s" % (part_num, source_desc))

                self.updateStateOnServer('panel','state','alarm')


                msg['source_desc'] = source_desc
                self.logEvent(msg, True)

        elif cmd_id in ('CLEAR_IMAGE', 'EVENT_LOST'):
            self.refreshPanelState("Reacting to %s message" % cmd_id)

        else:
            log.debug("Concord: unhandled panel message %s" % cmd_id)



class PanelConcurrentThread(Thread):
    def __init__(self, panel):
        ''' Constructor. '''

        Thread.__init__(self)
        self.panel = panel
        self.StopThread = False
        self.daemon = True

    def run(self):
        try:
            # Run the panel interface event loop.  It's possible for
            # this thread to be running before the panel object is
            # constructed and the serial port is configured.  We have
            # an outer loop because the user may stop the panel device
            # which will cause the panel's message loop to be stopped.
            while True:
                while self.panel is None:
                    time.sleep(1)
                self.panel.message_loop()

        except self.StopThread:
            log.debug("Got StopThread in runConcurrentThread()")
            pass


class HTTPChannel(asynchat.async_chat):
    def __init__(self, server, sock, addr):
        asynchat.async_chat.__init__(self, sock)
        self.server = server
        self.set_terminator("\r\n\r\n")
        self.header = None
        self.data = ""
        self.shutdown = 0

    def collect_incoming_data(self, data):
        self.data = self.data + data
        if len(self.data) > 16384:
        # limit the header size to prevent attacks
            self.shutdown = 1

    def found_terminator(self):
        if not self.header:
            # parse http header
            fp = StringIO.StringIO(self.data)
            request = string.split(fp.readline(), None, 2)
            if len(request) != 3:
                # badly formed request; just shut down
                self.shutdown = 1
            else:
                # parse message header
                self.header = mimetools.Message(fp)
                self.set_terminator("\r\n")
                self.server.handle_request(
                    self, request[0], request[1], self.header
                    )
                self.close_when_done()
            self.data = ""
        else:
            pass # ignore body data, for now

    def pushstatus(self, status, explanation="OK"):
        self.push("HTTP/1.0 %d %s\r\n" % (status, explanation))

    def pushok(self, content):
        self.pushstatus(200, "OK")
        self.push('Content-type: application/json\r\n')
        self.push('Expires: Sat, 26 Jul 1997 05:00:00 GMT\r\n')
        self.push('Last-Modified: '+ datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")+' GMT\r\n')
        self.push('Cache-Control: no-store, no-cache, must-revalidate\r\n' )
        self.push('Cache-Control: post-check=0, pre-check=0\r\n')
        self.push('Pragma: no-cache\r\n' )
        self.push('\r\n')
        self.push(content)

    def pushfile(self, file):
        self.pushstatus(200, "OK")
        extension = os.path.splitext(file)[1]
        if extension == ".html":
            self.push("Content-type: text/html\r\n")
        elif extension == ".js":
            self.push("Content-type: text/javascript\r\n")
        elif extension == ".png":
            self.push("Content-type: image/png\r\n")
        elif extension == ".css":
            self.push("Content-type: text/css\r\n")
        self.push("\r\n")
        self.push_with_producer(push_FileProducer(sys.path[0] + os.sep + 'ext' + os.sep + file))

class push_FileProducer:
    # a producer which reads data from a file object

    def __init__(self, file):
        self.file = open(file, "rb")

    def more(self):
        if self.file:
            data = self.file.read(2048)
            if data:
                return data
            self.file = None
        return ""

class ConcordHTTPServer(asyncore.dispatcher,Thread):

    def __init__(self, config):
        # Call parent class's __init__ method
        asyncore.dispatcher.__init__(self)

        #Store config
        self._config = config

        Thread.__init__(self)
        self.StopThread = False
        self.daemon = True

    def run(self):
        # Create socket and listen on it
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.bind(("", config.PORT))
        self.listen(5)
        logger('Listening for HTTP(S) connections on port: '+str(config.PORT))


    def handle_accept(self):
        # Accept the connection
        conn, addr = self.accept()
        logger('Incoming web connection from %s' % repr(addr))

        try:
            if config.USETLS:
                HTTPChannel(self, ssl.wrap_socket(conn, server_side=True, certfile=config.CERTFILE, keyfile=config.KEYFILE, ssl_version=ssl.PROTOCOL_TLSv1), addr)
            else:
                HTTPChannel(self, conn, addr) #use non ssl
        except ssl.SSLError:
            return

    def handle_request(self, channel, method, request, header):
        st_URL_prefix = config.CALLBACKURL_BASE + "/" + config.CALLBACKURL_APP_ID + "/concord/" + str(config.CALLBACKURL_CONCORD_DEVICE_ID) + "/"
        st_URL_suffix = "?access_token=" + config.CALLBACKURL_ACCESS_TOKEN
        logger('Web request: '+str(method)+' '+str(request))

        query = urlparse.urlparse(request)
        query_array = urlparse.parse_qs(query.query, True)
        path = query.path
        authorized = False
        header_str = str(header)
        userpw = ''
        #check auth
        for line in header_str.splitlines():
            if 'Authorization: Basic' in str(line):
                base64str  = line.split('Authorization: Basic ')[1]
                userpw = base64.b64decode(base64str)
                logger(userpw)
                if config.RESTAPIPW in userpw:
                    authorized = True
        try:
            if '&apiserverurl' in query.path:
                path,base64url = query.path.split('&apiserverurl=')
                url = urllib.unquote(base64url).decode('utf8')
                if url not in config.CALLBACKURL_BASE:
                    url = url.replace('http:','https:')
                    logger('Setting API Base URL To: '+url)
                    config.CALLBACKURL_BASE = url
            if not authorized:
                channel.pushstatus(401, "Unauthorized")
                logger('TX -> 401 Unauthorized (auth key:'+userpw+')')
            elif path == '/':
                channel.pushstatus(404, "Not found")
            elif '/concord/refresh' in path:
                concord_interface.refreshPanelState("Reacting to web poll request...")
                channel.pushok(json.dumps({'response' : 'Refreshing Concord...'}))
            elif '/concord/arm/stay' in path:
                if path.split('/')[-1] == 'loud':
                    concord_interface.ArmDisarm(action='stay',arm_silent=False)
                    channel.pushok(json.dumps({'response' : 'Arming System to STAY (LOUD)...'}))
                else:
                    concord_interface.ArmDisarm(action='stay')
                    channel.pushok(json.dumps({'response' : 'Arming System to STAY...'}))
            elif '/concord/arm/away' in path:
                if path.split('/')[-1] == 'loud':
                    concord_interface.ArmDisarm(action='away',arm_silent=False)
                    channel.pushok(json.dumps({'response' : 'Arming System to AWAY (LOUD)...'}))
                else:
                    concord_interface.ArmDisarm(action='away')
                    channel.pushok(json.dumps({'response' : 'Arming System to AWAY...'}))
            elif '/concord/disarm' in path:
                if path.split('/')[-1] == 'loud':
                    concord_interface.ArmDisarm(action='disarm',arm_silent=False)
                    channel.pushok(json.dumps({'response' : 'Disarm System (LOUD)...'}))
                else:
                    concord_interface.ArmDisarm(action='disarm')
                    channel.pushok(json.dumps({'response' : 'Disarm System...'}))
            elif '/concord/keypress' in path:
                code = path.split('/')[-1]
                concord_interface.send_key_press(key=[hex(int(code))])
                channel.pushok(json.dumps({'response' : 'Sending Keypress...'}))

            else:
                channel.pushstatus(404, "Not found")
                channel.push("Content-type: text/html\r\n")
                channel.push("\r\n")
        except Exception as ex:
            tb = traceback.format_exc()
            logger('HTTP Server Exception: '+ str(ex.message))
            log.debug('TRACEBACK:'+str(tb))

class SmartThingsUpdate(Thread):

    def __init__(self,url,concordSvr,method='get',senddelay=0):
        super(SmartThingsUpdate, self).__init__()
        self.daemon = True
        """Initialize"""
        self.url = url
        self.method = method
        self.senddelay = senddelay
        self.concord_interface = concordSvr
        log.debug('delay:'+str(senddelay))
        log.debug('url:'+self.url)
    def run(self):
        st_URL_prefix = config.CALLBACKURL_BASE + "/" + config.CALLBACKURL_APP_ID + "/concord/" + str(config.CALLBACKURL_CONCORD_DEVICE_ID) + "/"
        headers = {'Authorization': 'Bearer {}'.format(config.CALLBACKURL_ACCESS_TOKEN)}
        try:
            if 'get' in self.method:
                time.sleep(self.senddelay) #dont update smartthings, wait until panel is disarmed
                r = requests.get(st_URL_prefix+self.url,timeout=20,headers=headers)
                logger('TX -> '+st_URL_prefix+self.url)
                if (r.status_code != 200):
                    logger('ST TX Failed: ' + str(r.status_code)+' url:'+self.url)
        except Exception as ex:
            tb = traceback.format_exc()
            logger('ST TX Exception: '+ str(ex.message)+'url:'+self.url)
            log.debug('TRACEBACK:'+str(tb))

if __name__ == '__main__':
    args = sys.argv[1:]
    print('Concord 4 Automation Server v' +str(version))
    config = Concord4ServerConfig('concordsvr.conf')
    start_logger()
    concord_interface = ConcordSvr()
    concord_interface.startup()
    http_svr = ConcordHTTPServer(config)
    http_svr.start()
    concord_panel_thread = PanelConcurrentThread(concord_interface.panel)
    concord_panel_thread.start()
    try:
        while True:
            asyncore.loop(timeout=2, count=1)
            # insert scheduling code here.
    except KeyboardInterrupt:
        print "Crtl+C pressed. Shutting down."
        logger('Shutting down from Ctrl+C')
        #http_svr.shutdown(socket.SHUT_RDWR)
        http_svr.close()
        concord_panel_thread.panel = None
        concord_panel_thread.StopThread = True
        sys.exit()
