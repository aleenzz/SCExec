#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# ATSVC example for some functions implemented, creates, enums, runs, delete jobs
# This example executes a command on the target machine through the Task Scheduler 
# service. Returns the output of such command
#
# Author:
#  Alberto Solino (@agsolino)
#
# Reference for:
#  DCE/RPC for TSCH
from __future__ import division
from __future__ import print_function
import string
import sys
import argparse
import time
import random
import base64
import logging
import re

from impacket.examples import logger
from impacket import version
from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, \
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.krb5.keytab import Keytab
from six import PY2
from impacket.dcerpc.v5.epm import hept_map
from impacket.uuid import uuidtup_to_bin

CODEC = sys.stdout.encoding

class TSCH_EXEC:
    def __init__(self, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None,
                 command=None, sessionId=None):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__command = command
        self.sessionId = sessionId

        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def play(self, addr):
        stringbinding = hept_map(addr,uuidtup_to_bin(('86D35949-83C9-4044-B424-DB363231FD0C','1.0')),protocol='ncacn_ip_tcp')
        rpctransport = transport.DCERPCTransportFactory(stringbinding)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                         self.__aesKey)
            rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)
        try:
            self.doStuff(rpctransport)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)
            if str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') >=0:
                logging.info('When STATUS_OBJECT_NAME_NOT_FOUND is received, try running again. It might work')

    def doStuff(self, rpctransport):
        def output_callback(data):
            try:
                print(data.decode(CODEC))
            except UnicodeDecodeError:
                logging.error('Decoding error detected, consider running chcp.com at the target,\nmap the result with '
                              'https://docs.python.org/3/library/codecs.html#standard-encodings\nand then execute atexec.py '
                              'again with -codec and the corresponding codec')
                print(data.decode(CODEC, errors='replace'))

        def xml_escape(data):
            replace_table = {
                 "&": "&amp;",
                 '"': "&quot;",
                 "'": "&apos;",
                 ">": "&gt;",
                 "<": "&lt;",
                 }
            return ''.join(replace_table.get(c, c) for c in data)

        def cmd_split(cmdline):
            cmdline = cmdline.split(" ", 1)
            cmd = cmdline[0]
            args = cmdline[1] if len(cmdline) > 1 else ''

            return [cmd, args]

        dce = rpctransport.get_dce_rpc()

        dce.set_credentials(*rpctransport.get_credentials())
        if self.__doKerberos is True:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.connect()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(tsch.MSRPC_UUID_TSCHS)
        tmpName = ''.join([random.choice(string.ascii_letters) for _ in range(8)])
        tmpFileName = tmpName + '.tmp'
        ps_script = f"$task=Get-ScheduledTask -TaskName \"{tmpName}\" -TaskPath \\;$task.Description=(iex $task.Description|out-string);Set-ScheduledTask $task;[Environment]::Exit(0)"
        encoded_ps_script = base64.b64encode(ps_script.encode('utf-16le')).decode('ascii')
        args = self.__command
        xml = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>%s</Description>
  </RegistrationInfo>
  <Triggers />
  <Principals>
    <Principal id="Author">
      <UserId>SYSTEM</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <UseUnifiedSchedulingEngine>false</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NonInteractive -Enc "%s"</Arguments>
    </Exec>
  </Actions>
</Task>""" % (xml_escape(args), xml_escape(encoded_ps_script))
        taskCreated = False
        try:
            logging.info('Creating task \\%s' % tmpName)
            tsch.hSchRpcRegisterTask(dce, '\\%s' % tmpName, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
            taskCreated = True

            logging.info('Running task \\%s' % tmpName)
            done = False

            if self.sessionId is None:
                tsch.hSchRpcRun(dce, '\\%s' % tmpName)
            else:
                try:
                    tsch.hSchRpcRun(dce, '\\%s' % tmpName, flags=tsch.TASK_RUN_USE_SESSION_ID, sessionId=self.sessionId)
                except Exception as e:
                    if str(e).find('ERROR_FILE_NOT_FOUND') >= 0 or str(e).find('E_INVALIDARG') >= 0 :
                        logging.info('The specified session doesn\'t exist!')
                        done = True
                    else:
                        raise

            while not done:
                logging.debug('Calling SchRpcGetLastRunInfo for \\%s' % tmpName)
                resultRetrieveTask = tsch.hSchRpcRetrieveTask(dce,'\\%s'%tmpName)
                resp = tsch.hSchRpcGetLastRunInfo(dce, '\\%s' % tmpName)
                if resp['pLastRuntime']['wYear'] != 0 and resp['pLastReturnCode'] == 0:
                    done = True
                else:
                    time.sleep(2)
            logging.info('Deleting task \\%s' % tmpName)
            tsch.hSchRpcDelete(dce, '\\%s' % tmpName)
            taskCreated = False
            resultXML = resultRetrieveTask['pXml']
            if "Description" not in resultXML:
                logging.info("None")
                return False
            start = resultXML.find("<Description>") + len("<Description>")
            end = resultXML.find("</Description>")
            result = resultXML[start:end]
            logging.info("\n"+result)
        except tsch.DCERPCSessionError as e:
            logging.error(e)
            e.get_packet().dump()
        finally:
            if taskCreated is True:
                tsch.hSchRpcDelete(dce, '\\%s' % tmpName)

        if self.sessionId is not None:
            dce.disconnect()
            return
# Process command-line arguments.
if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('command', action='store', nargs='*', default=' ', help='command to execute at the target ')
    parser.add_argument('-session-id', action='store', type=int, help='an existed logon session to use (no output, no cmd.exe)')

    parser.add_argument('-ts', action='store_true', help='adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-codec', action='store', help='Sets encoding used (codec) from the target\'s output (default '
                                                       '"%s"). If errors are detected, run chcp.com at the target, '
                                                       'map the result with '
                          'https://docs.python.org/3/library/codecs.html#standard-encodings and then execute wmiexec.py '
                          'again with -codec and the corresponding codec ' % CODEC)

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. '
                                         'If omitted it will use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.codec is not None:
        CODEC = options.codec
    else:
        if CODEC is None:
            CODEC = 'utf-8'

    logging.warning("This will work ONLY on Windows >= Vista")

    if ''.join(options.command) == ' ':
        logging.error('You need to specify a command to execute!')
        sys.exit(1)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    import re

    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    #In case the password contains '@'
    if '@' in address:
        password = password + '@' + address.rpartition('@')[0]
        address = address.rpartition('@')[2]

    if domain is None:
        domain = ''

    if options.keytab is not None:
        Keytab.loadKeysFromKeytab (options.keytab, username, domain, options)
        options.k = True

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass

        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    atsvc_exec = TSCH_EXEC(username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip,
                           ' '.join(options.command), options.session_id)
    atsvc_exec.play(address)
