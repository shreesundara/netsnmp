import sys
import ast
import json
import os
import subprocess
from time import strptime, strftime
from keyword import iskeyword
from pysmi.mibinfo import MibInfo
from pysmi.codegen.base import AbstractCodeGen
from pysmi import error
from pysmi import debug

if sys.version_info[0] > 2:
    unicode = str
    long = int
    def dorepr(s): return repr(s)
else:
    def dorepr(s): return repr(s.encode('utf-8')).decode('utf-8')

# default pysnmp MIB packages
defaultMibPackages = ('pysnmp.smi.mibs', 'pysnmp_mibs')

# never compile these, they either:
# - define MACROs (implementation supplies them)
# - or carry conflicting OIDs (so that all IMPORT's of them will be rewritten)
# - or have manual fixes
# - or import base ASN.1 types from implementation-specific MIBs
fakeMibs = ('ASN1',
            'ASN1-ENUMERATION',
            'ASN1-REFINEMENT')
baseMibs = fakeMibs + \
           ('RFC1065-SMI',
            'RFC1155-SMI',
            'RFC1158-MIB',
            'RFC-1212',
            'RFC1213-MIB',
            'RFC-1215',
            'SNMPv2-SMI',
            'SNMPv2-TC',
            'SNMPv2-TM',
            'SNMPv2-CONF',
            'SNMP-FRAMEWORK-MIB',
            'SNMP-TARGET-MIB',
            'TRANSPORT-ADDRESS-MIB')

class ClangFormat():
    """Holds the clang-format subprocess for formatting the generated code"""
    def __init__(self, path=None,dstPath=None):
        if not path:
            path = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../clang-format')
            if not os.path.exists(path):
                path = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.abspath('clang-format.exe'))
                if not os.path.exists(path):
                    raise Exception('Could not find clang-format')
        elif not os.path.exists(path):
            raise Exception('Could not find clang-format')
        self.clangPath = path
        if not dstPath:
            dstPath = os.getcwd()
        else:
            self.dstPath = dstPath

    def format(self, codeFile):
        codeFile = os.path.join(self.dstPath,codeFile)
        cmd = '\"'+ self.clangPath+'\" -style="{IndentWidth: 4, SortIncludes: false}" -i \"' +codeFile+ "\""
        print cmd
        process = subprocess.Popen([cmd],stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
        # process = subprocess.Popen([self.clangPath + ' -style=\'{IndentWidth: 4, SortIncludes: false}\' ' + codeFile],stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
        process.poll
        stdout, stderr = process.communicate()
        if stderr != '':
            #print stderr
            return ''
        return stdout

class NetSnmpCodeGen(AbstractCodeGen):
    """Builds PySNMP-specific Python code representing MIB module supplied
       in form of an Abstract Syntax Tree on input.

       Instance of this class is supposed to be passed to *MibCompiler*,
       the rest is internal to *MibCompiler*.
    """
    symsTable = {
      'MODULE-IDENTITY': ('ModuleIdentity',),
      'OBJECT-TYPE': ('MibScalar', 'MibTable', 'MibTableRow', 'MibTableColumn'),
      'NOTIFICATION-TYPE': ('NotificationType',),
      'TEXTUAL-CONVENTION': ('TextualConvention',),
      'MODULE-COMPLIANCE': ('ModuleCompliance',),
      'OBJECT-GROUP': ('ObjectGroup',),
      'NOTIFICATION-GROUP': ('NotificationGroup',),
      'AGENT-CAPABILITIES': ('AgentCapabilities',),
      'OBJECT-IDENTITY': ('ObjectIdentity',),
      'TRAP-TYPE': ('NotificationType',),  # smidump always uses NotificationType
      'BITS': ('Bits',),
    }

    constImports = {
      'ASN1': ('Integer', 'OctetString', 'ObjectIdentifier'),
      'ASN1-ENUMERATION': ('NamedValues',),
      'ASN1-REFINEMENT': ('ConstraintsUnion', 'ConstraintsIntersection', 'SingleValueConstraint', 'ValueRangeConstraint', 'ValueSizeConstraint'),
      'SNMPv2-SMI': ('iso',
                     'Bits', # XXX
                     'Integer32', # XXX
                     'TimeTicks', # bug in some IETF MIBs
                     'Counter32', # bug in some IETF MIBs (e.g.  DSA-MIB)
                     'Counter64', # bug in some MIBs (e.g.A3COM-HUAWEI-LswINF-MIB)
                     'NOTIFICATION-TYPE', # bug in some MIBs (e.g.  A3COM-HUAWEI-DHCPSNOOP-MIB)
                     'Gauge32', # bug in some IETF MIBs (e.g.  DSA-MIB)
                     'MODULE-IDENTITY', 'OBJECT-TYPE', 'OBJECT-IDENTITY', 'Unsigned32', 'IpAddress', # XXX
                     'MibIdentifier'), # OBJECT IDENTIFIER
      'SNMPv2-TC': ('DisplayString', 'TimeStamp', 'TruthValue', 'TEXTUAL-CONVENTION',), # XXX
      'SNMPv2-CONF': ('MODULE-COMPLIANCE', 'NOTIFICATION-GROUP',), # XXX
    }

    baseTypes = ['Integer', 'Integer32', 'Bits', 'ObjectIdentifier', 'OctetString']
    updateDict = lambda x, newitems: x.update(newitems) or x

    commonSyms = {'RFC1155-SMI/RFC1065-SMI':
                     {'internet': [('SNMPv2-SMI', 'internet')],
                      'directory': [('SNMPv2-SMI', 'directory')],
                      'mgmt': [('SNMPv2-SMI', 'mgmt')],
                      'experimental': [('SNMPv2-SMI', 'experimental')],
                      'private': [('SNMPv2-SMI', 'private')],
                      'enterprises': [('SNMPv2-SMI', 'enterprises')],
                      'OBJECT-TYPE': [('SNMPv2-SMI', 'OBJECT-TYPE')],
                      'ObjectName': [('SNMPv2-SMI', 'ObjectName')],
                      'ObjectSyntax': [('SNMPv2-SMI', 'ObjectSyntax')],
                      'SimpleSyntax': [('SNMPv2-SMI', 'SimpleSyntax')],
                      'ApplicationSyntax': [('SNMPv2-SMI', 'ApplicationSyntax')],
                      'NetworkAddress': [('SNMPv2-SMI', 'IpAddress')],
                      'IpAddress': [('SNMPv2-SMI', 'IpAddress')],
                      'Counter': [('SNMPv2-SMI', 'Counter32')],
                      'Gauge': [('SNMPv2-SMI', 'Gauge32')],
                      'TimeTicks': [('SNMPv2-SMI', 'TimeTicks')],
                      'Opaque': [('SNMPv2-SMI', 'Opaque')]},
                   'RFC1158-MIB/RFC1213-MIB':
                     {'mib-2': [('SNMPv2-SMI', 'mib-2')],
                      'DisplayString': [('SNMPv2-TC', 'DisplayString')],
                      'system': [('SNMPv2-MIB', 'system')],
                      'interfaces': [('IF-MIB', 'interfaces')],
                      'ip': [('IP-MIB', 'ip')],
                      'icmp': [('IP-MIB', 'icmp')],
                      'tcp': [('TCP-MIB', 'tcp')],
                      'udp': [('UDP-MIB', 'udp')],
                      'transmission': [('SNMPv2-SMI', 'transmission')],
                      'snmp': [('SNMPv2-MIB', 'snmp')],
                      'sysDescr': [('SNMPv2-MIB', 'sysDescr')],
                      'sysObjectID': [('SNMPv2-MIB', 'sysObjectID')],
                      'sysUpTime': [('SNMPv2-MIB', 'sysUpTime')],
                      'sysContact': [('SNMPv2-MIB', 'sysContact')],
                      'sysName': [('SNMPv2-MIB', 'sysName')],
                      'sysLocation': [('SNMPv2-MIB', 'sysLocation')],
                      'sysServices': [('SNMPv2-MIB', 'sysServices')],
                      'ifNumber': [('IF-MIB', 'ifNumber')],
                      'ifTable': [('IF-MIB', 'ifTable')],
                      'ifEntry': [('IF-MIB', 'ifEntry')],
                      'ifIndex': [('IF-MIB', 'ifIndex')],
                      'ifDescr': [('IF-MIB', 'ifDescr')],
                      'ifType': [('IF-MIB', 'ifType')],
                      'ifMtu': [('IF-MIB', 'ifMtu')],
                      'ifSpeed': [('IF-MIB', 'ifSpeed')],
                      'ifPhysAddress': [('IF-MIB', 'ifPhysAddress')],
                      'ifAdminStatus': [('IF-MIB', 'ifAdminStatus')],
                      'ifOperStatus': [('IF-MIB', 'ifOperStatus')],
                      'ifLastChange': [('IF-MIB', 'ifLastChange')],
                      'ifInOctets': [('IF-MIB', 'ifInOctets')],
                      'ifInUcastPkts': [('IF-MIB', 'ifInUcastPkts')],
                      'ifInNUcastPkts': [('IF-MIB', 'ifInNUcastPkts')],
                      'ifInDiscards': [('IF-MIB', 'ifInDiscards')],
                      'ifInErrors': [('IF-MIB', 'ifInErrors')],
                      'ifInUnknownProtos': [('IF-MIB', 'ifInUnknownProtos')],
                      'ifOutOctets': [('IF-MIB', 'ifOutOctets')],
                      'ifOutUcastPkts': [('IF-MIB', 'ifOutUcastPkts')],
                      'ifOutNUcastPkts': [('IF-MIB', 'ifOutNUcastPkts')],
                      'ifOutDiscards': [('IF-MIB', 'ifOutDiscards')],
                      'ifOutErrors': [('IF-MIB', 'ifOutErrors')],
                      'ifOutQLen': [('IF-MIB', 'ifOutQLen')],
                      'ifSpecific': [('IF-MIB', 'ifSpecific')],
                      'ipForwarding': [('IP-MIB', 'ipForwarding')],
                      'ipDefaultTTL': [('IP-MIB', 'ipDefaultTTL')],
                      'ipInReceives': [('IP-MIB', 'ipInReceives')],
                      'ipInHdrErrors': [('IP-MIB', 'ipInHdrErrors')],
                      'ipInAddrErrors': [('IP-MIB', 'ipInAddrErrors')],
                      'ipForwDatagrams': [('IP-MIB', 'ipForwDatagrams')],
                      'ipInUnknownProtos': [('IP-MIB', 'ipInUnknownProtos')],
                      'ipInDiscards': [('IP-MIB', 'ipInDiscards')],
                      'ipInDelivers': [('IP-MIB', 'ipInDelivers')],
                      'ipOutRequests': [('IP-MIB', 'ipOutRequests')],
                      'ipOutDiscards': [('IP-MIB', 'ipOutDiscards')],
                      'ipOutNoRoutes': [('IP-MIB', 'ipOutNoRoutes')],
                      'ipReasmTimeout': [('IP-MIB', 'ipReasmTimeout')],
                      'ipReasmReqds': [('IP-MIB', 'ipReasmReqds')],
                      'ipReasmOKs': [('IP-MIB', 'ipReasmOKs')],
                      'ipReasmFails': [('IP-MIB', 'ipReasmFails')],
                      'ipFragOKs': [('IP-MIB', 'ipFragOKs')],
                      'ipFragFails': [('IP-MIB', 'ipFragFails')],
                      'ipFragCreates': [('IP-MIB', 'ipFragCreates')],
                      'ipAddrTable': [('IP-MIB', 'ipAddrTable')],
                      'ipAddrEntry': [('IP-MIB', 'ipAddrEntry')],
                      'ipAdEntAddr': [('IP-MIB', 'ipAdEntAddr')],
                      'ipAdEntIfIndex': [('IP-MIB', 'ipAdEntIfIndex')],
                      'ipAdEntNetMask': [('IP-MIB', 'ipAdEntNetMask')],
                      'ipAdEntBcastAddr': [('IP-MIB', 'ipAdEntBcastAddr')],
                      'ipAdEntReasmMaxSize': [('IP-MIB', 'ipAdEntReasmMaxSize')],
                      'ipNetToMediaTable': [('IP-MIB', 'ipNetToMediaTable')],
                      'ipNetToMediaEntry': [('IP-MIB', 'ipNetToMediaEntry')],
                      'ipNetToMediaIfIndex': [('IP-MIB', 'ipNetToMediaIfIndex')],
                      'ipNetToMediaPhysAddress': [('IP-MIB', 'ipNetToMediaPhysAddress')],
                      'ipNetToMediaNetAddress': [('IP-MIB', 'ipNetToMediaNetAddress')],
                      'ipNetToMediaType': [('IP-MIB', 'ipNetToMediaType')],
                      'icmpInMsgs': [('IP-MIB', 'icmpInMsgs')],
                      'icmpInErrors': [('IP-MIB', 'icmpInErrors')],
                      'icmpInDestUnreachs': [('IP-MIB', 'icmpInDestUnreachs')],
                      'icmpInTimeExcds': [('IP-MIB', 'icmpInTimeExcds')],
                      'icmpInParmProbs': [('IP-MIB', 'icmpInParmProbs')],
                      'icmpInSrcQuenchs': [('IP-MIB', 'icmpInSrcQuenchs')],
                      'icmpInRedirects': [('IP-MIB', 'icmpInRedirects')],
                      'icmpInEchos': [('IP-MIB', 'icmpInEchos')],
                      'icmpInEchoReps': [('IP-MIB', 'icmpInEchoReps')],
                      'icmpInTimestamps': [('IP-MIB', 'icmpInTimestamps')],
                      'icmpInTimestampReps': [('IP-MIB', 'icmpInTimestampReps')],
                      'icmpInAddrMasks': [('IP-MIB', 'icmpInAddrMasks')],
                      'icmpInAddrMaskReps': [('IP-MIB', 'icmpInAddrMaskReps')],
                      'icmpOutMsgs': [('IP-MIB', 'icmpOutMsgs')],
                      'icmpOutErrors': [('IP-MIB', 'icmpOutErrors')],
                      'icmpOutDestUnreachs': [('IP-MIB', 'icmpOutDestUnreachs')],
                      'icmpOutTimeExcds': [('IP-MIB', 'icmpOutTimeExcds')],
                      'icmpOutParmProbs': [('IP-MIB', 'icmpOutParmProbs')],
                      'icmpOutSrcQuenchs': [('IP-MIB', 'icmpOutSrcQuenchs')],
                      'icmpOutRedirects': [('IP-MIB', 'icmpOutRedirects')],
                      'icmpOutEchos': [('IP-MIB', 'icmpOutEchos')],
                      'icmpOutEchoReps': [('IP-MIB', 'icmpOutEchoReps')],
                      'icmpOutTimestamps': [('IP-MIB', 'icmpOutTimestamps')],
                      'icmpOutTimestampReps': [('IP-MIB', 'icmpOutTimestampReps')],
                      'icmpOutAddrMasks': [('IP-MIB', 'icmpOutAddrMasks')],
                      'icmpOutAddrMaskReps': [('IP-MIB', 'icmpOutAddrMaskReps')],
                      'tcpRtoAlgorithm': [('TCP-MIB', 'tcpRtoAlgorithm')],
                      'tcpRtoMin': [('TCP-MIB', 'tcpRtoMin')],
                      'tcpRtoMax': [('TCP-MIB', 'tcpRtoMax')],
                      'tcpMaxConn': [('TCP-MIB', 'tcpMaxConn')],
                      'tcpActiveOpens': [('TCP-MIB', 'tcpActiveOpens')],
                      'tcpPassiveOpens': [('TCP-MIB', 'tcpPassiveOpens')],
                      'tcpAttemptFails': [('TCP-MIB', 'tcpAttemptFails')],
                      'tcpEstabResets': [('TCP-MIB', 'tcpEstabResets')],
                      'tcpCurrEstab': [('TCP-MIB', 'tcpCurrEstab')],
                      'tcpInSegs': [('TCP-MIB', 'tcpInSegs')],
                      'tcpOutSegs': [('TCP-MIB', 'tcpOutSegs')],
                      'tcpRetransSegs': [('TCP-MIB', 'tcpRetransSegs')],
                      'tcpConnTable': [('TCP-MIB', 'tcpConnTable')],
                      'tcpConnEntry': [('TCP-MIB', 'tcpConnEntry')],
                      'tcpConnState': [('TCP-MIB', 'tcpConnState')],
                      'tcpConnLocalAddress': [('TCP-MIB', 'tcpConnLocalAddress')],
                      'tcpConnLocalPort': [('TCP-MIB', 'tcpConnLocalPort')],
                      'tcpConnRemAddress': [('TCP-MIB', 'tcpConnRemAddress')],
                      'tcpConnRemPort': [('TCP-MIB', 'tcpConnRemPort')],
                      'tcpInErrs': [('TCP-MIB', 'tcpInErrs')],
                      'tcpOutRsts': [('TCP-MIB', 'tcpOutRsts')],
                      'udpInDatagrams': [('UDP-MIB', 'udpInDatagrams')],
                      'udpNoPorts': [('UDP-MIB', 'udpNoPorts')],
                      'udpInErrors': [('UDP-MIB', 'udpInErrors')],
                      'udpOutDatagrams': [('UDP-MIB', 'udpOutDatagrams')],
                      'udpTable': [('UDP-MIB', 'udpTable')],
                      'udpEntry': [('UDP-MIB', 'udpEntry')],
                      'udpLocalAddress': [('UDP-MIB', 'udpLocalAddress')],
                      'udpLocalPort': [('UDP-MIB', 'udpLocalPort')],
                      'snmpInPkts': [('SNMPv2-MIB', 'snmpInPkts')],
                      'snmpOutPkts': [('SNMPv2-MIB', 'snmpOutPkts')],
                      'snmpInBadVersions': [('SNMPv2-MIB', 'snmpInBadVersions')],
                      'snmpInBadCommunityNames': [('SNMPv2-MIB', 'snmpInBadCommunityNames')],
                      'snmpInBadCommunityUses': [('SNMPv2-MIB', 'snmpInBadCommunityUses')],
                      'snmpInASNParseErrs': [('SNMPv2-MIB', 'snmpInASNParseErrs')],
                      'snmpInTooBigs': [('SNMPv2-MIB', 'snmpInTooBigs')],
                      'snmpInNoSuchNames': [('SNMPv2-MIB', 'snmpInNoSuchNames')],
                      'snmpInBadValues': [('SNMPv2-MIB', 'snmpInBadValues')],
                      'snmpInReadOnlys': [('SNMPv2-MIB', 'snmpInReadOnlys')],
                      'snmpInGenErrs': [('SNMPv2-MIB', 'snmpInGenErrs')],
                      'snmpInTotalReqVars': [('SNMPv2-MIB', 'snmpInTotalReqVars')],
                      'snmpInTotalSetVars': [('SNMPv2-MIB', 'snmpInTotalSetVars')],
                      'snmpInGetRequests': [('SNMPv2-MIB', 'snmpInGetRequests')],
                      'snmpInGetNexts': [('SNMPv2-MIB', 'snmpInGetNexts')],
                      'snmpInSetRequests': [('SNMPv2-MIB', 'snmpInSetRequests')],
                      'snmpInGetResponses': [('SNMPv2-MIB', 'snmpInGetResponses')],
                      'snmpInTraps': [('SNMPv2-MIB', 'snmpInTraps')],
                      'snmpOutTooBigs': [('SNMPv2-MIB', 'snmpOutTooBigs')],
                      'snmpOutNoSuchNames': [('SNMPv2-MIB', 'snmpOutNoSuchNames')],
                      'snmpOutBadValues': [('SNMPv2-MIB', 'snmpOutBadValues')],
                      'snmpOutGenErrs': [('SNMPv2-MIB', 'snmpOutGenErrs')],
                      'snmpOutGetRequests': [('SNMPv2-MIB', 'snmpOutGetRequests')],
                      'snmpOutGetNexts': [('SNMPv2-MIB', 'snmpOutGetNexts')],
                      'snmpOutSetRequests': [('SNMPv2-MIB', 'snmpOutSetRequests')],
                      'snmpOutGetResponses': [('SNMPv2-MIB', 'snmpOutGetResponses')],
                      'snmpOutTraps': [('SNMPv2-MIB', 'snmpOutTraps')],
                      'snmpEnableAuthenTraps': [('SNMPv2-MIB', 'snmpEnableAuthenTraps')]}
    }

    convertImportv2 = {
      'RFC1065-SMI': commonSyms['RFC1155-SMI/RFC1065-SMI'],
      'RFC1155-SMI': commonSyms['RFC1155-SMI/RFC1065-SMI'],
      'RFC1158-MIB': updateDict(dict(commonSyms['RFC1155-SMI/RFC1065-SMI']),
                       (('nullSpecific', [('SNMPv2-SMI', 'zeroDotZero')]),
                        ('ipRoutingTable', [('RFC1213-MIB', 'ipRouteTable')]),
                        ('ipRouteEntry', [('RFC1213-MIB', 'ipRouteEntry')]),
                        ('ipRouteDest', [('RFC1213-MIB', 'ipRouteDest')]),
                        ('ipRouteIfIndex', [('RFC1213-MIB', 'ipRouteIfIndex')]),
                        ('ipRouteMetric1', [('RFC1213-MIB', 'ipRouteMetric1')]),
                        ('ipRouteMetric2', [('RFC1213-MIB', 'ipRouteMetric2')]),
                        ('ipRouteMetric3', [('RFC1213-MIB', 'ipRouteMetric3')]),
                        ('ipRouteMetric4', [('RFC1213-MIB', 'ipRouteMetric4')]),
                        ('ipRouteNextHop', [('RFC1213-MIB', 'ipRouteNextHop')]),
                        ('ipRouteType', [('RFC1213-MIB', 'ipRouteType')]),
                        ('ipRouteProto', [('RFC1213-MIB', 'ipRouteProto')]),
                        ('ipRouteAge', [('RFC1213-MIB', 'ipRouteAge')]),
                        ('ipRouteMask', [('RFC1213-MIB', 'ipRouteMask')]),
                        ('egpInMsgs', [('RFC1213-MIB', 'egpInMsgs')]),
                        ('egpInErrors', [('RFC1213-MIB', 'egpInErrors')]),
                        ('egpOutMsgs', [('RFC1213-MIB', 'egpOutMsgs')]),
                        ('egpOutErrors', [('RFC1213-MIB', 'egpOutErrors')]),
                        ('egpNeighTable', [('RFC1213-MIB', 'egpNeighTable')]),
                        ('egpNeighEntry', [('RFC1213-MIB', 'egpNeighEntry')]),
                        ('egpNeighState', [('RFC1213-MIB', 'egpNeighState')]),
                        ('egpNeighAddr', [('RFC1213-MIB', 'egpNeighAddr')]),
                        ('egpNeighAs', [('RFC1213-MIB', 'egpNeighAs')]),
                        ('egpNeighInMsgs', [('RFC1213-MIB', 'egpNeighInMsgs')]),
                        ('egpNeighInErrs', [('RFC1213-MIB', 'egpNeighInErrs')]),
                        ('egpNeighOutMsgs', [('RFC1213-MIB', 'egpNeighOutMsgs')]),
                        ('egpNeighOutErrs', [('RFC1213-MIB', 'egpNeighOutErrs')]),
                        ('egpNeighInErrMsgs', [('RFC1213-MIB', 'egpNeighInErrMsgs')]),
                        ('egpNeighOutErrMsgs', [('RFC1213-MIB', 'egpNeighOutErrMsgs')]),
                        ('egpNeighStateUps', [('RFC1213-MIB', 'egpNeighStateUps')]),
                        ('egpNeighStateDowns', [('RFC1213-MIB', 'egpNeighStateDowns')]),
                        ('egpNeighIntervalHello', [('RFC1213-MIB', 'egpNeighIntervalHello')]),
                        ('egpNeighIntervalPoll', [('RFC1213-MIB', 'egpNeighIntervalPoll')]),
                        ('egpNeighMode', [('RFC1213-MIB', 'egpNeighMode')]),
                        ('egpNeighEventTrigger', [('RFC1213-MIB', 'egpNeighEventTrigger')]),
                        ('egpAs', [('RFC1213-MIB', 'egpAs')]),
                        ('snmpEnableAuthTraps', [('SNMPv2-MIB', 'snmpEnableAuthenTraps')]),)),
      'RFC-1212': {'OBJECT-TYPE': [('SNMPv2-SMI', 'OBJECT-TYPE')],
                    # XXX 'IndexSyntax': ???
      },
      'RFC1213-MIB': updateDict(dict(commonSyms['RFC1158-MIB/RFC1213-MIB']),
                        (('PhysAddress', [('SNMPv2-TC', 'PhysAddress')]),)),
      'RFC-1215': {'TRAP-TYPE': [('SNMPv2-SMI', 'TRAP-TYPE')],
      }
    }

    typeClasses = {
      'COUNTER32': 'Counter32',
      'COUNTER64': 'Counter64',
      'GAUGE32': 'Gauge32',
      'INTEGER': 'Integer32', # XXX
      'INTEGER32': 'Integer32',
      'INTEGER64':'Integer64',
      'IPADDRESS': 'IpAddress',
      'NETWORKADDRESS': 'IpAddress',
      'OBJECT IDENTIFIER': 'ObjectIdentifier',
      'OCTET STRING': 'OctetString',
      'OPAQUE': 'Opaque',
      'TIMETICKS': 'TimeTicks',
      'UNSIGNED32': 'Unsigned32',
      'UNSIGNED64':'Unsigned64',
      'Counter': 'Counter32',
      'Gauge': 'Gauge32',
      'NetworkAddress': 'IpAddress', # RFC1065-SMI, RFC1155-SMI -> SNMPv2-SMI
      'nullSpecific': 'zeroDotZero', # RFC1158-MIB -> SNMPv2-SMI
      'ipRoutingTable': 'ipRouteTable', # RFC1158-MIB -> RFC1213-MIB
      'snmpEnableAuthTraps': 'snmpEnableAuthenTraps'  # RFC1158-MIB -> SNMPv2-MIB
    }

    ctypeClasses = {
        'Integer32': 'long',
        'Integer64':'integer64',
        'Unsigned32':'u_long',
        'Unsigned64':'unsigned64',
        'TimeTicks': 'long',
        'OctetString': 'char *',
        'ObjectIdentifier':'oid',
        'Gauge32':'u_long',
        'Counter32': 'u_long',
        'Counter64': 'U64',
        'Bits' : 'u_long',
        'zeroDotZero' : 'int'
    }

    notificationTypes = {
        'Integer32':'i',
        'OctetString':'s',
        'ObjectIdentifier':'o',
        'Unsigned32':'u',
        'Gauge32':'u',
        'TimeTicks':'t',
        'IpAddress':'a',
        'Counter32':'c',
        'Counter64':'C',
        'Bits':'b'
    }

    netsnmpTypes = { 'Integer32':'ASN_INTEGER',
                    'Integer64':'ASN_INTEGER64',
                    'Unsigned32':'ASN_UNSIGNED',
                    'Unsigned64':'ASN_UNSIGNED64',
                    'TimeTicks':'ASN_TIMETICKS',
                    'OctetString':'ASN_OCTET_STR',
                    'ObjectIdentifier':'ASN_OBJECT_ID',
                    'Gauge32':'ASN_GAUGE',
                    'Counter32':'ASN_COUNTER',
                    'Counter64':'ASN_COUNTER64',
                    'Bits':'ASN_BIT8',
                    'IpAddress':'ASN_IPADDRESS',
                    'zeroDotZero':'ASN_INTEGER'
                    }

    smiv1IdxTypes = ['INTEGER', 'OCTET STRING', 'IPADDRESS', 'NETWORKADDRESS']

    ifTextStr = 'if mibBuilder.loadTexts: '
    indent = ' ' * 4
    fakeidx = 1000 # starting index for fake symbols

    def __init__(self, fileWriter, **options):
        self._rows = set()
        self._cols = {} # k, v = name, datatype
        self._exports = set()
        self._presentedSyms = set()
        self._importMap = {}
        self._out = {} # k, v = name, generated code
        self.moduleName = ['DUMMY']
        self.genRules = {'text': 1}
        self.headers = """#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
"""
        self.scalarSymbols = []
        self.notificationSymbols = []
        self.generatedSymbols = {}
        self.tables = {}
        self.tableRows = {}
        self.enumSymbols = {}
        self.fileWriter = fileWriter
        self.customTypes = {}
        self.parsedMibs = {}
        self.jsonData = None
        self.scalarMapping = options.get('scalarMapping','')
        self.jsonTables = options.get('jsonTables', [])
        self.clangFormatPath = options.get('clangFormatPath','')
        self.mappingFile = options.get('mappingFile','')
        self.clangFormatter = ClangFormat(path = self.clangFormatPath, dstPath = fileWriter._path)
        self.mappingFilePath = ''
        self.customFileHeaderString = ''
        self.customFileString = ''

        # Global Flag to tell the functions we are generating code
        # for the main AST
        self.mainModuleFlag = 1

        self.netsnmpTemplateHelperJsonData = None

    def fileWrite(self,fileName, data):
        if data.find('@@') >= 0:
            startIdx = data.find('@@');
            endIdx = data.find('@@', startIdx + 2)
            unparsedStr = data[startIdx:endIdx+2]
            print 'Unparsed @@ string : ' + unparsedStr + ' found while generating the file ' + fileName
            assert 0 and 'Invalid @@ string found Aborting'
        self.fileWriter.fileWrite(fileName=fileName,data=data)
        if '.json' in fileName:
            return
        data = self.clangFormatter.format(fileName)
        if data != '':
            self.fileWriter.fileWrite(fileName=fileName,data=data)
        #print 'Generated '+ fileName
        return

    def symTrans(self, symbol):
        if symbol in self.symsTable:
            return self.symsTable[symbol]
        return symbol,

    def transOpers(self, symbol):
        if iskeyword(symbol):
            symbol = 'pysmi_' + symbol
        return symbol.replace('-', '_')

    def isBinary(self, s):
        return isinstance(s, (str, unicode)) and s[0] == '\'' \
                                             and s[-2:] in ('\'b', '\'B')

    def isHex(self, s):
        return isinstance(s, (str, unicode)) and s[0] == '\'' \
                                             and s[-2:] in ('\'h', '\'H')

    def str2int(self, s):
        if self.isBinary(s):
            if s[1:-2]:
                i = int(s[1:-2], 2)
            else:
                raise error.PySmiSemanticError('empty binary string to int conversion')
        elif self.isHex(s):
            if s[1:-2]:
                i = int(s[1:-2], 16)
            else:
                raise error.PySmiSemanticError('empty hex string to int conversion')
        else:
            i = int(s)
        return i

    def prepData(self, pdata, classmode=0):
        data = []
        for el in pdata:
            if not isinstance(el, tuple):
                data.append(el)
            elif len(el) == 1:
                data.append(el[0])
            else:
                data.append(self.handlersTable[el[0]](self, self.prepData(el[1:], classmode=classmode), classmode=classmode))
        return data

    def getTypeFromSymbolTable(self, sym):
        for mod in self.symbolTable:
            if sym in self.symbolTable[mod]:
                return self.symbolTable[mod][sym]['syntax'][0][0] , self.symbolTable[mod][sym]['syntax'][0][1]
        return '',[]

    def getBaseTypeFromSymbolTable(self,mod,sym):
        baseType = self.symbolTable[mod][sym]['syntax'][0][0]
        subType = self.symbolTable[mod][sym]['syntax'][0][1]
        if baseType is 'MibTable' or baseType is 'MibTableRow' or baseType is 'MibTableColumn':
            return None
        while baseType not in self.ctypeClasses:
            baseType, subType = self.getTypeFromSymbolTable(baseType)
        return baseType, subType

    def genImports(self, imports):
        outStr = ''
        # convertion to SNMPv2
        toDel = []
        for module in list(imports):
            if module in self.convertImportv2:
                for symbol in imports[module]:
                    if symbol in self.convertImportv2[module]:
                        toDel.append((module, symbol))
                        for newImport in self.convertImportv2[module][symbol]:
                            newModule, newSymbol = newImport
                            if newModule in imports:
                                imports[newModule].append(newSymbol)
                            else:
                                imports[newModule] = [newSymbol]
        # removing converted symbols
        for d in toDel:
            imports[d[0]].remove(d[1])
        # merging mib and constant imports
        for module in self.constImports:
            if module in imports:
                imports[module] += self.constImports[module]
            else:
                imports[module] = self.constImports[module]
        for module in sorted(imports):
            #if module in baseMibs and 'SNMPv2-TC' not in module:
            #    continue
            symbols = ()
            for symbol in set(imports[module]):
                symbols += self.symTrans(symbol)
            if symbols:
                for s in symbols:
                    if module not in self.symbolTable:
                        continue
                    if s not in self.symbolTable[module]:
                        continue
                    if self.symbolTable[module][s]['type'] != 'TypeDeclaration':
                        continue
                    importType,subType = self.getBaseTypeFromSymbolTable(module,s)
                    if importType:
                        if s not in self.ctypeClasses:
                            self.customTypes[s] = {'baseType':importType,'subType':subType}
                self._presentedSyms = self._presentedSyms.union([self.transOpers(s) for s in symbols])
                self._importMap.update([(self.transOpers(s), module) for s in symbols])
                # outStr += '( %s, ) = mibBuilder.importSymbols("%s")\n' % \
                #   (', '.join([self.transOpers(s) for s in symbols]),
                #     '", "'.join((module,) + symbols))
        return outStr, tuple(sorted(imports))

    def genLabel(self, symbol, classmode=0):
        if symbol.find('-') != -1 or iskeyword(symbol):
            return classmode and 'label = "' + symbol + '"\n' or \
                                 '.setLabel("' + symbol + '")'
        return ''

    def regSym(self, symbol, outDict, parentOid=None, moduleIdentity=0):
        if symbol in self._presentedSyms and symbol not in self._importMap:
            raise error.PySmiSemanticError('Duplicate symbol found: %s' % symbol)
        self._out[symbol] = outDict

    def genNumericOid(self, oid):
        numericOid = []
        for part in oid:
            if isinstance(part, tuple):
                parent, module = part
                if parent == 'iso':
                    numericOid += [1,]
                    continue
                if module not in self.symbolTable:
                    # XXX do getname for possible future borrowed mibs
                    raise error.PySmiSemanticError('no module "%s" in symbolTable' % module)
                    continue
                if parent not in self.symbolTable[module]:
                    raise error.PySmiSemanticError('no symbol "%s" in module "%s"' % (parent, module))
                numericOid += self.genNumericOid(self.symbolTable[module][parent]['oid'])
            else:
                numericOid += [part,]
        return numericOid

    def getBaseType(self, symName, module):
        if module not in self.symbolTable:
            raise error.PySmiSemanticError('no module "%s" in symbolTable' % module)
        if symName not in self.symbolTable[module]:
            raise error.PySmiSemanticError('no symbol "%s" in module "%s"' % (symName, module))
        symType, symSubtype = self.symbolTable[module][symName].get('syntax', (('', ''), ''))
        if not symType[0]:
            raise error.PySmiSemanticError('unknown type for symbol "%s"' % symName)
        if symType[0] in self.baseTypes:
            return symType, symSubtype
        else:
            baseSymType, baseSymSubtype = self.getBaseType(*symType)
            if isinstance(baseSymSubtype, list):
                if isinstance(symSubtype, list):
                    symSubtype += baseSymSubtype
                else:
                    symSubtype = baseSymSubtype
            return baseSymType, symSubtype

### Clause generation functions
    def genAgentCapabilities(self, data, classmode=0):
        name, description, oid = data
        label = self.genLabel(name)
        name = self.transOpers(name)
        oidStr, parentOid = oid
        outStr = name + ' = AgentCapabilities(' + oidStr + ')' + label + '\n'
        if self.genRules['text']:
            outStr += self.ifTextStr + name + description + '\n'
        self.regSym(name, outStr, parentOid)
        return outStr

    def genModuleIdentity(self, data, classmode=0):
        name, lastUpdated, organization, contactInfo, \
            description, revisions, oid = data
        label = self.genLabel(name)
        name = self.transOpers(name)
        oidStr, parentOid = oid
        revisions = revisions and revisions or ''
        outDict = {}
        outDict['LAST-UPDATED'] = lastUpdated
        outDict['ORGANIZATION'] = organization
        outDict['CONTACT-INFO'] = contactInfo
        outDict['DESCRIPTION'] = description
        outDict['Revisions'] = revisions
        outDict['objectIdentifier'] = oid
        outStr = name + ' = ModuleIdentity(' + oidStr + ')' + label + revisions + '\n'
        if self.genRules['text']:
            outStr += self.ifTextStr + name + lastUpdated + '\n'
            outStr += self.ifTextStr + name + organization + '\n'
            outStr += self.ifTextStr + name + contactInfo + '\n'
            outStr += self.ifTextStr + name + description + '\n'
        outStr = '//' + name + ' genModuleIdentity\n'
        self.regSym(name, outDict, parentOid, moduleIdentity=1)
        return outDict

    def genModuleCompliance(self, data, classmode=0):
        name, description, compliances, oid = data
        label = self.genLabel(name)
        name = self.transOpers(name)
        oidStr, parentOid = oid
        outStr = name + ' = ModuleCompliance(' + oidStr + ')' + label
        outStr += compliances + '\n'
        if self.genRules['text']:
            outStr += self.ifTextStr + name + description + '\n'
        outStr = '//' + name + ' genModuleCompliance\n'
        self.regSym(name, outStr, parentOid)
        return outStr

    def genNotificationGroup(self, data, classmode=0):
        name, objects, description, oid = data
        label = self.genLabel(name)
        name = self.transOpers(name)
        oidStr, parentOid = oid
        objStr = ''
        if objects:
            objects = ['("' + self.moduleName[0] + '", "' + self.transOpers(obj) + '"),' for obj in objects]
        objStr = ' '.join(objects)
        outStr = name + ' = NotificationGroup(' + oidStr + ')' + label
        outStr += '.setObjects(*(' + objStr + '))\n'
        if self.genRules['text']:
            outStr += self.ifTextStr + name + description + '\n'
        outStr = '//' + name + ' genNotificationGroup'
        self.regSym(name, outStr, parentOid)
        return outStr

    def genNotificationType(self, data, classmode=0):
        name, tempobjects, description, oid = data
        label = self.genLabel(name)
        name = self.transOpers(name)
        oidStr, parentOid = oid
        outDict = {}
        objects = []
        if tempobjects:
            for obj in tempobjects:
                if self.transOpers(obj) in self._importMap:
                    objects.append({self._importMap[obj]:self.transOpers(obj)})
                else:
                    objects.append({self.moduleName[0]:self.transOpers(obj)})
        outDict['name'] = name
        outDict['oid'] = oid
        outDict['objects'] = objects
        self.notificationSymbols.append(name)
        self.regSym(name, outDict, parentOid)
        return {'Notification-Type':{name:outDict}}

    def genObjectGroup(self, data, classmode=0):
        name, objects, description, oid = data
        label = self.genLabel(name)
        name = self.transOpers(name)
        oidStr, parentOid = oid
        objStr = ''
        if objects:
            objects = ['("' + self.moduleName[0] + '", "' + self.transOpers(obj) + '"),' for obj in objects]
        objStr = ' '.join(objects)
        outStr = name + ' = ObjectGroup(' + oidStr + ')' + label
        outStr += '.setObjects(*(' + objStr + '))\n'
        if self.genRules['text']:
            outStr += self.ifTextStr + name + description + '\n'
        outStr = '//' + name + ' genObjectGroup'
        self.regSym(name, outStr, parentOid)
        return outStr

    def genObjectIdentity(self, data, classmode=0):
        name, description, oid = data
        label = self.genLabel(name)
        name = self.transOpers(name)
        oidStr, parentOid = oid
        outStr = name + ' = ObjectIdentity(' + oidStr + ')' + label + '\n'
        if self.genRules['text']:
            outStr += self.ifTextStr + name + description + '\n'
        outStr = '//' + name + ' genObjectIdentity'
        self.regSym(name, outStr, parentOid)
        return outStr

    def getTypeFromSyntax(self, syntax):
        ret = ''
        if 'SimpleSyntax' in syntax:
            ret = syntax['SimpleSyntax']['objType']
        return ret

    def getSubTypeFromSyntax(self, syntax):
        if 'SimpleSyntax' in syntax:
            if syntax['SimpleSyntax']['subType'] != {}:
                return syntax['SimpleSyntax']['subType']
            if syntax['SimpleSyntax']['objType'] in self.ctypeClasses:
                return syntax['SimpleSyntax']['subType']
            else:
                return self.getSubTypeFromSyntax(self._out[syntax['SimpleSyntax']['objType']]['syntax'])
        else:
            return {}

    def getMinMaxConstraints(self, row):
        if row['syntax']['SimpleSyntax']['subType'] == {}:
            subType = self.getSubTypeFromSyntax(row['syntax'])
        else:
            subType = row['syntax']['SimpleSyntax']['subType']
        if 'octetStringSubType' in subType:
            minConstraint, maxConstraint = subType['octetStringSubType'].get('ValueSizeConstraint', (0,0))
        else:
            minConstraint, maxConstraint = (0,0)
        return minConstraint, maxConstraint

    def getStringLength(self, row):
        minConstraint, maxConstraint = self.getMinMaxConstraints(row)
        stringLength = 255
        if minConstraint == 0 and maxConstraint != 0:
            stringLength = maxConstraint + 1
        else:
            if maxConstraint != 0:
                stringLength = maxConstraint
        return stringLength

    def genObjectType(self, data, classmode=0):
        name, syntax, units, maxaccess, description, augmention, index, defval, oid = data
        outDict = {}
        label = self.genLabel(name)
        name = self.transOpers(name)
        outDict['name'] = name
        outDict['syntax'] = syntax
        outDict['UNITS'] = units
        outDict['maxaccess'] = maxaccess
        outDict['DESCRIPTION'] = description
        outDict['augmention'] = augmention
        outDict['INDEX'] = index
        outDict['objectIdentifier'] = oid
        oidStr, parentOid = oid
        indexStr, fakeStrlist, fakeSyms = index and index or ('', '', [])
        classtype = self.getTypeFromSyntax(syntax)
        defval = self.genDefVal(defval, objname=name)
        outDict['DEFVAL'] = defval
        outStr = ''
        if 'SimpleSyntax' in syntax or 'Bits' in syntax:
            if name in self.symbolTable[self.moduleName[0]]['_symtable_cols']:
                outStr = self.genTableColumnCode(name, syntax,units,maxaccess,description,augmention,index,defval,oid)
            elif name in self.symbolTable[self.moduleName[0]]:
                outStr = self.genScalarCode(name,syntax, units,maxaccess, description, augmention, index, defval, oid)
        elif 'conceptualTable' in syntax:
            if name in self.symbolTable[self.moduleName[0]]:
                outStr = self.genTableCode(name, syntax,units,maxaccess,description,augmention,index,defval,oid)
        elif 'row' in syntax:
            if name in self.symbolTable[self.moduleName[0]]:
                outStr = self.genTableRowCode(name,syntax,units,maxaccess,description,augmention,index,defval,oid)
        self.regSym(name, outDict, parentOid)
        if fakeSyms: # fake symbols for INDEX to support SMIv1
            for i in range(len(fakeSyms)):
                fakeOutStr = fakeStrlist[i] % oidStr
                self.regSym(fakeSyms[i], fakeOutStr, name)
        return outStr

    def genTrapType(self, data, classmode=0):
        name, enterprise, variables, description, value = data
        label = self.genLabel(name)
        name = self.transOpers(name)
        enterpriseStr, parentOid = enterprise
        varStr = ''
        if variables:
            variables = ['("' + self.moduleName[0] + '", "' + self.transOpers(var) + '"),' for var in variables]
        varStr = ' '.join(variables)
        outStr = name + ' = NotificationType(' + enterpriseStr + \
                 ' + (0,' + str(value) + '))' + label
        outStr += '.setObjects(*(' + varStr + '))\n'
        if self.genRules['text']:
            outStr += self.ifTextStr + name + description + '\n'
        self.regSym(name, outStr, parentOid)
        outStr = '//' + name + ' genTrapType'
        return outStr

    def genTypeDeclaration(self, data, classmode=0):
        outStr = ''
        outDict = {}
        name, declaration = data
        if declaration:
            if not declaration[0] or 'SEQUENCE' not in declaration[0]:
                name = self.transOpers(name)
                for x in declaration:
                    if isinstance(x, dict):
                        if 'SimpleSyntax' in x:
                            self.customTypes[name] = {'baseType':x['SimpleSyntax']['objType'],
                                                    'subType':x['SimpleSyntax']['subType']}
                        elif 'Bits' in x:
                            self.customTypes[name] = {'baseType':'Bits'}
                        outDict = x
                #if 'SimpleSyntax' in declaration:
                #    self.customTypes[name] =
                #    {'baseType':attrs['SimpleSyntax']['objType'],
                #                              'subType':attrs['SimpleSyntax']['subType']}
                #elif 'Bits' in declaration:
                #    self.customTypes[name] = {'baseType':'Bits'}
                #outDict = declaration
                self.regSym(name, {'syntax':outDict})
        outStr = '//' + name + ' genTypeDeclaration'
        return outStr

    def genValueDeclaration(self, data, classmode=0):
        name, oid = data
        label = self.genLabel(name)
        name = self.transOpers(name)
        oidStr, parentOid = oid
        outDict = {}
        outDict['objectIdentifier'] = oid
        outStr = name + ' = MibIdentifier(' + oidStr + ')' + label + '\n'
        outStr = '//' + name + ' genValueDeclaration\n'
        self.regSym(name, outDict, parentOid)
        return outDict

### Subparts generation functions
    def genBitNames(self, data, classmode=0):
        names = data[0]
        return names

    def genBits(self, data, classmode=0):
        bits = data[0]
        namedval = [(bit[0], bit[1]) for bit in bits]
        numFuncCalls = len(namedval) / 255 + 1
        funcCalls = ''
        #for i in range(int(numFuncCalls)):
        #    funcCalls += 'NamedValues(' + ' '.join(namedval[255 * i:255 * (i +
        #    1)]) + ') + '
        #funcCalls = funcCalls[:-3]
        #outStr = classmode and \
        #  self.indent + 'namedValues = ' + funcCalls + '\n' or \
        #  '.clone(namedValues=' + funcCalls + ')'
        return {'Bits': namedval}

    def genCompliances(self, data, classmode=0):
        complStr = ''
        compliances = []
        for complianceModule in data[0]:
            name = complianceModule[0] or self.moduleName[0]
            compliances += ['("' + name + '", "' + self.transOpers(compl) + '"),' for compl in complianceModule[1]]
        complStr = ' '.join(compliances)
        return '.setObjects(*(' + complStr + '))'

    def genConceptualTable(self, data, classmode=0):
        row = data[0]['row']
        if row[1] and row[1][-2:] == '()':
            row = row[1][:-2]
            self._rows.add(row)
        return {'conceptualTable':row }

    def genContactInfo(self, data, classmode=0):
        text = data[0]
        return '.setContactInfo(' + dorepr(text) + ')'

    def genDisplayHint(self, data, classmode=0):
        return self.indent + 'displayHint = ' + dorepr(data[0]) + '\n'

    def genDefVal(self, data, classmode=0, objname=None):
        if not data:
            return ''
        if not objname:
            return data
        defval = data[0]
        defvalType = self.getBaseType(objname, self.moduleName[0])
        if isinstance(defval, (int, long)): # number
            val = str(defval)
        elif self.isHex(defval): # hex
            if defvalType[0][0] in ('Integer32', 'Integer'): # common bug in MIBs
                val = str(int(defval[1:-2], 16))
            else:
                val = 'hexValue="' + defval[1:-2] + '"'
        elif self.isBinary(defval): # binary
            binval = defval[1:-2]
            if defvalType[0][0] in ('Integer32', 'Integer'): # common bug in MIBs
                val = str(int(binval and binval or '0', 2))
            else:
                hexval = binval and hex(int(binval, 2))[2:] or ''
                val = 'hexValue="' + hexval + '"'
        elif defval[0] == defval[-1] and defval[0] == '"': # quoted string
            if defval[1:-1] == '' and defvalType != 'OctetString': # common bug
                # a warning should be here
                return False # we will set no default value
            val = dorepr(defval[1:-1])
        else: # symbol (oid as defval) or name for enumeration member
            if defvalType[0][0] == 'ObjectIdentifier' and \
               (defval in self.symbolTable[self.moduleName[0]] or \
                defval in self._importMap): # oid
                module = self._importMap.get(defval, self.moduleName[0])
                try:
                    val = str(self.genNumericOid(self.symbolTable[module][defval]['oid']))
                except:
                    raise error.PySmiSemanticError('no symbol "%s" in module "%s"' % (defval, module)) ### or no module if it will be borrowed later
            elif defvalType[0][0] in ('Integer32', 'Integer') and \
                 isinstance(defvalType[1], list) and \
                 defval in dict(defvalType[1]): # enumeration
                val = dorepr(defval)
            elif defvalType[0][0] == 'Bits':
                defvalBits = []
                bits = dict(defvalType[1])
                for bit in defval:
                    bitValue = bits.get(bit, None)
                    if bitValue is not None:
                        defvalBits.append((bit, bitValue))
                    else:
                        raise error.PySmiSemanticError('no such bit as "%s" for symbol "%s"' % (bit, objname))
                return defvalBits
            else:
                raise error.PySmiSemanticError('unknown type "%s" for defval "%s" of symbol "%s"' % (defvalType, defval, objname))
        return '.clone(' + val + ')'

    def genDescription(self, data, classmode=0):
        text = data[0]
        return '.setDescription(' + dorepr(text) + ')'

    def genEnumSpec(self, data, classmode=0):
        items = data[0]
        return {'enumSpec':items}
        # singleval = [str(item[1]) + ',' for item in items]
        # outStr = classmode and self.indent + 'subtypeSpec = %s.subtypeSpec+'
        # or '.subtype(subtypeSpec='
        # numFuncCalls = len(singleval) / 255 + 1
        # singleCall = numFuncCalls == 1 or False
        # funcCalls = ''
        # outStr += not singleCall and 'ConstraintsUnion(' or ''
        # for i in range(int(numFuncCalls)):
        #     funcCalls += 'SingleValueConstraint(' + \
        #                       ' '.join(singleval[255 * i:255 * (i + 1)]) +
        #                       '), '
        # funcCalls = funcCalls[:-2]
        # outStr += funcCalls
        # outStr += not singleCall and \
        #           (classmode and ')\n' or '))') or \
        #           (not classmode and ')' or '\n')
        # outStr += self.genBits(data, classmode=classmode)[1]
        # return {'enumSpec':items}

    def genTableIndex(self, data, classmode=0):
        def genFakeSyms(fakeidx, idxType):
            fakeSymName = 'pysmiFakeCol%s' % fakeidx
            objType = self.typeClasses.get(idxType, idxType)
            objType = self.transOpers(objType)
            return (fakeSymName + ' = MibTableColumn(%s + (' + str(fakeidx) + \
                   ', ), ' + objType + '())\n', # stub for parentOid
                   fakeSymName)

        indexes = data[0]
        idxStrlist, fakeSyms, fakeStrlist = [], [], []
        for idx in indexes:
            idxName = idx[1]
            if idxName in self.smiv1IdxTypes: # SMIv1 support
                idxType = idxName
                fakeSymStr, idxName = genFakeSyms(self.fakeidx, idxType)
                fakeStrlist.append(fakeSymStr)
                fakeSyms.append(idxName)
                self.fakeidx += 1
            idxStrlist.append('(' + str(idx[0]) + ', "' + \
                              self._importMap.get(idxName, self.moduleName[0]) + \
                              '", "' + idxName + '")')
        return '.setIndexNames(' + ', '.join(idxStrlist) + ')', fakeStrlist, fakeSyms

    def genIntegerSubType(self, data, classmode=0):
        outDict = {}
        singleRange = len(data[0]) == 1 or False
        outStr = classmode and self.indent + 'subtypeSpec = %s.subtypeSpec+' or \
                               '.subtype(subtypeSpec='
        outStr += not singleRange and 'ConstraintsUnion(' or ''
        for rng in data[0]:
            vmin, vmax = len(rng) == 1 and (rng[0], rng[0]) or rng
            vmin, vmax = str(self.str2int(vmin)), str(self.str2int(vmax))
            outDict['ValueRangeConstraint'] = (vmin, vmax)
            outStr += 'ValueRangeConstraint(' + vmin + ',' + vmax + ')' + \
                      (not singleRange and ',' or '')
        outStr += not singleRange and \
                  (classmode and ')' or '))') or \
                  (not classmode and ')' or '\n')
        return {'integerSubType':outDict}

    def genMaxAccess(self, data, classmode=0):
        access = data[0].replace('-', '')
        #return access != 'notaccessible' and '.setMaxAccess("' + access + '")' or ''
        return access

    def genOctetStringSubType(self, data, classmode=0):
        outDict = {}
        singleRange = len(data[0]) == 1 or False
        outStr = classmode and self.indent + 'subtypeSpec = %s.subtypeSpec+' or \
                               '.subtype(subtypeSpec='
        outStr += not singleRange and 'ConstraintsUnion(' or ''
        for rng in data[0]:
            vmin, vmax = len(rng) == 1 and (rng[0], rng[0]) or rng
            vmin, vmax = str(self.str2int(vmin)), str(self.str2int(vmax))
            outDict['ValueSizeConstraint'] = (vmin, vmax)
            outStr += 'ValueSizeConstraint(' + vmin + ',' + vmax + ')' + \
                      (not singleRange and ',' or '')
        outStr += not singleRange and \
                  (classmode and ')' or '))') or \
                  (not classmode and ')' or '\n')
        outStr += singleRange and vmin == vmax and \
                  (classmode and self.indent + 'fixedLength = ' + vmin + '\n' or '.setFixedLength(' + vmin + ')') or ''
        return {'octetStringSubType':outDict}

    def genOid(self, data, classmode=0):
        out = []
        parent = ''
        for el in data[0]:
            if isinstance(el, (str, unicode)):
                parent = self.transOpers(el)
                out += ((parent, self._importMap.get(parent, self.moduleName[0])),)
            elif isinstance(el, (int, long)):
                out += (el,)
            elif isinstance(el, tuple):
                out += (el[1],) # XXX Do we need to create a new object el[0]?
            else:
                raise error.PySmiSemanticError('unknown datatype for OID: %s' % el)
        return str(self.genNumericOid(out)), parent

    def genObjects(self, data, classmode=0):
        if data[0]:
            return [self.transOpers(obj) for obj in data[0]] # XXX self.transOpers or not??
        return []

    def genTime(self, data, classmode=0):
        times = []
        for t in data:
            lenTimeStr = len(t)
            if lenTimeStr == 11:
                t = '19' + t
            # XXX raise in strict mode
            #elif lenTimeStr != 13:
            #  raise error.PySmiSemanticError("Invalid date %s" % t)
            try:
                times.append(strftime('%Y-%m-%d %H:%M', strptime(t, '%Y%m%d%H%MZ')))
            except ValueError:
                # XXX raise in strict mode
                #raise error.PySmiSemanticError("Invalid date %s: %s" % (t,
                #sys.exc_info()[1]))
                t = '197001010000Z' # dummy date for dates with typos
                times.append(strftime('%Y-%m-%d %H:%M', strptime(t, '%Y%m%d%H%MZ')))
        return times

    def genLastUpdated(self, data, classmode=0):
        text = data[0]
        return '.setLastUpdated(' + dorepr(text) + ')'

    def genOrganization(self, data, classmode=0):
        text = data[0]
        return '.setOrganization(' + dorepr(text) + ')'

    def genRevisions(self, data, classmode=0):
        times = self.genTime(data[0])
        return '.setRevisions(("' + '", "'.join(times) + '",))'

    def genRow(self, data, classmode=0):
        row = data[0]
        row = self.transOpers(row)
        # return row in self.symbolTable[self.moduleName[0]]['_symtable_rows']
        # and ('MibTableRow', '') or self.genSimpleSyntax(data,
        # classmode=classmode)
        if row in self.symbolTable[self.moduleName[0]]['_symtable_rows']:
            return {'row':row}
        return self.genSimpleSyntax(data, classmode=classmode)

    def genSequence(self, data, classmode=0):
        cols = data[0]
        self._cols.update(cols)
        return {'SEQUENCE':cols}

    def genSimpleSyntax(self, data, classmode=0):
        objType = data[0]
        objType = self.typeClasses.get(objType, objType)
        objType = self.transOpers(objType)
        outDict = {'objType':objType,'subType':{}}
        subtype = len(data) == 2 and data[1] or ''
        if subtype is not '':
            outDict['subType'] = subtype
        if classmode:
            subtype = '%s' in subtype and subtype % objType or subtype # XXX hack?
            outDict['subType'] = {}
            return {'SimpleSyntax':outDict}
        out = [objType, subtype]
        return {'SimpleSyntax':outDict}

    def genTypeDeclarationRHS(self, data, classmode=0):
        return data
        # if len(data) == 1:
        #     parentType, attrs = data[0] # just syntax
        # else:
        #     # Textual convention
        #     display, syntax = data
        #     parentType, attrs = syntax
        #     parentType = parentType + ', TextualConvention'
        #     attrs = (display and display or '') + attrs
        # attrs = attrs or self.indent + 'pass\n'
        # return parentType, attrs

    def genUnits(self, data, classmode=0):
        text = data[0]
        return '.setUnits(' + dorepr(text) + ')'

    handlersTable = {
      'agentCapabilitiesClause': genAgentCapabilities,
      'moduleIdentityClause': genModuleIdentity,
      'moduleComplianceClause': genModuleCompliance,
      'notificationGroupClause': genNotificationGroup,
      'notificationTypeClause': genNotificationType,
      'objectGroupClause': genObjectGroup,
      'objectIdentityClause': genObjectIdentity,
      'objectTypeClause': genObjectType,
      'trapTypeClause': genTrapType,
      'typeDeclaration': genTypeDeclaration,
      'valueDeclaration': genValueDeclaration,

      'ApplicationSyntax': genSimpleSyntax,
      'BitNames': genBitNames,
      'BITS': genBits,
      'ComplianceModules': genCompliances,
      'conceptualTable': genConceptualTable,
      'CONTACT-INFO': genContactInfo,
      'DISPLAY-HINT': genDisplayHint,
      'DEFVAL': genDefVal,
      'DESCRIPTION': genDescription,
      'enumSpec': genEnumSpec,
      'INDEX': genTableIndex,
      'integerSubType': genIntegerSubType,
      'MaxAccessPart': genMaxAccess,
      'Notifications': genObjects,
      'octetStringSubType': genOctetStringSubType,
      'objectIdentifier': genOid,
      'Objects': genObjects,
      'LAST-UPDATED': genLastUpdated,
      'ORGANIZATION': genOrganization,
      'Revisions' : genRevisions,
      'row': genRow,
      'SEQUENCE': genSequence,
      'SimpleSyntax': genSimpleSyntax,
      'typeDeclarationRHS': genTypeDeclarationRHS,
      'UNITS': genUnits,
      'VarTypes': genObjects,
      #'a': lambda x: genXXX(x, 'CONSTRAINT')
    }

    def getObjTypeString(self, sym):
        syntax = sym['syntax']
        ret = ''
        if 'Bits' in syntax:
            return 'Bits'
        objType = syntax['SimpleSyntax']['objType']
        if objType in self.customTypes:
            ret = self.customTypes[objType]['baseType']
            if 'subType' in self.customTypes[objType]:
                syntax['SimpleSyntax']['subType'] = self.customTypes[objType]['subType']
        else:
            ret = objType

        if objType in self.enumSymbols:
            self.enumSymbols[sym['name']] = self.enumSymbols[objType]

        if ret not in self.ctypeClasses:
            if ret in self._out:
                if 'SimpleSyntax' in self._out[ret]:
                    ret = self._out[ret]['SimpleSyntax']['objType']
                elif 'Bits' in self._out[ret]:
                    ret = 'Bits'
        if ret not in self.ctypeClasses:
            ret = self.getObjTypeString(self._out[ret])

        return ret

    def genScalarCode(self, name, syntax, units, maxaccess, description, augmention, index, defval, oid):
        if self.mainModuleFlag:
            self.scalarSymbols.append(name)
        return ''

    def genTableCode(self, name, syntax, units, maxaccess, description, augmention, index, defval, oid):
        tempDict = self.getDictionary(name, syntax, units, maxaccess,description, augmention,index, defval,oid)
        self.tables[name] = {'data': tempDict}
        return ''

    def genTableRowCode(self, name, syntax, units, maxaccess, description, augmention, index, defval, oid):
        oidStr, parentOid = oid
        self.tables[parentOid]['row'] = name
        tempDict = self.getDictionary(name, syntax,units,maxaccess, description, augmention, index, defval,oid)
        self.tableRows[name] = {'data' : tempDict}
        self.tableRows[name]['index'] = []
        indexColumn = ''
        if index is not None:
            indexColumn, a ,b = index
            indexColumn = indexColumn[indexColumn.find('('):indexColumn.rfind(')') + 1]
            idxCount = indexColumn.count('(')
            indexColumn = indexColumn.replace('(','[',1)
            indexColumn = indexColumn.rsplit(')',1)
            indexColumn = ']'.join(indexColumn)
            tempArray = ast.literal_eval(indexColumn)
            for x in tempArray:
                tempVal, mibname, indexColumn = x
                self.tableRows[name]['index'].append(indexColumn)
        self.tableRows[name]['columns'] = []
        return ''

    def genTableColumnCode(self, name, syntax, units, maxaccess, description, augmention, index, defval, oid):
        oidStr, parentOid = oid
        tempDict = self.getDictionary(name, syntax, units, maxaccess, description, augmention, index, defval, oid)
        self.tableRows[parentOid]['columns'].append(tempDict)
        return ''

    def getDictionary(self, name, syntax, units, maxaccess, description, augmention, index,defval,oid):
        return {'name':name,
                'syntax':syntax,
                'units':units,
                'maxaccess':maxaccess,
                'description':description,
                'augmention':augmention,
                'index':index,
                'defval':defval,
                'oid':oid}

    codeGenClassTable = { 'MibScalar':genScalarCode,
                         'MibTable':genTableCode,
                         'MibTableRow':genTableRowCode,
                         'MibTableColumn':genTableColumnCode}

    def getJsonObject(self, data_file):
        filestring = ''
        for line in data_file:
            if '//' not in line:
                filestring += line
        self.jsonData = json.loads(filestring)
        if not self.jsonData:
            raise Exception('Could not load json object from the mapping file')

    def loadNetSnmpTemplateCodeFromFile(self,filename):
        tmpJsonData = ''
        try:
            path = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../codegen/netsnmp_code_templates/'+filename)
            with open(path) as data_file:
                filestring = ''
                line = ''
                for line in data_file:
                    #if '//' not in line:
                    #if not line.strip().startswith('//') :
                    #if line.strip().find('//',0,2) != 0 and line[1:].strip().find('//',0,2) != 0 :
                    if not line.strip().startswith('//') or line[1:].strip().find('//',0,2) != 0:
                        filestring += line
                if filename.find('netsnmp_template_helper.txt') >= 0 :
                    tmpJsonData = json.loads(filestring)
                    for key in tmpJsonData.keys():
                        tmpJsonData[key] = '\n'.join([x.strip() for x in tmpJsonData[key]])
                    if not tmpJsonData:
                        raise Exception('Could not load json object from the netsnmp template code file {1} '.format(filename))
                    return tmpJsonData
                else:
                    return filestring
        except IOError:
            raise Exception('failure opening netsnmp template code file %s: %s' % (path, sys.exc_info()[1]))
        return


    def getNetSnmpCodeTemplateFromHelperFile(self,requestedCode):
        if not self.netsnmpTemplateHelperJsonData:
            self.netsnmpTemplateHelperJsonData = self.loadNetSnmpTemplateCodeFromFile('netsnmp_template_helper.txt');
        return self.netsnmpTemplateHelperJsonData[requestedCode]


    def addSymbolsFromImports(self, parsedMibs):
        for tempast in parsedMibs:
            self.moduleName[0], moduleOid, imports, declarations = parsedMibs[tempast][2]
            out, importedModules = self.genImports(imports and imports or {})
            for declr in declarations and declarations or []:
                if declr:
                    clausetype = declr[0]
                    classmode = clausetype == 'typeDeclaration'
                    self.handlersTable[declr[0]](self, self.prepData(declr[1:], classmode), classmode)

    def doesTableSupportMultipleCardinality(self,tableName):
        return  1 < self.tables[tableName]['Table_MibSchemaCardinalityCount']

    def ovsColumnHasValidConditionType(self,tableName,idxOrClmSymbol):
        #dbIdx = ''
        #if idxOrClmSymbol['name'] in self.jsonData[tableName]['Indexes']:
        #    dbIdx = self.jsonData[tableName]['Indexes'][idxOrClmSymbol['name']]
        #elif idxOrClmSymbol['name'] in self.jsonData[tableName]['Columns']:
        #    dbIdx = self.jsonData[tableName]['Columns'][idxOrClmSymbol['name']]
        dbIdx = self.getSchemaDataObjectFromMappingFileForGivenMibObject(tableName,idxOrClmSymbol)
        if dbIdx == '':
            return False
        if isinstance(dbIdx['OvsColumn'],dict):
            if 'Table_MibSchemaCardinalityConditions' not in self.jsonData[tableName]:
                return False
            for conditionType in dbIdx['OvsColumn'].keys():
                if conditionType not in self.jsonData[tableName]['Table_MibSchemaCardinalityConditions']:
                    exceptStr = 'INVALID CONDITION TYPE SPECIFIED in the mapping file for table "' + tableName + '": column "' + idxOrClmSymbol['name'] +'"\n VALID CONDITION TYPES ARE : '
                    exceptStr += ' '.join(self.jsonData[tableName]['Table_MibSchemaCardinalityConditions'])
                    #print exceptStr
                    raise Exception(exceptStr)
                    return False
        else:
            return False
        return True

    def checkForMultipleTypesTagInJson(self,tableName,idxOrClmSymbol):
        #dbIdx = ''
        #if idxOrClmSymbol['name'] in self.jsonData[tableName]['Indexes']:
        #    dbIdx = self.jsonData[tableName]['Indexes'][idxOrClmSymbol['name']]
        #elif idxOrClmSymbol['name'] in self.jsonData[tableName]['Columns']:
        #    dbIdx = self.jsonData[tableName]['Columns'][idxOrClmSymbol['name']]
        dbIdx = self.getSchemaDataObjectFromMappingFileForGivenMibObject(tableName,idxOrClmSymbol)
        if dbIdx == '':
            return False
        if 'MultipleTypes' in dbIdx :
            if 'Table_MibSchemaCardinalityConditions' not in self.jsonData[tableName]:
                return False
            for conditionType in dbIdx['MultipleTypes'].keys():
                if conditionType not in self.jsonData[tableName]['Table_MibSchemaCardinalityConditions']:
                    exceptStr = 'INVALID CONDITION TYPE SPECIFIED in the mapping file for table "' + tableName + '": column "' + idxOrClmSymbol['name'] +'"\n VALID CONDITION TYPES ARE : '
                    exceptStr += ' '.join(self.jsonData[tableName]['Table_MibSchemaCardinalityConditions'])
                    #print exceptStr
                    raise Exception(exceptStr)
                    return False
        else:
            return False
        return True

    def loadSchemaObjectDetailsForGivenMibObjectFromMappingFile(self,tableName,idxOrClmSymbol):
        ovsTableName = ''
        ovsColumnName = ''
        ovsTypeKey = ''
        ovsType_KeyType = ''
        ovsType_KeyName = ''
        ovsCustomFnName = ''
        dbIdx = self.getSchemaDataObjectFromMappingFileForGivenMibObject(tableName,idxOrClmSymbol)
        if dbIdx == '':
            #return ['ovsTable','ovsColumn','Type_Key','Type_KeyType','Type_KeyName']
            return ovsTableName,ovsColumnName,ovsTypeKey,ovsType_KeyType,ovsType_KeyName,ovsCustomFnName
        else:
            ovsTableName = self.getOvsTableNameForGivenSymbolFromMappingFile()
            ovsColumnName = self.getOvsColumnNameForGivenSymbolFromMappingFile()
            #tmpIndexOrColumSymbol_Type = self.getTypeForGivenSymbolFromMappingFile()
            ovsTypeKey = self.getTypeKeyForGivenSymbolFromMappingFile()
            ovsType_KeyType = self.getTypeKeyTypeForGivenSymbolFromMappingFile()
            ovsType_KeyName = self.getTypeKeyNameForGivenSymbolFromMappingFile()
            ovsCustomFnName = self.getCustomFunctionForGivenSymbolFromMappingFile()
            return ovsTableName,ovsColumnName,ovsTypeKey,ovsType_KeyType,ovsType_KeyName,ovsCustomFnName

    def getSchemaDataObjectFromMappingFileForGivenMibObject(self,tableName,idxOrClmSymbol):
        dbIdx = ''
        if idxOrClmSymbol['name'] in self.jsonData[tableName]['Indexes']:
            dbIdx = self.jsonData[tableName]['Indexes'][idxOrClmSymbol['name']]
        elif idxOrClmSymbol['name'] in self.jsonData[tableName]['Columns']:
            dbIdx = self.jsonData[tableName]['Columns'][idxOrClmSymbol['name']]
        return dbIdx;

    def mibObjectParticipatesInMultipleCardinality(self,tableName,idxOrClmSymbol):
        return  self.checkForMultipleTypesTagInJson(tableName,idxOrClmSymbol) or self.ovsColumnParticipatesInMultipleCardinality(tableName,idxOrClmSymbol) or self.keyParticipatesInMultipleCardinality(tableName,idxOrClmSymbol)

    def ovsColumnParticipatesInMultipleCardinality(self,tableName,idxOrClmSymbol):
            return self.ovsColumnHasValidConditionType(tableName,idxOrClmSymbol)

    def getOvsTableNameForGivenSymbolFromMappingFile(self,tableName,idxOrClmSymbol):
        dbIdx = self.getSchemaDataObjectFromMappingFileForGivenMibObject(tableName,idxOrClmSymbol)
        return dbIdx['OvsTable'];

    def getOvsColumnNameForGivenSymbolFromMappingFile():
        dbIdx = self.getSchemaDataObjectFromMappingFileForGivenMibObject(tableName,idxOrClmSymbol)
        return dbIdx['OvsColumn'];

    def getTypeKeyForGivenSymbolFromMappingFile():
        dbIdx = self.getSchemaDataObjectFromMappingFileForGivenMibObject(tableName,idxOrClmSymbol)
        if 'Type' in dbIdx and 'Key' in dbIdx['Type'] and dbIdx['Type']['Key'] and not isinstance(dbIdx['Type']['Key'],dict):
            return dbIdx['Type']['Key'];
        return ''

    def getTypeKeyTypeForGivenSymbolFromMappingFile():
        dbIdx = self.getSchemaDataObjectFromMappingFileForGivenMibObject(tableName,idxOrClmSymbol)
        if 'Type' in dbIdx and 'Key' in dbIdx['Type'] and dbIdx['Type']['Key'] and isinstance(dbIdx['Type']['Key'],dict) and 'Type' in dbIdx['Type']['Key']:
            return dbIdx['Type']['Key']['Type'];
        return ''

    def getTypeKeyNameForGivenSymbolFromMappingFile():
        dbIdx = self.getSchemaDataObjectFromMappingFileForGivenMibObject(tableName,idxOrClmSymbol)
        if 'Type' in dbIdx and 'Key' in dbIdx['Type'] and dbIdx['Type']['Key'] and isinstance(dbIdx['Type']['Key'],dict) and 'Type' in dbIdx['Type']['Value']:
            return dbIdx['Type']['Key']['Value'];
        return ''

    def getCustomFunctionForGivenSymbolFromMappingFile():
        dbIdx = self.getSchemaDataObjectFromMappingFileForGivenMibObject(tableName,idxOrClmSymbol)
        if 'CustomFunction' in dbIdx and dbIdx['CustomFunction']:
            return dbIdx['CustomFunction']
        return ''


    def getCustomFnDefinitions(self,fnPrototype,fnBodyOptional='',tableName='',idxOrColSymbol='',appendConditionFlagParameterName=''):
        tmpCustomFileString = fnPrototype + '{\n'
        tmpCustomFileString  += '**** TO COMPLETE THIS FUNCTION ****\n;\n'
        tmpCustomFileString  += fnBodyOptional
        tmpCustomFileString  += self.getAutoGeneratedCodeForSingleOrMultipleOvsColumns(tableName,idxOrColSymbol,appendConditionFlagParameterName)
        tmpCustomFileString += self.getAutoGeneratedCodeForSingleOrMultipleKeys(tableName,idxOrColSymbol,appendConditionFlagParameterName)
        #tmpCustomFileString += call multiple types support code here.<Phani> TO DO
        tmpCustomFileString  += '}\n\n'
        return tmpCustomFileString

    def keyHasValidConditionType(self,tableName,idxOrClmSymbol):
        dbIdx = ''
        if idxOrClmSymbol['name'] in self.jsonData[tableName]['Indexes']:
            dbIdx = self.jsonData[tableName]['Indexes'][idxOrClmSymbol['name']]
        elif idxOrClmSymbol['name'] in self.jsonData[tableName]['Columns']:
            dbIdx = self.jsonData[tableName]['Columns'][idxOrClmSymbol['name']]
        if dbIdx == '':
            return False
        if 'Type' in dbIdx and dbIdx['Type']['Key'] and isinstance(dbIdx['Type']['Key'],dict):
            #if 'Type' not in dbIdx['Type']['Key']:
            allConditionTypes = ''
            if 'Value' in dbIdx['Type']['Key'] and isinstance(dbIdx['Type']['Key']['Value'],dict):
                #for conditionType in dbIdx['Type']['Key'].keys():
                 allConditionTypes = dbIdx['Type']['Key']['Value'].keys()
            elif not 'Value' in dbIdx['Type']['Key'] and not 'Type' in dbIdx['Type']['Key']: # this is for multi-keys for smap-type
                 allConditionTypes = dbIdx['Type']['Key'].keys()
            else:
                return False

            for conditionType in allConditionTypes :
                if conditionType not in self.jsonData[tableName]['Table_MibSchemaCardinalityConditions']:
                    exceptStr = 'INVALID CONDITION TYPE SPECIFIED in the mapping file for table "' + tableName + '": column "' + idxOrClmSymbol['name'] +'"\n VALID CONDITION TYPES ARE : '
                    exceptStr += ' '.join(self.jsonData[tableName]['Table_MibSchemaCardinalityConditions'])
                    #print exceptStr
                    raise Exception(exceptStr)
                    return False
        else:
            return False
        return True

    def keyParticipatesInMultipleCardinality(self,tableName,idxOrClmSymbol):
        return self.keyHasValidConditionType(tableName,idxOrClmSymbol)

    def getAutoGeneratedCodeForSingleOrMultipleKeys(self,tableName='',idxOrClmSymbol='',appendConditionFlagParameterName='',replaceString='NONE',ifBlockContentForKeyStrType='',ifBlockContentForKeyintType='',ifBlockContentForSmapType=''):
        retString = ''
        dbIdx = ''
        if tableName == '' or not tableName:#for check_type_function this will be passed as ''
            retString = '';
            return retString
        if idxOrClmSymbol['name'] in self.jsonData[tableName]['Indexes']:
            dbIdx = self.jsonData[tableName]['Indexes'][idxOrClmSymbol['name']]
        elif idxOrClmSymbol['name'] in self.jsonData[tableName]['Columns']:
            dbIdx = self.jsonData[tableName]['Columns'][idxOrClmSymbol['name']]
        if dbIdx == '':
            return retString
        ##ADD code here...
        if self.keyParticipatesInMultipleCardinality(tableName,idxOrClmSymbol):
            #for conditionType in dbIdx['Type']['Key'].keys():
            allCoditiontTypes = ''
            isValueMapMultipleKeyType = False
            if 'Value' in dbIdx['Type']['Key'] and isinstance(dbIdx['Type']['Key']['Value'],dict): #if multiple keys in value-map type
                allConditionTypes = dbIdx['Type']['Key']['Value'].keys()
                isValueMapMultipleKeyType = True
            else : #if multiple keys in smap-type
                allConditionTypes = dbIdx['Type']['Key'].keys()
                isValueMapMultipleKeyType = False
            for conditionType in allCoditiontTypes :
                #retString  += 'if(strcmp('+appendConditionFlagParameterName+','+self.tables[tableName]['CardinalityConditionTypeConstants'][conditionType] +') == 0 ) {\n'
                retString  += 'if('+appendConditionFlagParameterName+'=='+self.tables[tableName]['CardinalityConditionTypeConstants'][conditionType] +') {\n'
                #keyType = dbIdx['Type']['Key'][conditionType]['Type']
                #keyVal = dbIdx['Type']['Key'][conditionType]['Value']
                if isValueMapMultipleKeyType:
                    keyVal = dbIdx['Type']['Key']['Value'][conditionType]
                    keyType = dbIdx['Type']['Key']['Type']
                    if keyType == 'str':
                        retString  += ifBlockContentForKeyStrType.replace(replaceString,keyVal)
                    if keyType == 'int':
                        retString  += ifBlockContentForKeyintType.replace(replaceString,keyVal)
                else:
                    keyVal = dbIdx['Type']['Key'][conditionType]
                    retString  += ifBlockContentForSmapType.replace(replaceString,keyVal)

                retString  += '}\n'
            return retString
        elif 'Type' in dbIdx and dbIdx['Type']['Key'] and isinstance(dbIdx['Type']['Key'],dict):#i.e. for single entry it should be as usual.
            keyType = dbIdx['Type']['Key']['Type']
            keyVal = dbIdx['Type']['Key']['Value']
            if keyType == 'str':
                retString  += ifBlockContentForKeyStrType.replace(replaceString,keyVal)
            if keyType == 'int':
                retString  += ifBlockContentForKeyintType.replace(replaceString,keyVal)
            return retString
        elif  dbIdx['Type']['Key']:#i.e. for single entry for smap-type
            keyVal = dbIdx['Type']['Key']
            retString += ifBlockContentForSmapType.replace(replaceString,keyVal)
        else:
            return ''
        return ''

    def getAutoGeneratedCodeForSingleOrMultipleOvsColumns(self,tableName='',tableColmnOrIdxSymbol='',appendConditionFlagParameterName='',replaceString='NONE',ifBlockContent=''):
        retString = ''
        dbIdx = ''
        if tableName == '' or not tableName: #for check_type_function this will be passed as ''
            retString = '';
            return retString
        if tableColmnOrIdxSymbol['name'] in self.jsonData[tableName]['Indexes']:
            dbIdx = self.jsonData[tableName]['Indexes'][tableColmnOrIdxSymbol['name']]
        elif tableColmnOrIdxSymbol['name'] in self.jsonData[tableName]['Columns']:
            dbIdx = self.jsonData[tableName]['Columns'][tableColmnOrIdxSymbol['name']]
        if dbIdx == '':
            return retString
        if self.doesTableSupportMultipleCardinality(tableName):
            #if tableColmnOrIdxSymbol['name'] in self.jsonData[tableName]['Table_MibColumnsParticipatingInMultipleCardinality']:
            if self.ovsColumnParticipatesInMultipleCardinality(tableName,tableColmnOrIdxSymbol):
                #if isinstance(dbIdx['OvsColumn'],dict) :
                for tmpDictKey in dbIdx['OvsColumn'].keys() :
                    #retString  += 'if(strcmp('+appendConditionFlagParameterName+','+self.tables[tableName]['CardinalityConditionTypeConstants'][tmpDictKey] +') == 0 ) {\n'
                    retString  += 'if('+appendConditionFlagParameterName+'=='+self.tables[tableName]['CardinalityConditionTypeConstants'][tmpDictKey] +') {\n'
                    #tableOvsdbGetString += 'temp = (char*)'+idxTable + '_row->' + dbIdx['OvsColumn'][tmpDictKey] + ';\n'
                    #retString  += '********** COMPLETE *** THIS *** IF **** BLOCK *************'
                    retString  += ifBlockContent.replace(replaceString,dbIdx['OvsColumn'][tmpDictKey])
                    retString  += '}\n'
                return retString
        else :
            retString  += ifBlockContent.replace(replaceString,dbIdx['OvsColumn'])
            return retString
        return ''

    def genCode(self, ast, symbolTable, **kwargs):
        self.genRules['text'] = kwargs.get('genTexts', False)
        self.parsedMibs = kwargs.get('parsedMibs', {})
        path = os.path.normpath(self.mappingFile)
        if len(self.jsonTables) == 0 and self.scalarMapping == '':
            try:
                with open(path) as data_file:
                    self.getJsonObject(data_file)
            except IOError:
                raise Exception('failure opening Mapping file %s: %s' % (path, sys.exc_info()[1]))
        self.symbolTable = symbolTable
        out = ''
        importedModules = ()
        self._rows.clear()
        self._cols.clear()
        self._exports.clear()
        self._presentedSyms.clear()
        self._importMap.clear()
        self._out.clear()
        # FIXME this is hack
        self._out[unicode('IpAddress')] = {'syntax':{'SimpleSyntax':{'objType':'OctetString', 'subType':{'octetStringSubtype':{'ValueSizeConstraint':(0,4)}}}}}

        self.moduleName[0], moduleOid, imports, declarations = ast
        out, importedModules = self.genImports(imports and imports or {})
        for declr in declarations and declarations or []:
            if declr:
                clausetype = declr[0]
                classmode = clausetype == 'typeDeclaration'
                self.handlersTable[declr[0]](self, self.prepData(declr[1:], classmode), classmode)

        # Removing the current MIB from this as it was evaluated above
        tempParsedMibs = {}
        self.mainModuleFlag = 0
        for key, value in self.parsedMibs.iteritems():
            if key != self.moduleName[0]:
                tempParsedMibs[key] = value
        self.addSymbolsFromImports(tempParsedMibs)
        self.moduleName[0], moduleOid, imports, declarations = ast

        for sym in self._out:
            try:
                if 'enumSpec' in self._out[sym]['SimpleSyntax']['subType']:
                    self.enumSymbols[sym] = self._out[sym]['SimpleSyntax']['subType']['enumSpec']
            except:
                pass

        #for importAst in [x[2] for x in self.parsedMibs.items()]:
        #    tempModuleName, tempModuleOid, tempImports, tempDeclarations =
        #    importAst
        #    if tempModuleName in baseMibs:
        #        continue
        #    for declr in tempDeclarations and tempDeclarations or []:
        #        if declr:
        #            clausetype = declr[0]
        #            classmode = clausetype == 'typeDeclaration'
        #            self.handlersTable[declr[0]](self,
        #            self.prepData(declr[1:], classmode), classmode)
        #for sym in self.symbolTable[self.moduleName[0]]['_symtable_order']:
            # if sym not in self._out:
            #     raise error.PySmiCodegenError('No generated code for symbol
            #     %s' % sym)
            #if sym in self.codeSymbols:
            #    out += self._out[sym]
        # out += self.genExports()
        # out +=
        # self.genRegisterUnregister(self.moduleName[0].replace('-','_'))
        out = self.headers
        if 'comments' in kwargs:
            out = ''.join(['// %s\n' % x for x in kwargs['comments']]) + '//\n' + out
            out = '//\n// Net-SNMP MIB module %s (http://pysnmp.sf.net)\n' % self.moduleName[0] + out
        debug.logger & debug.flagCodegen and debug.logger('canonical MIB name %s (%s), imported MIB(s) %s, C code size %s bytes' % (self.moduleName[0], moduleOid, ','.join(importedModules) or '<none>', len(out)))
        if len(self.jsonTables) != 0 or self.scalarMapping != '':
            self.genJsonFile(self.moduleName[0].replace('-','_'),self.jsonTables)
            return MibInfo(oid=None, name=self.moduleName[0], imported=tuple([x for x in importedModules if x not in fakeMibs])), out
        self.genCFile(self.moduleName[0].replace('-','_'),out)
        self.genCTableFiles(self.moduleName[0].replace('-','_'))
        self.genNotificationFile(self.moduleName[0].replace('-','_'))
        self.genCustomFiles(self.moduleName[0].replace('-','_'))
        return MibInfo(oid=None, name=self.moduleName[0], imported=tuple([ x for x in importedModules if x not in fakeMibs])), out

    def genCustomFiles(self, moduleName):
        self.customFileString = '// Define Custom Functions for ' + moduleName + ' MIB in this fileName\n\n' + '#include "' +moduleName.upper() + '_custom.h"\n\n' + self.customFileString
        self.fileWrite(fileName = moduleName + '_custom.c', data=self.customFileString)
        tempStartString = '#ifndef ' + moduleName.upper() + '_CUSTOM_H\n'
        tempStartString += '#define ' + moduleName.upper() + '_CUSTOM_H\n\n'
        tempStartString += """#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "vswitch-idl.h"

"""
        tmpConditionTypeConstants = ''
        for key in self.tables.keys():
            tableName = key
            if tableName in self.jsonData:
                if self.jsonData[tableName]['MibType'] != 'Table':
                    raise Exception('%s is not a table',tableName)
                if(self.doesTableSupportMultipleCardinality(tableName)):
                    #for tmpConstantName,tmpConstantVal in self.tables[tableName]['CardinalityConditionTypeConstants'].items():
                    #    tmpConditionTypeConstants += '#define ' + tmpConstantVal + ' "' + tmpConstantName  + '"\n
                    tmpCnstVal = 1
                    for conditionTypeConstantEnum in self.tables[tableName]['CardinalityConditionTypeConstants'].values():
                        tmpConditionTypeConstants += '#define ' + conditionTypeConstantEnum + ' ' + str(tmpCnstVal)  + '\n'
                        tmpCnstVal += 1
            else:
                continue

        tempStartString += tmpConditionTypeConstants + '\n';
        self.customFileHeaderString = tempStartString + self.customFileHeaderString
        self.customFileHeaderString += '#endif'
        self.fileWrite(fileName = moduleName + '_custom.h', data=self.customFileHeaderString)
        self.genHeaderFile(self.moduleName[0].replace('-','_'))

    def genJsonFile(self, moduleName, jsonTables):
        jsonFileString = '{\n'
        if(len(jsonTables) > 0 ):
            for tableName in jsonTables:
                tableJson = self.tables[tableName]
                jsonFileString += '    "' + tableName + '" : {\n'
                jsonFileString += """        "MibType" : "Table",
            "RootOvsTable": null,
            "CacheTimeout": 30,
            "SkipFunction": null,
    """
                indexes = self.getIndexesForTable(tableName)
                jsonFileString += '        "Indexes":{\n'
                for idx in indexes:
                    jsonFileString += '            "' + idx['name'] + '": {\n'
                    jsonFileString += """                "OvsTable": null,
                    "OvsColumn": null,
                    "Type": {
                        "Key": null
                    },
                    "CustomFunction":null
                }"""
                    if idx != indexes[-1]:
                        jsonFileString += ','
                    jsonFileString += '\n'
                jsonFileString += '        },\n'
                columns = self.tableRows[self.tables[tableName]['row']]['columns']
                jsonFileString += '        "Columns" : {\n'
                for col in columns:
                    if col['name'] in [ idx['name'] for idx in indexes]:
                        continue
                    jsonFileString += '            "' + col['name'] + '": {\n'
                    jsonFileString += """                "OvsTable": null,
                    "OvsColumn": null,
                    "Type": {
                        "Key": null
                    },
                    "CustomFunction": null
                }"""
                    if col != columns[-1]:
                        jsonFileString += ','
                    jsonFileString += '\n'
                jsonFileString += '        }\n'
                jsonFileString += '    }'
                if tableName != jsonTables[-1]:
                    jsonFileString += ',\n'
                jsonFileString += '\n'
        elif self.scalarMapping != '' :
            for scalar in self.scalarSymbols :
                jsonFileString += '    "' + tableName + '" : {\n'
                jsonFileString += """        "MibType" : "Scalar",
            "OvsTable": null,
            "OvsColumn": null,
            "Type": {
                "Key": null
            },
            "CustomFunction": null
    """
        jsonFileString += '}'
        self.fileWrite(fileName=moduleName + '_mapping.json', data=jsonFileString)


    def genCFile(self, moduleName, data):
        scalarFileString = data
        scalarFileString += '#include "' + moduleName + '_custom.h"\n'
        scalarFileString += '#include "' + moduleName + '_scalars.h"\n'
        scalarFileString += '#include "' + moduleName + '_scalars_ovsdb_get.h"\n'
        scalarFileString += '#include "ovsdb-idl.h"\n'
        scalarFileString += '#include "vswitch-idl.h"\n'
        for sym in self.scalarSymbols:
            name = self._out[sym]['name']
            syntax = self._out[sym]['syntax']
            oid = self._out[sym]['objectIdentifier']
            if name not in self.jsonData:
                continue
            jsonValue = self.jsonData[name]
            oidStr, parendOid = oid
            objType = syntax['SimpleSyntax']['objType']

            baseType = objType
            if objType in self.customTypes:
                baseType = self.customTypes[objType]['baseType']

            outStr = 'static '
            if self.getObjTypeString(self._out[sym]) == 'OctetString':
                if 'octetStringSubType' in syntax['SimpleSyntax']['subType']:
                    minConstraint, maxConstraint = syntax['SimpleSyntax']['subType']['octetStringSubType'].get('ValueSizeConstraint',(0,0))
                else:
                    minConstraint, maxConstraint = (0,0)
                if maxConstraint == 0:
                    stringLength = 256
                else:
                    if minConstraint == 0:
                        stringLength = maxConstraint + 1
                    else:
                        stringLength = maxConstraint
                outStr += 'char netsnmp_' + name + '[' + str(stringLength) + '];\n'
                outStr += 'static size_t netsnmp_' + name + '_len = 0;\n'
            elif self.getObjTypeString(self._out[sym]) == 'ObjectIdentifier':
                outStr += 'oid netsnmp_' + name + '[MAX_OID_LEN];\n'
                outStr += 'static size_t netsnmp_' + name + '_len = 0;\n'
            else:
                outStr += self.ctypeClasses[self.getObjTypeString(self._out[sym])] + ' netsnmp_' + name + ';\n'
            outStr += 'int handler_' + name + '(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests);\n\n'
            outStr += 'void init_' + name + '(void) {\n'
            outStr += 'const oid ' + name + '_oid[] = ' + str(oidStr).replace('[', '{').replace(']','}') + ';\n'
            outStr += 'netsnmp_register_scalar(\n netsnmp_create_handler_registration("' + name + '", handler_' + name + ',' + name + '_oid, OID_LENGTH(' + name + '_oid), HANDLER_CAN_RWRITE));\n\n'
            if jsonValue['OvsTable'] and jsonValue['OvsColumn']:
                outStr += 'ovsdb_idl_add_column(idl, &ovsrec_' + jsonValue['OvsTable'] + '_col_' + jsonValue['OvsColumn'] + ');\n'
            outStr += '}\n\n'
            outStr += 'int handler_' + name + '(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {\n'
            outStr += 'if(reqinfo->mode == MODE_GET) {\n'
            scalarType = self.getObjTypeString(self._out[sym])
            if not jsonValue['OvsTable']:
                if scalarType == 'OctetString' or scalarType == 'ObjectIdentifier':
                    outStr += 'ovsdb_get_' + name + '(idl, netsnmp_' + name + ', &netsnmp_' + name + '_len);\n'
                else:
                    outStr += 'ovsdb_get_' + name + '(idl, &netsnmp_' + name + ');\n'
            else:
                outStr += 'const struct ovsrec_' + jsonValue['OvsTable'] + ' *' + jsonValue['OvsTable'] + '_row = ovsrec_' + jsonValue['OvsTable'] + '_first(idl);\n'
                outStr += 'if ('+jsonValue['OvsTable']+'_row == NULL) {\n snmp_log(LOG_ERR, "not able to fetch ' + jsonValue['OvsTable'] + ' row");\n return -1;\n}\n'
                if scalarType == 'OctetString' or scalarType == 'ObjectIdentifier':
                    outStr += 'ovsdb_get_' + name + '(idl, ' + jsonValue['OvsTable'] + '_row, netsnmp_' + name + ', &netsnmp_' + name + '_len);\n'
                else:
                    outStr += 'ovsdb_get_' + name + '(idl, ' + jsonValue['OvsTable'] + '_row, &netsnmp_' + name + ');\n'
            if scalarType == 'OctetString':
                outStr += 'snmp_set_var_typed_value(requests->requestvb, ' + self.netsnmpTypes[scalarType] + ', &netsnmp_' + name + ', netsnmp_' + name + '_len);\n'
            elif scalarType == 'ObjectIdentifier':
                outStr += 'snmp_set_var_typed_value(requests->requestvb, ' + self.netsnmpTypes[scalarType] + ', &netsnmp_' + name + ', netsnmp_' + name + '_len *sizeof(netsnmp_' + name + '[0]));\n'
            else:
                outStr += 'snmp_set_var_typed_value(requests->requestvb, ' + self.netsnmpTypes[self.getObjTypeString(self._out[sym])] + ', &netsnmp_' + name + ', sizeof(netsnmp_' + name + '));\n'
            outStr += '}\n'
            outStr += 'return SNMP_ERR_NOERROR;\n'
            outStr += '}\n\n'
            scalarFileString += outStr
        self.fileWrite(fileName=moduleName + '_scalars.c',data=scalarFileString)

        scalarOvsdbGetString = """#include "openswitch-idl.h"
#include "ovsdb-idl.h"
#include "vswitch-idl.h"
#include "openvswitch/vlog.h"
"""
        scalarOvsdbGetString += '#include "' + moduleName + '_custom.h"\n'
        scalarOvsdbGetString += '#include "' + moduleName + '_scalars_ovsdb_get.h"\n\n'
        for sym in self.scalarSymbols:
            name = sym
            scalar = self._out[name]
            if name not in self.jsonData:
                continue
            scalarJson = self.jsonData[name]
            scalarType = self.getObjTypeString(scalar)
            if name in self.generatedSymbols:
                continue
            if not scalarJson['OvsTable']:
                if scalarType == 'OctetString':
                    scalarOvsdbGetString += 'void ovsdb_get_' + scalar['name'] + '(struct ovsdb_idl *idl, char *' + scalar['name'] + '_val_ptr, size_t *' + scalar['name'] + '_val_ptr_len) {\n'
                    if scalarJson['CustomFunction']:
                        scalarOvsdbGetString += scalarJson['CustomFunction'] + '(idl, ' + scalar['name'] + '_val_ptr, ' + scalar['name'] + '_val_ptr_len);\n'
                        self.customFileHeaderString += 'void ' + scalarJson['CustomFunction'] + '(struct ovsdb_idl *idl, char *' + scalar['name'] + '_val_ptr, size_t *' + scalar['name'] + '_val_ptr_len);\n\n'
                    else:
                        scalarOvsdbGetString += '*' + scalar['name'] + '_val_ptr = \'\\0\';\n'
                        scalarOvsdbGetString += '*' + scalar['name'] + '_val_ptr_len = 0;\n'
                elif scalarType == 'ObjectIdentifier':
                    scalarOvsdbGetString += 'void ovsdb_get_' + scalar['name'] + '(struct ovsdb_idl *idl, oid *' + scalar['name'] + '_val_ptr, size_t *' + scalar['name'] + '_val_ptr_len) {\n'
                    if scalarJson['CustomFunction']:
                        scalarOvsdbGetString += scalarJson['CustomFunction'] + '(idl, ' + scalar['name'] + '_val_ptr, ' + scalar['name'] + '_val_ptr_len);\n'
                        self.customFileHeaderString += 'void ' + scalarJson['CustomFunction'] + '(struct ovsdb_idl *idl, oid *' + scalar['name'] + '_val_ptr, size_t *' + scalar['name'] + '_val_ptr_len);\n\n'
                    else:
                        scalarOvsdbGetString += '*' + scalar['name'] + '_val_ptr = (oid)NULL;\n'
                        scalarOvsdbGetString += '*' + scalar['name'] + '_val_ptr_len = 0;\n'
                else:
                    scalarOvsdbGetString += 'void ovsdb_get_' + scalar['name'] + '(struct ovsdb_idl *idl, ' + self.ctypeClasses[scalarType] + ' *' + scalar['name'] + '_val_ptr) {\n'
                    if scalarJson['CustomFunction']:
                        scalarOvsdbGetString += scalarJson['CustomFunction'] + '(idl, ' + scalar['name'] + '_val_ptr);\n'
                        self.customFileHeaderString += 'void ' + scalarJson['CustomFunction'] + '(struct ovsdb_idl *idl, ' + self.ctypeClasses[scalarType] + ' *' + scalar['name'] + '_val_ptr);\n\n'
                    else:
                        scalarOvsdbGetString += '*' + scalar['name'] + '_val_ptr = (' + self.ctypeClasses[scalarType] + ')NULL;\n'
                scalarOvsdbGetString += '}\n\n'
                self.generatedSymbols[name] = 1
                continue
            if scalarType == 'OctetString':
                scalarOvsdbGetString += 'void ovsdb_get_' + scalar['name'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + scalarJson['OvsTable'] + ' *' + scalarJson['OvsTable'] + '_row, char *' + scalar['name'] + '_val_ptr, size_t *' + scalar['name'] + '_val_ptr_len) {\n'
                if scalarJson['CustomFunction']:
                    scalarOvsdbGetString += scalarJson['CustomFunction'] + '(idl, ' + scalarJson['OvsTable'] + '_row, ' + scalar['name'] + '_val_ptr, ' + scalar['name'] + '_val_ptr_len);\n'
                    self.customFileHeaderString += 'void ' + scalarJson['CustomFunction'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + scalarJson['OvsTable'] + ' *' + scalarJson['OvsTable'] + '_row, char *' + scalar['name'] + '_val_ptr, size_t *' + scalar['name'] + '_val_ptr_len);\n'
                else:
                    scalarOvsdbGetString += 'char *temp = (char*)'
                    if scalarJson['Type']['Key']:
                        if type(scalarJson['Type']['Key']) == dict:
                            keyType = scalarJson['Type']['Key']['KeyType']
                            keyValue = scalarJson['Type']['Key']['KeyValue']
                            if keyType == 'str':
                                scalarOvsdbGetString += 'for (int i = 0; i < ' + scalarJson['OvsTable']+'_row->n_'+scalarJson['OvsColumn']+'; i++) {\n'
                                scalarOvsdbGetString += 'if(strcmp("'+keyValue+'", '+scalarJson['OvsTable']+'_row->key_'+scalarJson['OvsColumn']+'[i]) == 0) {\n'
                                scalarOvsdbGetString += '*'+scalar['name']+'_val_ptr = ('+self.ctypeClasses[scalarType]+')'+scalarJson['OvsTable']+'_row->value_'+scalarJson['OvsColumn']+'[i];\n'
                                scalarOvsdbGetString += '}\n'
                                scalarOvsdbGetString += '}\n'
                            elif keyType == 'int':
                                scalarOvsdbGetString += 'for (int i = 0; i < ' + scalarJson['OvsTable']+'_row->n_'+scalarJson['OvsColumn']+'; i++) {\n'
                                scalarOvsdbGetString += 'if('+keyValue+' == '+scalarJson['OvsTable']+'_row->key_'+scalarJson['OvsColumn']+'[i]) {\n'
                                scalarOvsdbGetString += '*'+scalar['name']+'_val_ptr = ('+self.ctypeClasses[scalarType]+')'+scalarJson['OvsTable']+'_row->value_'+scalarJson['OvsColumn']+'[i];\n'
                                scalarOvsdbGetString += '}\n'
                                scalarOvsdbGetString += '}\n'
                        else:
                            scalarOvsdbGetString += 'smap_get(&' + scalarJson['OvsTable'] + '_row->' + scalarJson['OvsColumn'] + ', "' + scalarJson['Type']['Key'] + '");\n'
                    else:
                        scalarOvsdbGetString += scalarJson['OvsTable'] + '_row->' + scalarJson['OvsColumn'] + ';\n'
                    scalarOvsdbGetString += '*' + scalar['name'] + '_val_ptr_len = temp != NULL ? strlen(temp) : 0;\n'
                    scalarOvsdbGetString += 'memcpy(' + scalar['name'] + '_val_ptr, temp, *' + scalar['name'] + '_val_ptr_len);\n'
            elif scalarType == 'ObjectIdentifier':
                scalarOvsdbGetString += 'void ovsdb_get_' + scalar['name'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + scalarJson['OvsTable'] + ' *' + scalarJson['OvsTable'] + '_row, oid *' + scalar['name'] + '_val_ptr, size_t *' + scalar['name'] + '_val_ptr_len) {\n'
                if scalarJson['CustomFunction']:
                    scalarOvsdbGetString += scalarJson['CustomFunction'] + '(idl,' + scalarJson['OvsTable'] + '_row, ' + scalar['name'] + '_val_ptr, ' + scalar['name'] + '_val_ptr_len);\n'
                    self.customFileHeaderString += 'void ' + scalarJson['CustomFunction'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + scalarJson['OvsTable'] + ' *' + scalarJson['OvsTable'] + '_row, oid *' + scalar['name'] + '_val_ptr, size_t *' + scalar['name'] + '_val_ptr_len);\n'
                else:
                    scalarOvsdbGetString += 'char *temp = (char *)'
                    if scalarJson['Type']['Key']:
                        if type(scalarJson['Type']['Key']) == dict:
                            keyType = scalarJson['Type']['Key']['KeyType']
                            keyValue = scalarJson['Type']['Key']['KeyValue']
                            if keyType == 'str':
                                scalarOvsdbGetString += 'for (int i = 0; i < ' + scalarJson['OvsTable']+'_row->n_'+scalarJson['OvsColumn']+'; i++) {\n'
                                scalarOvsdbGetString += 'if(strcmp("'+keyValue+'", '+scalarJson['OvsTable']+'_row->key_'+scalarJson['OvsColumn']+'[i]) == 0) {\n'
                                scalarOvsdbGetString += '*'+scalar['name']+'_val_ptr = ('+self.ctypeClasses[scalarType]+')'+scalarJson['OvsTable']+'_row->value_'+scalarJson['OvsColumn']+'[i];\n'
                                scalarOvsdbGetString += '}\n'
                                scalarOvsdbGetString += '}\n'
                            elif keyType == 'int':
                                scalarOvsdbGetString += 'for (int i = 0; i < ' + scalarJson['OvsTable']+'_row->n_'+scalarJson['OvsColumn']+'; i++) {\n'
                                scalarOvsdbGetString += 'if('+keyValue+' == '+scalarJson['OvsTable']+'_row->key_'+scalarJson['OvsColumn']+'[i]) {\n'
                                scalarOvsdbGetString += '*'+scalar['name']+'_val_ptr = ('+self.ctypeClasses[scalarType]+')'+scalarJson['OvsTable']+'_row->value_'+scalarJson['OvsColumn']+'[i];\n'
                                scalarOvsdbGetString += '}\n'
                                scalarOvsdbGetString += '}\n'
                        else:
                            scalarOvsdbGetString += 'smap_get(&' + scalarJson['OvsTable'] + '_row->' + scalarJson['OvsColumn'] + ', "' + scalarJson['Type']['Key'] + '");\n'
                            scalarOvsdbGetString += 'oid temp_oid[MAX_OID_LEN] = {0};\n'
                            scalarOvsdbGetString += 'if (temp != NULL) {\n'
                            scalarOvsdbGetString += 'snmp_parse_oid(temp, temp_oid, ' + scalar['name'] + '_val_ptr_len);\n'
                            scalarOvsdbGetString += '}\n'
                    else:
                        scalarOvsdbGetString += scalarJson['OvsTable'] + '_row->' + scalarJson['OvsColumn'] + ';\n'
                        scalarOvsdbGetString += 'oid temp_oid[MAX_OID_LEN] = {0};\n'
                        scalarOvsdbGetString += 'if (temp != NULL) {\n'
                        scalarOvsdbGetString += 'snmp_parse_oid(temp, temp_oid, ' + scalar['name'] + '_val_ptr_len);\n'
                        scalarOvsdbGetString += '}\n'
                    scalarOvsdbGetString += 'memcpy(' + scalar['name'] + '_val_ptr, temp_oid, *' + scalar['name'] + '_val_ptr_len);\n'
            else:
                scalarOvsdbGetString += 'void ovsdb_get_' + scalar['name'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + scalarJson['OvsTable'] + ' *' + scalarJson['OvsTable'] + '_row, ' + self.ctypeClasses[scalarType] + '*' + scalar['name'] + '_val_ptr) {\n'
                if scalarJson['CustomFunction']:
                    scalarOvsdbGetString += scalarJson['CustomFunction'] + '(idl, ' + scalarJson['OvsTable'] + '_row, ' + scalar['name'] + '_val_ptr);\n'
                    self.customFileHeaderString += 'void ' + scalarJson['CustomFunction'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + scalarJson['OvsTable'] + ' *' + scalarJson['OvsTable'] + '_row, ' + self.ctypeClasses[scalarType] + ' *' + scalar['name'] + '_val_ptr);\n'
                else:
                    if scalarJson['Type']['Key']:
                        if type(scalarJson['Type']['Key']) == dict:
                            keyType = scalarJson['Type']['Key']['KeyType']
                            keyValue = scalarJson['Type']['Key']['KeyValue']
                            if keyType == 'str':
                                scalarOvsdbGetString += 'for (int i = 0; i < ' + scalarJson['OvsTable']+'_row->n_'+scalarJson['OvsColumn']+'; i++) {\n'
                                scalarOvsdbGetString += 'if(strcmp("'+keyValue+'", '+scalarJson['OvsTable']+'_row->key_'+scalarJson['OvsColumn']+'[i]) == 0) {\n'
                                scalarOvsdbGetString += '*'+scalar['name']+'_val_ptr = ('+self.ctypeClasses[scalarType]+')'+scalarJson['OvsTable']+'_row->value_'+scalarJson['OvsColumn']+'[i];\n'
                                scalarOvsdbGetString += '}\n'
                                scalarOvsdbGetString += '}\n'
                            elif keyType == 'int':
                                scalarOvsdbGetString += 'for (int i = 0; i < ' + scalarJson['OvsTable']+'_row->n_'+scalarJson['OvsColumn']+'; i++) {\n'
                                scalarOvsdbGetString += 'if('+keyValue+' == '+scalarJson['OvsTable']+'_row->key_'+scalarJson['OvsColumn']+'[i]) {\n'
                                scalarOvsdbGetString += '*'+scalar['name']+'_val_ptr = ('+self.ctypeClasses[scalarType]+')'+scalarJson['OvsTable']+'_row->value_'+scalarJson['OvsColumn']+'[i];\n'
                                scalarOvsdbGetString += '}\n'
                                scalarOvsdbGetString += '}\n'
                        else:
                            scalarOvsdbGetString += 'char *temp = (char*)'
                            scalarOvsdbGetString += 'smap_get(&' + scalarJson['OvsTable'] + '_row->' + scalarJson['OvsColumn'] + ', "' + scalarJson['Type']['Key'] + '");\n'
                            scalarOvsdbGetString += 'if(temp == NULL) {\n'
                            scalarOvsdbGetString += '*' + scalar['name'] + '_val_ptr = 0;\n'
                            scalarOvsdbGetString += '}\n'
                            scalarOvsdbGetString += 'else {\n'
                            scalarOvsdbGetString += '*' + scalar['name'] + '_val_ptr = (' + self.ctypeClasses[scalarType] + ')atoi(temp);\n'
                            scalarOvsdbGetString += '}\n'
                    else:
                        scalarOvsdbGetString += '*' + scalar['name'] + '_val_ptr = (' + self.ctypeClasses[scalarType] + ')*('
                        scalarOvsdbGetString += scalarJson['OvsTable'] + '_row->' + scalarJson['OvsColumn'] + ');\n'
            scalarOvsdbGetString += '}\n\n'
            self.generatedSymbols[name] = 1
        self.fileWrite(fileName=moduleName + '_scalars_ovsdb_get.c',data=scalarOvsdbGetString)

        scalarOvsdbGetHeaderString = '#ifndef ' + moduleName.upper() + '_SCALARS_OVSDB_GET_H\n'
        scalarOvsdbGetHeaderString += '#define ' + moduleName.upper() + '_SCALARS_OVSDB_GET_H\n\n'
        scalarOvsdbGetHeaderString += '#include "vswitch-idl.h"\n'
        scalarOvsdbGetHeaderString += '#include "ovsdb-idl.h"\n'
        scalarOvsdbGetHeaderString += 'extern struct ovsdb_idl *idl;\n\n'
        for sym in self.scalarSymbols:
            name = sym
            scalar = self._out[name]
            if name not in self.jsonData:
                continue
            scalarJson = self.jsonData[name]
            scalarType = self.getObjTypeString(scalar)
            if not scalarJson['OvsTable']:
                if scalarType == 'OctetString':
                    scalarOvsdbGetHeaderString += 'void ovsdb_get_' + scalar['name'] + '(struct ovsdb_idl *idl, char *' + scalar['name'] + '_val_ptr, size_t*' + scalar['name'] + '_val_ptr_len);\n'
                elif scalarType == 'ObjectIdentifier':
                    scalarOvsdbGetHeaderString += 'void ovsdb_get_' + scalar['name'] + '(struct ovsdb_idl *idl, oid *' + scalar['name'] + '_val_ptr, size_t*' + scalar['name'] + '_val_ptr_len);\n'
                else:
                    scalarOvsdbGetHeaderString += 'void ovsdb_get_' + scalar['name'] + '(struct ovsdb_idl *idl, ' + self.ctypeClasses[scalarType] + ' *' + scalar['name'] + '_val_ptr);\n'
                continue
            if scalarType == 'OctetString':
                scalarOvsdbGetHeaderString += 'void ovsdb_get_' + scalar['name'] + '(struct ovsdb_idl *idl, const  struct ovsrec_' + scalarJson['OvsTable'] + ' *' + scalarJson['OvsTable'] + '_row, char*' + scalar['name'] + '_val_ptr, size_t*' + scalar['name'] + '_val_ptr_len);\n'
            elif scalarType == 'ObjectIdentifier':
                scalarOvsdbGetHeaderString += 'void ovsdb_get_' + scalar['name'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + scalarJson['OvsTable'] + ' *' + scalarJson['OvsTable'] + '_row, oid*' + scalar['name'] + '_val_ptr, size_t*' + scalar['name'] + '_val_ptr_len);\n'
            else:
                scalarOvsdbGetHeaderString += 'void ovsdb_get_' + scalar['name'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + scalarJson['OvsTable'] + ' *' + scalarJson['OvsTable'] + '_row, ' + self.ctypeClasses[scalarType] + ' *' + scalar['name'] + '_val_ptr);\n'
        scalarOvsdbGetHeaderString += '\n#endif'
        self.fileWrite(fileName=moduleName + '_scalars_ovsdb_get.h', data=scalarOvsdbGetHeaderString)

        pluginsFileString = """#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
"""
        pluginsFileString += '#include "' + moduleName + '_plugins.h"\n'
        pluginsFileString += '#include "' + moduleName + '_scalars.h"\n'
        for tableName in self.tables.keys():
            if tableName in self.jsonData:
                pluginsFileString += '#include "' + tableName + '.h"\n'
        pluginsFileString += '\n'
        pluginsFileString += 'void ops_snmp_init(void) {\n'
        for codeSym in self.scalarSymbols:
            name = codeSym
            if name not in self.jsonData:
                continue
            pluginsFileString += 'init_' + name + '();\n'
        pluginsFileString += '\n'
        for tableName in self.tables.keys():
            if tableName in self.jsonData:
                pluginsFileString += 'init_' + tableName + '();\n'
        pluginsFileString += '}\n\n'
        pluginsFileString += 'void ops_snmp_run(void){}\n'
        pluginsFileString += 'void ops_snmp_wait(void){}\n'
        pluginsFileString += 'void ops_snmp_destroy(void){\n'
        for tableName in self.tables.keys():
            if tableName in self.jsonData:
                pluginsFileString += 'shutdown_' + tableName + '();\n'
        pluginsFileString += '}\n'
        self.fileWrite(fileName=moduleName + '_plugins.c', data=pluginsFileString)

        pluginsFileHeaderString = '#ifndef ' + moduleName.upper() + '_PLUGINS_H\n'
        pluginsFileHeaderString += '#define ' + moduleName.upper() + '_PLUGINS_H\n\n'
        pluginsFileHeaderString += 'void ops_snmp_init(void);\n'
        pluginsFileHeaderString += 'void ops_snmp_run(void);\n'
        pluginsFileHeaderString += 'void ops_snmp_wait(void);\n'
        pluginsFileHeaderString += 'void ops_snmp_shutdown(void);\n\n'
        pluginsFileHeaderString += '#endif'
        self.fileWrite(fileName=moduleName + '_plugins.h',data=pluginsFileHeaderString)

    def getOvsdbRowsForTable(self, tableName):
        if tableName not in self.jsonData or self.jsonData[tableName]['MibType'] != 'Table':
            return []
        tables = [self.jsonData[tableName]['RootOvsTable']]
        for col, val in self.jsonData[tableName]['Columns'].items():
            if val['OvsTable'] and val['OvsTable'] not in tables:
                tables.append(val['OvsTable'])
        for idx, val in self.jsonData[tableName]['Indexes'].items():
            if val['OvsTable'] and val['OvsTable'] not in tables:
                tables.append(val['OvsTable'])
        return tables

    def getOvsdbTableColumnsForTable(self, tableName):
        if tableName not in self.jsonData or self.jsonData[tableName]['MibType'] != 'Table':
            return []
        tables = []
        for col, val in self.jsonData[tableName]['Columns'].items():
            if val['OvsTable'] and (val['OvsTable'], val['OvsColumn']) not in tables:
                if isinstance(val['OvsColumn'],dict):
                    for individualCols in val['OvsColumn'].values():
                        tables.append((val['OvsTable'], individualCols))
                else:
                    tables.append((val['OvsTable'], val['OvsColumn']))
        for idx, val in self.jsonData[tableName]['Indexes'].items():
            if val['OvsTable'] and (val['OvsTable'], val['OvsColumn']) not in tables:
                tables.append((val['OvsTable'],val['OvsColumn']))
        return tables

    def getOvsdbRowsStringForTable(self, tableName):
        ovsdbTables = self.getOvsdbRowsForTable(tableName)
        #templateJsonObject = self.loadNetSnmpTemplateCodeFromFile('tableName_data_access.c.template')
        #tmplate = self.loadNetSnmpTemplateCodeFromFile('netsnmp_template_helper.txt')['@@SUBSTITUTE_OVSDB_ROW_STRINGS_FOR_TABLE@@']
        tmplate = self.getNetSnmpCodeTemplateFromHelperFile('ovsdb_table_row_ptr_declaration')
        outStr = ''
        for tbl in ovsdbTables :
#            tmpStr = """
#    const struct ovsrec_@@SUBSTITUTE_OVSDB_TABLE@@ *@@SUBSTITUTE_OVSDB_TABLE@@_row = NULL;
#"""
            tmpStr = tmplate
            tmpStr = tmpStr.replace('@@SUBSTITUTE_OVSDB_TABLE@@',tbl)
            outStr += tmpStr
        tmplate = ''
        return outStr + '\n'

    def getLocalsStringForTable(self, tableName):
        outStr = ''
        outStr += self.getAllIdxClmDeclarationsForGivenTable(tableName)
        outStr += '\n'
        outStr += self.getAllNonIdxClmDeclarationsForGivenTable(tableName)
        return outStr + '\n'

    def getFirstIntanceStringForTable(self, tableName):
        ovsdbTables = self.getOvsdbRowsForTable(tableName)
        outStr = ''
        for tbl in ovsdbTables:
#            tmpStr = """
#    @@SUBSTITUTE_OVSDB_TABLE@@_row = ovsrec_@@SUBSTITUTE_OVSDB_TABLE@@_first(idl);
#    if (!@@SUBSTITUTE_OVSDB_TABLE@@_row) {
#        snmp_log(LOG_ERR, "not able to fetch @@SUBSTITUTE_OVSDB_TABLE@@ row");
#        return -1;
#    }

#"""
            tmpStr = self.getNetSnmpCodeTemplateFromHelperFile('ovsdb_row_ptr_initialization')
            tmpStr = tmpStr.replace('@@SUBSTITUTE_OVSDB_TABLE@@',tbl)
            outStr += tmpStr
        return outStr

    def getTableSkipFnCall(self,tableName):
        outStr = ''
        if self.jsonData[tableName]['SkipFunction']:
            skipFnName = self.jsonData[tableName]['SkipFunction']
            rootOvsTable = self.jsonData[tableName]['RootOvsTable']
#            outStr = """
#    if(@@SUBSTITUTE_SKIP_FN_NAME@@(idl, @@SUBSTITUTE_ROOT_OVS_TBL@@_row)) {
#        continue;
#    }
#"""
            outstr = self.getNetSnmpCodeTemplateFromHelperFile('skip_fn_call_statement')

#            tmpCusFileHdrStr = """
#int @@SUBSTITUTE_SKIP_FN_NAME@@(struct ovsdb_idl *idl,
#                                const struct ovsrec_@@SUBSTITUTE_ROOT_OVS_TBL@@ *@@SUBSTITUTE_ROOT_OVS_TBL@@_row);

#"""
            tmpCusFileHdrStr = self.getNetSnmpCodeTemplateFromHelperFile('skip_fn_declaration')
            tmpCusFileHdrStr = tmpCusFileHdrStr.replace('@@SUBSTITUTE_SKIP_FN_NAME@@',skipFnName)
            tmpCusFileHdrStr = tmpCusFileHdrStr.replace('@@SUBSTITUTE_ROOT_OVS_TBL@@',rootOvsTable)
            self.customFileHeaderString += tmpCusFileHdrStr

            outStr = outStr.replace('@@SUBSTITUTE_SKIP_FN_NAME@@',skipFnName)
            outStr = outStr.replace('@@SUBSTITUTE_ROOT_OVS_TBL@@',rootOvsTable)
        return outStr

    def getOvsdbGetForGivenClmOrIdx(self,tableName,rootOvsTbl,clmOrIdxSymbol,useSchemaSpecifiedCardinality,tmpAppendTypeBasedFlagParameter):
        tmpStr = ''
        appendTypeBasedFlagParameter = tmpAppendTypeBasedFlagParameter
        if useSchemaSpecifiedCardinality:
            #if idx['name'] in self.jsonData[tableName]['Table_MibColumnsParticipatingInMultipleCardinality']:
            if self.mibObjectParticipatesInMultipleCardinality(tableName,clmOrIdxSymbol):
                appendTypeBasedFlagParameter = tmpAppendTypeBasedFlagParameter
            else:
                appendTypeBasedFlagParameter = ''

        dbIdx = self.getSchemaDataObjectFromMappingFileForGivenMibObject(tableName,clmOrIdxSymbol)
        idxTable = dbIdx['OvsTable']
        idxType = self.getObjTypeString(clmOrIdxSymbol)
        if idxTable and idxTable != rootOvsTbl:
            if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
                #outStr += 'ovsdb_get_' + idx['name'] + '(idl, ' + table + '_row, ' + idxTable + '_row, ' + idx['name'] + ', &' + idx['name'] + '_len);\n'
#                tmpStr = """
#    ovsdb_get_@@SUBSTITUTE_IDX_OR_CLM_NAME@@(idl, @@SUBSTITUTE_ROOT_OVS_TBL@@_row, @@SUBSTITUTE_LOCAL_OVS_TBL@@_row, @@SUBSTITUTE_IDX_OR_CLM_NAME@@, &@@SUBSTITUTE_IDX_OR_CLM_NAME@@_len @@SUBSTITUTE_APPEND_TYPE_BASED_FLAG_PARAM@@);
#"""
                tmpStr = self.getNetSnmpCodeTemplateFromHelperFile('ovsdb_get_fn_call_with_ovstable_and_string_type')
            else:
                #outStr += 'ovsdb_get_' + idx['name'] + '(idl, ' + table + '_row, ' + idxTable + '_row, &' + idx['name'] + ');\n'
#                tmpStr = """
#    ovsdb_get_@@SUBSTITUTE_IDX_OR_CLM_NAME@@(idl, @@SUBSTITUTE_ROOT_OVS_TBL@@_row, @@SUBSTITUTE_LOCAL_OVS_TBL@@_row, &@@SUBSTITUTE_IDX_OR_CLM_NAME@@ @@SUBSTITUTE_APPEND_TYPE_BASED_FLAG_PARAM@@);
#"""
                tmpStr = self.getNetSnmpCodeTemplateFromHelperFile('ovsdb_get_fn_call_with_ovstable_and_primitive_type')
        else:
            if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
                #outStr += 'ovsdb_get_' + idx['name'] + '(idl, ' + table + '_row, ' + idx['name'] + ', &' + idx['name'] + '_len);\n'
#                tmpStr = """
#    ovsdb_get_@@SUBSTITUTE_IDX_OR_CLM_NAME@@(idl, @@SUBSTITUTE_ROOT_OVS_TBL@@_row, @@SUBSTITUTE_IDX_OR_CLM_NAME@@, &@@SUBSTITUTE_IDX_OR_CLM_NAME@@_len @@SUBSTITUTE_APPEND_TYPE_BASED_FLAG_PARAM@@);
#"""
                tmpStr = self.getNetSnmpCodeTemplateFromHelperFile('ovsdb_get_fn_call_with_root_ovstable_and_string_type')
            else:
                #outStr += 'ovsdb_get_' + idx['name'] + '(idl, ' + table + '_row, &' + idx['name'] + ');\n'
#                tmpStr = """
#    ovsdb_get_@@SUBSTITUTE_IDX_OR_CLM_NAME@@(idl, @@SUBSTITUTE_ROOT_OVS_TBL@@_row, &@@SUBSTITUTE_IDX_OR_CLM_NAME@@ @@SUBSTITUTE_APPEND_TYPE_BASED_FLAG_PARAM@@);
#"""
                tmpStr = self.getNetSnmpCodeTemplateFromHelperFile('ovsdb_get_fn_call_with_root_ovstable_and_primitive_type')
        tmpStr += '\n'
        tmpStr = tmpStr.replace('@@SUBSTITUTE_ROOT_OVS_TBL@@',rootOvsTbl)
        if idxTable:
            tmpStr = tmpStr.replace('@@SUBSTITUTE_LOCAL_OVS_TBL@@',idxTable)
        tmpStr = tmpStr.replace('@@SUBSTITUTE_APPEND_TYPE_BASED_FLAG_PARAM@@',appendTypeBasedFlagParameter)
        tmpStr = self.parseColSpecificSubstitutionsAndReturnActualString(tmpStr,tableName,clmOrIdxSymbol)

        return tmpStr


    def getOvsdbGetFnCallsForAllClms(self,tableName,rootOvsTbl,indexes,useSchemaSpecifiedCardinality,tmpAppendTypeBasedFlagParameter):
        tmpStr = ''

        for idx in indexes:
            tmpStr += self.getOvsdbGetForGivenClmOrIdx(tableName,rootOvsTbl,idx,useSchemaSpecifiedCardinality,tmpAppendTypeBasedFlagParameter)

        for col in self.tableRows[self.tables[tableName]['row']]['columns']:
            if col['name'] in [idx['name'] for idx in indexes]:
                continue
            tmpStr += self.getOvsdbGetForGivenClmOrIdx(tableName,rootOvsTbl,col,useSchemaSpecifiedCardinality,tmpAppendTypeBasedFlagParameter)

        outStr = """
    rowreq_ctx = @@SUBSTITUTE_TABLE_NAME@@_allocate_rowreq_ctx(NULL);

    if (rowreq_ctx == NULL) {
        snmp_log(LOG_ERR, "memory allocation failed");
        return MFD_RESOURCE_UNAVAILABLE;
    }

    if (MFD_SUCCESS != @@SUBSTITUTE_TABLE_NAME@@_indexes_set( rowreq_ctx @@SUBSTITUTE_ALL_LOCAL_IDX_COL_DECLNS_AS_FUNC_CALL_PARAMS@@) ) {
        snmp_log(LOG_ERR, "error setting indexes while loading");
        @@SUBSTITUTE_TABLE_NAME@@_release_rowreq_ctx(rowreq_ctx);
        continue;
    }

    @@SUBSTITUTE_POPULATE_VALUES_INTO_SNMP_ROW_REQ_PTR@@

    CONTAINER_INSERT(container, rowreq_ctx);
    ++count;

"""

        row_idx_params = ''
        for idx in indexes:
            idxType = self.getObjTypeString(idx)
            if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
                row_idx_params  += ', ' + idx['name'] + ', ' + idx['name'] + '_len'
            else:
                row_idx_params  += ', ' + idx['name']

        row_req_single_col_populated_vals = ''
        row_req_all_col_populated_vals = ''
        for col in self.tableRows[self.tables[tableName]['row']]['columns']:
            if col['name'] in [idx['name'] for idx in indexes]:
                continue
            colType = self.getObjTypeString(col)
            if colType == 'OctetString' or colType == 'ObjectIdentifier':
                row_req_single_col_populated_vals = """
    rowreq_ctx->data.@@SUBSTITUTE_IDX_OR_CLM_NAME@@_len = @@SUBSTITUTE_IDX_OR_CLM_NAME@@_len* sizeof(@@SUBSTITUTE_IDX_OR_CLM_NAME@@[0]);
    memcpy(rowreq_ctx->data.@@SUBSTITUTE_IDX_OR_CLM_NAME@@,@@SUBSTITUTE_IDX_OR_CLM_NAME@@,@@SUBSTITUTE_IDX_OR_CLM_NAME@@_len* sizeof(@@SUBSTITUTE_IDX_OR_CLM_NAME@@[0]));
"""
            else:
                row_req_single_col_populated_vals = """
    rowreq_ctx->data.@@SUBSTITUTE_IDX_OR_CLM_NAME@@ = @@SUBSTITUTE_IDX_OR_CLM_NAME@@;
"""
            row_req_single_col_populated_vals = row_req_single_col_populated_vals.replace('@@SUBSTITUTE_IDX_OR_CLM_NAME@@', col['name'])
            row_req_all_col_populated_vals += row_req_single_col_populated_vals

        outStr = outStr.replace('@@SUBSTITUTE_TABLE_NAME@@',tableName)
        outStr = outStr.replace('@@SUBSTITUTE_ALL_LOCAL_IDX_COL_DECLNS_AS_FUNC_CALL_PARAMS@@',row_idx_params)
        outStr = outStr.replace('@@SUBSTITUTE_POPULATE_VALUES_INTO_SNMP_ROW_REQ_PTR@@',row_req_all_col_populated_vals)

        tmpStr += outStr
        return tmpStr


    def getOvsdbGetFnCallsForAllConditionTypes(self,tableName,rootOvsTbl,indexes,useSchemaSpecifiedCardinality) :
        repeatCount = 1;
        generateForIpv4 = False
        outStr = ''
        tmpStr = ''
        appendTypeBasedFlagParameter = ''

        if useSchemaSpecifiedCardinality:
            repeatCount = self.tables[tableName]['Table_MibSchemaCardinalityCount']
        else:
            if(self.tables[tableName]['supportsBothIpv4Ipv6']):
                #appendTypeBasedFlagParameter = " ,int isIpv4" #must always be the last parameter of the function
                generateForIpv4 = True
                repeatCount = 2;
            else:
                #appendTypeBasedFlagParameter = "" #must always be the last parameter of the function
                repeatCount = 1;

        #repeat the following entire block (till return statement excluding return statement) within 2 iff's
        #one for ipv4 and one for ipv6
        while(repeatCount > 0):

            if useSchemaSpecifiedCardinality:
                tmpAppendTypeBasedFlagParameterName = self.tables[tableName]['CardinalityConditionTypeConstants'].values()[self.tables[tableName]['Table_MibSchemaCardinalityCount'] - repeatCount]
                tmpAppendTypeBasedFlagParameter = ', '+tmpAppendTypeBasedFlagParameterName
                appendTypeBasedFlagParameter = tmpAppendTypeBasedFlagParameter
#                tmpStr = """
#    if(@@SUBSTITUTE_APPEND_PARAM_NAME_LOWER@@_check_custom_function(idl,@@SUBSTITUTE_ROOT_OVS_TBL@@_row)) {

#        @@SUBSTITUTE_OVSDB_GET_FN_CALL_FOR_ALL_IDX_OR_CLM@@

#    }
#"""
                tmpStr = self.getNetSnmpCodeTemplateFromHelperFile('ovsdb_get_for_multiple_type_support')
                tmpStr = tmpStr.replace('@@SUBSTITUTE_APPEND_PARAM_NAME_LOWER@@',tmpAppendTypeBasedFlagParameterName.lower())

#                tmpFnPrototype = """
#int @@SUBSTITUTE_APPEND_PARAM_NAME_LOWER@@_check_custom_function(
#                                                                  struct ovsdb_idl *idl, 
#                                                                  const struct ovsrec_@@SUBSTITUTE_ROOT_OVS_TBL@@ *@@SUBSTITUTE_ROOT_OVS_TBL@@_row)"""
                tmpFnPrototype = self.getNetSnmpCodeTemplateFromHelperFile('multiple_type_support_check_custom_fn_prototype')
                tmpFnPrototype = tmpFnPrototype.replace('@@SUBSTITUTE_APPEND_PARAM_NAME_LOWER@@',tmpAppendTypeBasedFlagParameterName.lower())
                tmpFnPrototype = tmpFnPrototype.replace('@@SUBSTITUTE_ROOT_OVS_TBL@@',rootOvsTbl)


#                tmpFnBody = """
#    /*return 1 - if @@SUBSTITUTE_APPEND_PARAM_NAME@@ type or */
#    /*return 0 - if not @@SUBSTITUTE_APPEND_PARAM_NAME@@ type */
#"""
                tmpFnBody = self.getNetSnmpCodeTemplateFromHelperFile('multiple_type_support_check_custom_fn_body')

                tmpFnBody = tmpFnBody.replace('@@SUBSTITUTE_ROOT_OVS_TBL@@',rootOvsTbl)
                tmpFnBody = tmpFnBody.replace('@@SUBSTITUTE_APPEND_PARAM_NAME@@',tmpAppendTypeBasedFlagParameterName)

                self.customFileHeaderString += tmpFnPrototype + ';\n\n'
                self.customFileString += self.getCustomFnDefinitions(tmpFnPrototype,tmpFnBody)
                #self.customFileHeaderString += 'int ' + tmpAppendTypeBasedFlagParameterName.lower()  + '_check_custom_function(struct ovsdb_idl *idl, const struct ovsrec_' + table + ' *' + table + '_row);\n\n'
                #self.customFileString += 'int ' + tmpAppendTypeBasedFlagParameterName.lower()  + '_check_custom_function(struct ovsdb_idl *idl, const struct ovsrec_' + table + ' *' + table + '_row) {\n'
                #self.customFileString += ' **** TO COMPLETE THIS FUNCTION ****\n /*return 1 - if ' +tmpAppendTypeBasedFlagParameterName   + ' type or */\n /*return 0 - if not ' + tmpAppendTypeBasedFlagParameterName+ ' type */\n }\n\n'
            elif(self.tables[tableName]['supportsBothIpv4Ipv6']):
                if(generateForIpv4):
                    appendTypeBasedFlagParameter = ', 1'
                    #outStr += 'if(' + table + 'Table_check_inetv4_custom_function(idl,' + table + '_row)) {\n'
#                    tmpStr = """
#if(@@SUBSTITUTE_ROOT_OVS_TBL@@Table_check_inetv4_custom_function(idl,@@SUBSTITUTE_ROOT_OVS_TBL@@_row)) {

#    @@SUBSTITUTE_OVSDB_GET_FN_CALL_FOR_ALL_IDX_OR_CLM@@

#}
#"""
                    tmpStr = self.getNetSnmpCodeTemplateFromHelperFile('ovsdb_get_for_inetv4_type')

#                    tmpFnPrototype = """
#int @@SUBSTITUTE_ROOT_OVS_TBL@@Table_check_inetv4_custom_function(
#                            struct ovsdb_idl *idl,
#                            const struct ovsrec_@@SUBSTITUTE_ROOT_OVS_TBL@@ *@@SUBSTITUTE_ROOT_OVS_TBL@@_row)"""
                    tmpFnPrototype = self.getNetSnmpCodeTemplateFromHelperFile('inetv4_type_check_custom_fn_prototype')
                    tmpFnPrototype = tmpFnPrototype.replace('@@SUBSTITUTE_ROOT_OVS_TBL@@',rootOvsTbl)

#                    tmpFnBody = """
#/*return 1 - if ipv4 version*/
#/*return 0 - if not ipv4 version*/
#"""
                    tmpFnBody = self.getNetSnmpCodeTemplateFromHelperFile('inetv4_type_check_custom_fn_body')

                    self.customFileHeaderString += tmpFnPrototype + ';\n\n'
                    self.customFileString += self.getCustomFnDefinitions(tmpFnPrototype,tmpFnBody)
                    #self.customFileHeaderString += 'int ' + table + 'Table_check_inetv4_custom_function(struct ovsdb_idl *idl, const struct ovsrec_' + table + ' *' + table + '_row);\n\n'
                    #self.customFileString += 'int ' + table + 'Table_check_inetv4_custom_function(struct ovsdb_idl *idl, const struct ovsrec_' + table + ' *' + table + '_row) {\n'
                    #self.customFileString += ' **** TO COMPLETE THIS FUNCTION ****\n /*return 1 - if ipv4 version*/\n /*return 0 - if not ipv4 version*/\n }\n\n'
                else:
                    appendTypeBasedFlagParameter = ', 0'
                    #outStr += 'if(' + table + 'Table_check_inetv6_custom_function(idl,' + table + '_row)) {\n'
#                    tmpStr = """
#if(@@SUBSTITUTE_ROOT_OVS_TBL@@Table_check_inetv6_custom_function(idl,@@SUBSTITUTE_ROOT_OVS_TBL@@_row)) {

#    @@SUBSTITUTE_OVSDB_GET_FN_CALL_FOR_ALL_IDX_OR_CLM@@

#}
#"""
                    tmpStr = self.getNetSnmpCodeTemplateFromHelperFile('ovsdb_get_for_inetv6_type')

#                    tmpFnPrototype = """
#int @@SUBSTITUTE_ROOT_OVS_TBL@@Table_check_inetv6_custom_function(
#                                                                struct ovsdb_idl *idl, 
#                                                                const struct ovsrec_@@SUBSTITUTE_ROOT_OVS_TBL@@ *@@SUBSTITUTE_ROOT_OVS_TBL@@_row)"""
                    tmpFnPrototype = self.getNetSnmpCodeTemplateFromHelperFile('inetv6_type_check_custom_fn_prototype')
                    tmpFnPrototype = tmpFnPrototype.replace('@@SUBSTITUTE_ROOT_OVS_TBL@@',rootOvsTbl)

#                    tmpFnBody = """
#/*return 1 - if ipv6 version*/
#/*return 0 - if not ipv6 version*/
#"""
                    tmpFnBody = self.getNetSnmpCodeTemplateFromHelperFile('inetv6_type_check_custom_fn_body')
                    self.customFileHeaderString += tmpFnPrototype + ';\n\n'
                    self.customFileString += self.getCustomFnDefinitions(tmpFnPrototype,tmpFnBody)
                    #self.customFileHeaderString += 'int ' + table + 'Table_check_inetv6_custom_function(struct ovsdb_idl *idl, const struct ovsrec_' + table + ' *' + table + '_row);\n\n'
                    #self.customFileString += 'int ' + table + 'Table_check_inetv6_custom_function(struct ovsdb_idl *idl, const struct ovsrec_' + table + ' *' + table + '_row) {\n'                    self.customFileString += ' **** TO DO : COMPLETE THIS FUNCTION ****\n /*return 1 - if ipv6 version*/ \n /*return 0 - if not ipv6 version*/ \n }\n\n'
            else:#if there are no condition types at all..
                appendTypeBasedFlagParameter = ''
#                tmpStr = """
#    @@SUBSTITUTE_OVSDB_GET_FN_CALL_FOR_ALL_IDX_OR_CLM@@
#"""
                tmpStr = self.getNetSnmpCodeTemplateFromHelperFile('ovsdb_get_for_single_type')

            tmpStr = tmpStr.replace('@@SUBSTITUTE_ROOT_OVS_TBL@@',rootOvsTbl)
            tmpStr = tmpStr.replace('@@SUBSTITUTE_OVSDB_GET_FN_CALL_FOR_ALL_IDX_OR_CLM@@',self.getOvsdbGetFnCallsForAllClms(tableName,rootOvsTbl ,indexes,useSchemaSpecifiedCardinality,appendTypeBasedFlagParameter))

            outStr += tmpStr

            generateForIpv4 = False
            repeatCount -= 1
            ##substitute each time in this loop...

        #end of python repetetion while loop..
        return outStr


    def getForLoopStringForTable(self, tableName):
        indexes = self.getIndexesForTable(tableName)
        outStr = ''
        table = self.jsonData[tableName]['RootOvsTable']
        useSchemaSpecifiedCardinality = self.doesTableSupportMultipleCardinality(tableName)

#        outStr += """
#    OVSREC_@@SUBSTITUTE_ROOT_OVS_TBL_UPPER@@_FOR_EACH(@@SUBSTITUTE_ROOT_OVS_TBL@@_row, idl) {

#        @@SUBSTITUTE_TABLE_SKIP_FN_CALL@@

#        @@SUBSTITUTE_OVSDB_GET_FN_CALL_FOR_ALL_CONDITION_TYPES@@

#    }//end of for-each loop..

#"""
        outStr = self.getNetSnmpCodeTemplateFromHelperFile('container_load_ovsrec_for_each_body')

        outStr = outStr.replace('@@SUBSTITUTE_ROOT_OVS_TBL@@',table)
        outStr = outStr.replace('@@SUBSTITUTE_ROOT_OVS_TBL_UPPER@@',table.upper())
        outStr = outStr.replace('@@SUBSTITUTE_TABLE_SKIP_FN_CALL@@',self.getTableSkipFnCall(tableName))
        outStr = outStr.replace('@@SUBSTITUTE_OVSDB_GET_FN_CALL_FOR_ALL_CONDITION_TYPES@@', self.getOvsdbGetFnCallsForAllConditionTypes(tableName,table,indexes,useSchemaSpecifiedCardinality))

        return outStr


    def getIndexesForTable(self, tableName):
        indexes = []
        for col in self.tableRows[self.tables[tableName]['row']]['index']:
            indexes.append(self._out[col])
        if len(indexes) is 0:
            augment = self.tableRows[self.tables[tableName]['row']]['data']['augmention']
            for col in self.tableRows[augment]['index']:
                indexes.append(self._out[col])
        return indexes


    def getNonIdxClmsOfGivenTable(self,tableName):
        clms = []
        for col in self.tableRows[self.tables[tableName]['row']]['columns']:
            if col['name'] not in self.tableRows[self.tables[tableName]['row']]['index']:
            #if col['name'] not in [idx['name'] for idx in indexes]:
                clms.append(col)
        return clms

    def getAllClmsOfGivenTable(self,tableName):
        clms = []
        for col in self.tableRows[self.tables[tableName]['row']]['columns']:
                clms.append(col)
        return clms

    def getIdxOrClmSize(self,tableName,clmOrIdx):
        if self.getObjTypeString(clmOrIdx) == 'OctetString':
            stringLength = self.getStringLength(clmOrIdx)
            return str(stringLength)
        elif self.getObjTypeString(clmOrIdx) == 'ObjectIdentifier':
            return 'MAX_OID_LEN'
        else:
            return ''

    def getIdxOrColTypeEquivalentInC(self,tableName,clmOrIdx):
        if self.getObjTypeString(clmOrIdx) == 'OctetString':
            return 'char'
        elif self.getObjTypeString(clmOrIdx) == 'ObjectIdentifier':
            return 'oid'
            # Verify if this is the thing for oid
        else:
            return self.ctypeClasses[self.getObjTypeString(clmOrIdx)]

    def getIdxOrClmDeclarationOfGivenTableIdxOrClm(self,tableName,clmOrIdx):
        tmpStr = ''
        clmOrIdxName = clmOrIdx['name']
        if self.getObjTypeString(clmOrIdx) == 'OctetString':
            stringLength = self.getStringLength(clmOrIdx)
#            tmpStr = """
#@@SUBSTITUTE_GET_OBJECT_TYPE_EQUIVALENT_IN_C@@ @@SUBSTITUTE_IDX_OR_CLM_NAME@@[@@COLUMN_OR_IDX_SIZE@@];
#size_t @@SUBSTITUTE_IDX_OR_CLM_NAME@@_len;
#"""
            #tmpStr = self.loadNetSnmpTemplateCodeFromFile('netsnmp_template_helper.txt')['@@SUBSTITUTE_GET_MIB_OBJ_DECL_FOR_OCTET_STR_MIB_TYPE@@']
            tmpStr = self.getNetSnmpCodeTemplateFromHelperFile('octet_str_mib_type_declaration')

        elif self.getObjTypeString(clmOrIdx) == 'ObjectIdentifier':
#            tmpStr = """
#@@SUBSTITUTE_GET_OBJECT_TYPE_EQUIVALENT_IN_C@@ @@SUBSTITUTE_IDX_OR_CLM_NAME@@[@@COLUMN_OR_IDX_SIZE@@];
#size_t @@SUBSTITUTE_IDX_OR_CLM_NAME@@_len;
#"""
            #tmpStr = self.loadNetSnmpTemplateCodeFromFile('netsnmp_template_helper.txt')['@@SUBSTITUTE_GET_MIB_OBJ_DECL_FOR_OBJ_IDENTIFIER_MIB_TYPE@@']
            tmpStr = self.getNetSnmpCodeTemplateFromHelperFile('obj_identifier_mib_type_declaration')

        else:
#            tmpStr = """
#@@SUBSTITUTE_GET_OBJECT_TYPE_EQUIVALENT_IN_C@@ @@SUBSTITUTE_IDX_OR_CLM_NAME@@;
#"""
            #tmpStr = self.loadNetSnmpTemplateCodeFromFile('netsnmp_template_helper.txt')['@@SUBSTITUTE_GET_MIB_OBJ_DECL_FOR_PRIMITIVE_MIB_TYPE@@']
            tmpStr = self.getNetSnmpCodeTemplateFromHelperFile('primitive_mib_type_declaration')
        tmpStr = self.parseColSpecificSubstitutionsAndReturnActualString(tmpStr,tableName,clmOrIdx)
        return tmpStr


    def getAllNonIdxClmDeclarationsForGivenTable(self,tableName):
        tmpStr = ''
        colms = self.getNonIdxClmsOfGivenTable(tableName)
        for col in colms :
                tmpStr += self.getIdxOrClmDeclarationOfGivenTableIdxOrClm(tableName,col)
        return tmpStr

    def getAllIdxClmDeclarationsForGivenTable(self,tableName):
        tmpStr = ''
        indexes = self.getIndexesForTable(tableName)
        for idx in indexes:
            tmpStr += self.getIdxOrClmDeclarationOfGivenTableIdxOrClm(tableName,idx)
        return tmpStr

    def getOidForGivenTable(self,tableName):
        oidStr,parentOid = self.tables[tableName]['data']['oid']
        oidStr = oidStr.replace('[','').replace(']','')
        return oidStr

    def getMaxNonIdxColumnForGivenTable(self,tableName):
        return self.tableRows[self.tables[tableName]['row']]['columns'][-1]['name'].upper()

    def getMinNonIdxColumnForGivenTable(self,tableName):
        minColumn = None
        allCols = self.getAllClmsOfGivenTable(tableName)
        indexes = self.getIndexesForTable(tableName)
        for col in allCols:
            if col not in indexes and not minColumn:
                minColumn = col
                break
        return minColumn['name'].upper()

    def getIdxOrClmOid(self,tableName,clmOrIdxSym):
        tempOid, tempParentOid = clmOrIdxSym['oid']
        tempOid = tempOid[tempOid.rfind(',') + 1:tempOid.rfind(']')]
        return tempOid

    def getClmnOidHashDefinesForGivenTable(self,tableName,clmOrIdxSym):
        hashDefine = """
#define COLUMN_@@SUBSTITUTE_IDX_OR_CLM_NAME_UPPER@@ @@SUBSTITUTE_COLUMN_OID@@
"""
        hashDefine = self.parseColSpecificSubstitutionsAndReturnActualString(hashDefine,tableName,clmOrIdxSym)
        return hashDefine

    def getHashDefinesOfAllColumnOidsForGivenTable(self,tableName):
        minColumn = None
        allTableCols = self.getAllClmsOfGivenTable(tableName)
        tmpStr = ''
        for col in allTableCols:
            #if col not in indexes and not minColumn:
            #    minColumn = col
            tmpStr += self.getClmnOidHashDefinesForGivenTable(tableName,col)
        return tmpStr



    def getTblColOrIdxDblIndirectionDecls4FnDefnParam(self,tableName,idxOrClmSymbol):
        symbolDeclAsFuncParameter = ''
        idxName = idxOrClmSymbol['name']
        idxType = self.getObjTypeString(idxOrClmSymbol)
        if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
            #tableDataGetString += ', '
            symbolDeclAsFuncParameter = """
@@SUBSTITUTE_GET_OBJECT_TYPE_EQUIVALENT_IN_C@@ **@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_ptr , size_t* @@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_len_ptr
"""
        else:
            symbolDeclAsFuncParameter = """
@@SUBSTITUTE_GET_OBJECT_TYPE_EQUIVALENT_IN_C@@ *@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr
"""
        symbolDeclAsFuncParameter = self.parseColSpecificSubstitutionsAndReturnActualString(symbolDeclAsFuncParameter,tableName,idxOrClmSymbol)
        return symbolDeclAsFuncParameter



    def getDeclarationOfTblClmOrIdxAsFunctionDefnParameter4IndexesSetFn(self,tableName,idxOrClmSymbol):
        symbolDeclAsFuncParameter = ''
        idxName = idxOrClmSymbol['name']
        idxType = self.getObjTypeString(idxOrClmSymbol)
        if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
            symbolDeclAsFuncParameter = """
@@SUBSTITUTE_GET_OBJECT_TYPE_EQUIVALENT_IN_C@@ *@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr , size_t @@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_len
"""
                # Verify if this is the thing for oid
        else:
            #symbolDeclAsFuncParameter += ', ' + self.ctypeClasses[idxType] + ' ' + idx['name'] + '_val'
            symbolDeclAsFuncParameter = """
@@SUBSTITUTE_GET_OBJECT_TYPE_EQUIVALENT_IN_C@@ @@SUBSTITUTE_IDX_OR_CLM_NAME@@_val
"""

        symbolDeclAsFuncParameter = self.parseColSpecificSubstitutionsAndReturnActualString(symbolDeclAsFuncParameter,tableName,idxOrClmSymbol)
        return symbolDeclAsFuncParameter


    def getDeclarationOfTblClmOrIdxAsFunctionCallParameter4IndexesSetFn(self,tableName,idxOrClmSymbol):
        symbolDeclAsFuncParameter = ''
        idxName = idxOrClmSymbol['name']
        idxType = self.getObjTypeString(idxOrClmSymbol)
        if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
            symbolDeclAsFuncParameter = """
@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr , @@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_len
"""
        else:
            symbolDeclAsFuncParameter = """
@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val
"""
        symbolDeclAsFuncParameter = self.parseColSpecificSubstitutionsAndReturnActualString(symbolDeclAsFuncParameter,tableName,idxOrClmSymbol)
        return symbolDeclAsFuncParameter



    def getDeclarationOfTblClmOrIdxAsFunctionDefnParameter4OvsdbGetFn(self,tableName,idxOrClmSymbol):
        symbolDeclAsFuncParameter = ''
        idxName = idxOrClmSymbol['name']
        idxType = self.getObjTypeString(idxOrClmSymbol)
        if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
            symbolDeclAsFuncParameter = """ @@SUBSTITUTE_GET_OBJECT_TYPE_EQUIVALENT_IN_C@@ *@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr , size_t * @@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_len
"""
                # Verify if this is the thing for oid
        else:
            symbolDeclAsFuncParameter = """ @@SUBSTITUTE_GET_OBJECT_TYPE_EQUIVALENT_IN_C@@ *@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr
"""

        symbolDeclAsFuncParameter = self.parseColSpecificSubstitutionsAndReturnActualString(symbolDeclAsFuncParameter,tableName,idxOrClmSymbol)
        return symbolDeclAsFuncParameter



    def getDeclarationOfTblClmOrIdxAsFunctionCallParameter4OvsdbGetFn(self,tableName,idxOrClmSymbol):
        symbolDeclAsFuncParameter = ''
        idxName = idxOrClmSymbol['name']
        idxType = self.getObjTypeString(idxOrClmSymbol)
        if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
            symbolDeclAsFuncParameter = """ @@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr , @@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_len
"""
        else:
            symbolDeclAsFuncParameter = """ @@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr
"""
        symbolDeclAsFuncParameter = self.parseColSpecificSubstitutionsAndReturnActualString(symbolDeclAsFuncParameter,tableName,idxOrClmSymbol)
        return symbolDeclAsFuncParameter


    def getDeclarationsOfAllIndexColumnsAsFunctionDefinitionParameters4IndexesSetFn(self,tableName):
        idxDeclarationsList = []
        indexes = self.getIndexesForTable(tableName)
        for idx in indexes:
            idxDeclarationsList.append(self.getDeclarationOfTblClmOrIdxAsFunctionDefnParameter4IndexesSetFn(tableName,idx))
        idxDeclarations = ', '.join(idxDeclarationsList);
        return idxDeclarations

    def getDeclarationsOfAllIndxColumnsAsFunctionCallParameters4IndexesSetFn(self,tableName):
        idxDeclarationsList = []
        indexes = self.getIndexesForTable(tableName)
        for idx in indexes:
            idxDeclarationsList.append(self.getDeclarationOfTblClmOrIdxAsFunctionCallParameter4IndexesSetFn(tableName,idx))
        idxDeclarations = ', '.join(idxDeclarationsList);
        return idxDeclarations

    def getSetTblIdxStatementForGivenIdx(self,tableName,tableIndex):
        idx = tableIndex
        tmpStr = ''
        idxType = self.getObjTypeString(idx)
        idxName = idx['name']
        if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
            tmpStr = """
tbl_idx->@@SUBSTITUTE_IDX_OR_CLM_NAME@@_len = sizeof(tbl_idx->@@SUBSTITUTE_IDX_OR_CLM_NAME@@)/sizeof(tbl_idx->@@SUBSTITUTE_IDX_OR_CLM_NAME@@[0]);
if ((NULL == tbl_idx->@@SUBSTITUTE_IDX_OR_CLM_NAME@@) || (tbl_idx->@@SUBSTITUTE_IDX_OR_CLM_NAME@@_len < (@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_len))) {
    snmp_log(LOG_ERR, "not enough space for value (@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr)\\n");
    return MFD_ERROR;
}
tbl_idx->@@SUBSTITUTE_IDX_OR_CLM_NAME@@_len = @@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_len;
memcpy(tbl_idx->@@SUBSTITUTE_IDX_OR_CLM_NAME@@, @@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr, @@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_len* sizeof(@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr[0]));
"""
        else:
            tmpStr = """
tbl_idx->@@SUBSTITUTE_IDX_OR_CLM_NAME@@ = @@SUBSTITUTE_IDX_OR_CLM_NAME@@_val;
"""
        tmpStr = self.parseColSpecificSubstitutionsAndReturnActualString(tmpStr,tableName,tableIndex)
        return tmpStr

    def getSetTblIdxStatements(self,tableName):
        indexes = self.getIndexesForTable(tableName)
        tmpStr = ''
        for idx in indexes:
            tmpStr += self.getSetTblIdxStatementForGivenIdx(tableName,idx)
        return tmpStr

    def getNetSnmpAssertStatements4ColOrIdxDblIndirectionParam(self,tableName,idxOrClmSymbol):
        idxName = idxOrClmSymbol['name']
        idxType = self.getObjTypeString(idxOrClmSymbol)
        tableDataGetString = ''
        if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
            tableDataGetString = """
netsnmp_assert( (NULL != @@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_ptr) && (NULL != *@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_ptr));
netsnmp_assert(NULL != @@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_len_ptr);
"""
        else:
            tableDataGetString = """
netsnmp_assert(NULL != @@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr);
"""
        tableDataGetString = self.parseColSpecificSubstitutionsAndReturnActualString(tableDataGetString,tableName,idxOrClmSymbol)
        return tableDataGetString

    def getTblColGetFnBodyForColumnGetFn(self,tableName,colOrIdxSymbol):
        colName = colOrIdxSymbol['name']
        idxType = self.getObjTypeString(colOrIdxSymbol)
        if colOrIdxSymbol in self.getIndexesForTable(tableName):
            if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
                tableDataGetString = """
    if ((NULL == (*@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_ptr)) || ((*@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_len_ptr) < (rowreq_ctx->tbl_idx.@@SUBSTITUTE_IDX_OR_CLM_NAME@@_len* sizeof(rowreq_ctx->tbl_idx.@@SUBSTITUTE_IDX_OR_CLM_NAME@@[0])))) {
        (* @@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_ptr) = malloc(rowreq_ctx->tbl_idx.@@SUBSTITUTE_IDX_OR_CLM_NAME@@_len* sizeof(rowreq_ctx->tbl_idx.@@SUBSTITUTE_IDX_OR_CLM_NAME@@[0]));
        if (NULL == (*@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_ptr)) {
            snmp_log(LOG_ERR, "could not allocate memory (rowreq_ctx->tbl_idx.@@SUBSTITUTE_IDX_OR_CLM_NAME@@)\\n");
            return MFD_ERROR;
        }
    }
    (* @@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_len_ptr) = rowreq_ctx->tbl_idx.@@SUBSTITUTE_IDX_OR_CLM_NAME@@_len* sizeof(rowreq_ctx->tbl_idx.@@SUBSTITUTE_IDX_OR_CLM_NAME@@[0]);
    memcpy((*@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_ptr), rowreq_ctx->tbl_idx.@@SUBSTITUTE_IDX_OR_CLM_NAME@@, rowreq_ctx->tbl_idx.@@SUBSTITUTE_IDX_OR_CLM_NAME@@_len* sizeof(rowreq_ctx->tbl_idx.@@SUBSTITUTE_IDX_OR_CLM_NAME@@[0]));

    """
            else:
                tableDataGetString = """
    (*@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr) = rowreq_ctx->tbl_idx.@@SUBSTITUTE_IDX_OR_CLM_NAME@@;
    """
        else:
            if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
                tableDataGetString = """
    if ((NULL == (*@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_ptr)) || ((*@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_len_ptr) < (rowreq_ctx->data.@@SUBSTITUTE_IDX_OR_CLM_NAME@@_len* sizeof(rowreq_ctx->data.@@SUBSTITUTE_IDX_OR_CLM_NAME@@[0])))) {
        (* @@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_ptr) = malloc(rowreq_ctx->data.@@SUBSTITUTE_IDX_OR_CLM_NAME@@_len* sizeof(rowreq_ctx->data.@@SUBSTITUTE_IDX_OR_CLM_NAME@@[0]));
        if (NULL == (*@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_ptr)) {
            snmp_log(LOG_ERR, "could not allocate memory (rowreq_ctx->data.@@SUBSTITUTE_IDX_OR_CLM_NAME@@)\\n");
            return MFD_ERROR;
        }
    }
    (* @@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_len_ptr) = rowreq_ctx->data.@@SUBSTITUTE_IDX_OR_CLM_NAME@@_len* sizeof(rowreq_ctx->data.@@SUBSTITUTE_IDX_OR_CLM_NAME@@[0]);
    memcpy((*@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_ptr), rowreq_ctx->data.@@SUBSTITUTE_IDX_OR_CLM_NAME@@, rowreq_ctx->data.@@SUBSTITUTE_IDX_OR_CLM_NAME@@_len* sizeof(rowreq_ctx->data.@@SUBSTITUTE_IDX_OR_CLM_NAME@@[0]));

    """
            else:
                tableDataGetString = """
    (*@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr) = rowreq_ctx->data.@@SUBSTITUTE_IDX_OR_CLM_NAME@@;
    """
        tableDataGetString = self.parseColSpecificSubstitutionsAndReturnActualString(tableDataGetString,tableName,colOrIdxSymbol)
        return tableDataGetString;

    def getColumnGetFnPrototypeForGivenCol(self,tableName,colOrIdxSymbol):
        colName = colOrIdxSymbol['name']
        idxType = self.getObjTypeString(colOrIdxSymbol)

        tableDataHeaderString ="""
int @@SUBSTITUTE_IDX_OR_CLM_NAME@@_get(@@SUBSTITUTE_TABLE_NAME@@_rowreq_ctx *rowreq_ctx, @@SUBSTITUTE_CLMN_DOUBLE_INDIRECTION_DECL_4_CLM_GET_FUNC_DEFN_PARAM@@ )
"""
        tableDataHeaderString = self.parseColSpecificSubstitutionsAndReturnActualString(tableDataHeaderString,tableName,colOrIdxSymbol)
        tableDataHeaderString = self.parseTableSpecificSubstitutionsAndReturnActualString(tableDataHeaderString,tableName)
        return tableDataHeaderString

    def generateColumnGetFnDeclarationForGivenCol(self,tableName,colOrIdxSymbol):
        colName = colOrIdxSymbol['name']
        idxType = self.getObjTypeString(colOrIdxSymbol)
        tableDataHeaderString ="""
@@SUBSTITTUTE_COL_GET_FN_PROTOTYPE@@ ;
"""
        tableDataHeaderString = self.parseColSpecificSubstitutionsAndReturnActualString(tableDataHeaderString,tableName,colOrIdxSymbol)
        return tableDataHeaderString


    def generateColumnGetFnsForGivenCol(self,tableName,colOrIdxSymbol):
        colName = colOrIdxSymbol['name']
        idxType = self.getObjTypeString(colOrIdxSymbol)
        tableDataGetString ="""
@@SUBSTITTUTE_COL_GET_FN_PROTOTYPE@@ {

    @@SUBSTITUTE_NETSNMP_ASSERT_STATEMENTS_4_CLM_DECL_PARAM@@

    DEBUGMSGTL(("verbose:@@SUBSTITUTE_TABLE_NAME@@:@@SUBSTITUTE_IDX_OR_CLM_NAME@@_get","called\\n"));
    netsnmp_assert(NULL != rowreq_ctx);

    @@SUBSTITUTE_COL_GET_FN_BODY@@

    return MFD_SUCCESS;
}

"""
        tableDataGetString = self.parseColSpecificSubstitutionsAndReturnActualString(tableDataGetString,tableName,colOrIdxSymbol)
        tableDataGetString = self.parseTableSpecificSubstitutionsAndReturnActualString(tableDataGetString,tableName)
        return tableDataGetString


    def getColumnGetFnDefnsForAllTableCols(self,tableName):
        tmpStr = ''
        indexes = self.getIndexesForTable(tableName)
        for idx in indexes:
            if idx['maxaccess'] == 'notaccessible':
                continue
            tmpStr += self.generateColumnGetFnsForGivenCol(tableName,idx)
        for col in self.tableRows[self.tables[tableName]['row']]['columns']:
            if col['name'] in [idx['name'] for idx in indexes] or col['maxaccess'] == 'notaccessible':
                continue
            tmpStr += self.generateColumnGetFnsForGivenCol(tableName,col)
        return tmpStr

    def getColumnGetFnDeclarationForAllTableCols(self,tableName):
        indexes = self.getIndexesForTable(tableName)
        tmpStr = ''
        for idx in indexes:
            if idx['maxaccess'] == 'notaccessible':
                continue
            tmpStr += self.generateColumnGetFnDeclarationForGivenCol(tableName,idx)
        for col in self.tableRows[self.tables[tableName]['row']]['columns']:
            if col['name'] in [idx['name'] for idx in indexes] or col['maxaccess'] == 'notaccessible':
                continue
            tmpStr += self.generateColumnGetFnDeclarationForGivenCol(tableName,col)
        return tmpStr

    def substituteTableName(self,tableName):
        # handle '@@SUBSTITUTE_TABLE_NAME@@' by replacing with the 'tableName' parameter
        return tableName

    def substituteTableNameCaps(self,tableName):
        # handle '@@SUBSTITUTE_TABLE_NAME_UPPER@@' by replacing with the 'tableName.upper()' parameter
        return tableName.upper()

    def substituteColName(self,tableName,colOrIdxSymbol):
        return colOrIdxSymbol['name']

    def substituteColNameCaps(self,tableName,colOrIdxSymbol):
        return colOrIdxSymbol['name'].upper()

    def constructHashDefineConstForEnum(self,tableName,idxOrColSymbol,enumName,enumVal):
        enumHashDefine = """
#define D_@@SUBSTITUTE_IDX_OR_CLM_NAME@@_@@SUBSTITUTE_ENUM_NAME@@ @@SUBSTITUTE_ENUM_VAL@@
"""
        enumHashDefine = enumHashDefine.replace('@@SUBSTITUTE_ENUM_NAME@@',enumName)
        enumHashDefine = enumHashDefine.replace('@@SUBSTITUTE_ENUM_VAL@@',str(enumName))
        enumHashDefine = self.parseColSpecificSubstitutionsAndReturnActualString(enumHashDefine,tableName,idxOrColSymbol)
        return enumHashDefine

    def getHashDefinesOfEnumsFromGivenCol(self,tableName,colOrIdxSymbol):
        tableEnumHeaderString = ''
        if colOrIdxSymbol['name'] in self.enumSymbols:
            for x in self.enumSymbols[colOrIdxSymbol['name']]:
                name, val = x
                tableEnumsHeaderString += self.constructHashDefineConstForEnum(tableName,idx,name,val)
        return tableEnumHeaderString;

    def getHashDefineOfAllEnumsOfTable(self,tableName):
        indexes = self.getIndexesForTable(tableName)
        hashDefines = ''
        for idx in indexes:
            hashDefines += self.getHashDefinesOfEnumsFromGivenCol(tableName,idx)
        for col in self.tableRows[self.tables[tableName]['row']]['columns']:
            hashDefines += self.getHashDefinesOfEnumsFromGivenCol(tableName,idx)
        return hashDefines


    def getIdxOrClmTypeEquivalentInNET_SNMP(self,tableName,colOrIdxSym):
        return self.netsnmpTypes[self.getObjTypeString(colOrIdxSym)]


    def getInternalSnmpGetLogicForGivenColOrIdx(self,tableName,idxOrCllmSymbol):
        tableInterfaceString = ''
        if idxOrCllmSymbol['maxaccess'] == 'notaccessible':
            return tableInterfaceString
        idxType = self.getObjTypeString(idxOrCllmSymbol)
        if idxType == 'Bits':
            tableInterfaceString = """
                case COLUMN_@@SUBSTITUTE_IDX_OR_CLM_NAME_UPPER@@: {
                    u_long mask = (u_long)0xff << ((sizeof(char)-1)*8);
                    int idx = 0;
                    var->type =  ASN_OCTET_STR;
                    rc = @@SUBSTITUTE_IDX_OR_CLM_NAME@@_get(rowreq_ctx, (u_long *)var->val.string);
                    var->val_len = 0;
                    while( 0 != mask) {
                        ++idx;
                        if(*((u_long*)var->val.string)&mask)
                            var->val_len = idx;
                        mask = mask >> 8;
                    }
                }
               break;
"""
        elif idxType == 'OctetString':
            tableInterfaceString = """
                case COLUMN_@@SUBSTITUTE_IDX_OR_CLM_NAME_UPPER@@: {
                    var->type = @@SUBSTITUTE_NET_SNMP_TYPE_FOR_GIVEN_IDX_OR_COL@@;
                    rc = @@SUBSTITUTE_IDX_OR_CLM_NAME@@_get(rowreq_ctx, (char **)&var->val.string, &var->val_len);
                }
                break;
"""
        elif idxType == 'ObjectIdentifier':
            tableInterfaceString = """
                case COLUMN_@@SUBSTITUTE_IDX_OR_CLM_NAME_UPPER@@:{
                    var->type = @@SUBSTITUTE_NET_SNMP_TYPE_FOR_GIVEN_IDX_OR_COL@@;
                    rc = @@SUBSTITUTE_IDX_OR_CLM_NAME@@_get(rowreq_ctx, (oid **)&var->val.string, &var->val_len);
                }
                break;
"""
        else:
            tableInterfaceString = """
                case COLUMN_@@SUBSTITUTE_IDX_OR_CLM_NAME_UPPER@@:{
                    var->type = @@SUBSTITUTE_NET_SNMP_TYPE_FOR_GIVEN_IDX_OR_COL@@;
                    var->val_len = sizeof(@@SUBSTITUTE_GET_OBJECT_TYPE_EQUIVALENT_IN_C@@);
                    rc = @@SUBSTITUTE_IDX_OR_CLM_NAME@@_get(rowreq_ctx, (@@SUBSTITUTE_GET_OBJECT_TYPE_EQUIVALENT_IN_C@@*)var->val.string);
                }
                break;
"""
        tableInterfaceString = self.parseColSpecificSubstitutionsAndReturnActualString(tableInterfaceString,tableName,idxOrCllmSymbol)
        return tableInterfaceString;


    ##@@SUBSTITUTE_NET_SNMP_INTERNAL_GET_LOGIC_FOR_ALL_IDX_OR_COL@@
    def getInternalSnmpGetLogicForAllIdxOrClmOfTable(self,tableName):
        tmpStr = ''
        indexes = self.getIndexesForTable(tableName)
        for idx in indexes:
            tmpStr += self.getInternalSnmpGetLogicForGivenColOrIdx(tableName,idx)

        for col in self.tableRows[self.tables[tableName]['row']]['columns']:
            if col['name'] in self.tableRows[self.tables[tableName]['row']]['index']:
                continue
            tmpStr += self.getInternalSnmpGetLogicForGivenColOrIdx(tableName,col)

        return tmpStr


    #dict {k,v}, k - substitution string, v - function to be called
    ColSpecificSubstitutionStringFnsMap = {
##ONLY COLUMN SPECIFIC SUBSTITUTIONS -- Takes col-symbol as extra parameter
'@@SUBSTITUTE_IDX_OR_CLM_NAME@@' : substituteColName,
'@@SUBSTITUTE_IDX_OR_CLM_NAME_UPPER@@': substituteColNameCaps,
'@@COLUMN_OR_IDX_SIZE@@' : getIdxOrClmSize,
'@@SUBSTITUTE_GET_OBJECT_TYPE_EQUIVALENT_IN_C@@':getIdxOrColTypeEquivalentInC,
'@@SUBSTITUTE_COLUMN_OID@@':getIdxOrClmOid,
'@@SUBSTITUTE_CLMN_DOUBLE_INDIRECTION_DECL_4_CLM_GET_FUNC_DEFN_PARAM@@' : getTblColOrIdxDblIndirectionDecls4FnDefnParam,
'@@SUBSTITTUTE_COL_GET_FN_PROTOTYPE@@' : getColumnGetFnPrototypeForGivenCol,
'@@SUBSTITUTE_NETSNMP_ASSERT_STATEMENTS_4_CLM_DECL_PARAM@@' : getNetSnmpAssertStatements4ColOrIdxDblIndirectionParam,
'@@SUBSTITUTE_COL_GET_FN_BODY@@' : getTblColGetFnBodyForColumnGetFn,
'@@SUBSTITUTE_NET_SNMP_TYPE_FOR_GIVEN_IDX_OR_COL@@' : getIdxOrClmTypeEquivalentInNET_SNMP

   }

    #dict {k,v}, k - substitution string, v - function to be called
    TableSpecificSubstitutionStringFnsMap = {
##ONLY TABLE SPECIFIC SUBSTITUTIONS
'@@SUBSTITUTE_TABLE_NAME@@':substituteTableName,
'@@SUBSTITUTE_TABLE_NAME_UPPER@@':substituteTableNameCaps,
'@@SUBSTITUTE_GET_ALL_NON_IDX_COL_DECLNS_4_TABLE@@' : getAllNonIdxClmDeclarationsForGivenTable,
'@@SUBSTITUTE_GET_ALL_IDX_COL_DECLNS_4_TABLE@@' : getAllIdxClmDeclarationsForGivenTable,
'@@SUBSTITUTE_TABLE_OID@@' : getOidForGivenTable,
'@@SUBSTITUTE_TABLE_MIN_COL_NAME_UPPER@@' : getMinNonIdxColumnForGivenTable,
'@@SUBSTITUTE_TABLE_MAX_COL_NAME_UPPER@@' : getMaxNonIdxColumnForGivenTable,
'@@SUBSTITUTE_GET_HASH_DEFINE_OID_OF_ALL_COL_4_TABLE@@' : getHashDefinesOfAllColumnOidsForGivenTable,
'@@SUBSTITUTE_GET_ALL_IDX_COL_DECLNS_AS_PARAMS_4_INDEXES_SET_FUNC_DEFNN@@' : getDeclarationsOfAllIndexColumnsAsFunctionDefinitionParameters4IndexesSetFn,
'@@SUBSTITUTE_GET_ALL_IDX_COL_DECLNS_AS_FUNC_CALL_PARAMS_4_INDEXES_SET_FN@@': getDeclarationsOfAllIndxColumnsAsFunctionCallParameters4IndexesSetFn,
'@@SUBSTITUTE_SET_TBL_INDEXES_FOR_TABLE@@' : getSetTblIdxStatements,
'@@SUBSTITUTE_GENERATE_COLUMN_GET_FUNCTION_DEFNS_FOR_ALL_COLUMNS_OF_TABLE@@' : getColumnGetFnDefnsForAllTableCols,
'@@SUBSTITUTE_GENERATE_COLUMN_GET_FUNCTION_DECLARATION_FOR_ALL_COLUMNS_OF_TABLE@@':getColumnGetFnDeclarationForAllTableCols,
'@@SUBSTITUTE_HASH_DEFINE_OF_ALL_ENUMS_OF_GIVEN_TABLE@@':getHashDefineOfAllEnumsOfTable,
'@@SUBSTITUTE_OVSDB_ROW_STRINGS_FOR_TABLE@@' : getOvsdbRowsStringForTable,
'@@SUBSTITUTE_GET_ALL_LOCAL_STRINGS_FOR_TABLE@@' : getLocalsStringForTable,
'@@SUBSTITUTE_GET_FIRST_INSTANCE_STRINGS_FOR_TABLE@@' : getFirstIntanceStringForTable,
'@@SUBSTITUTE_GET_FOR_LOOP_STR_FOR_TABLE@@' : getForLoopStringForTable,
'@@SUBSTITUTE_TABLE_SKIP_FN_CALL@@' : getTableSkipFnCall,
'@@SUBSTITUTE_NET_SNMP_INTERNAL_GET_LOGIC_FOR_ALL_IDX_OR_COL@@': getInternalSnmpGetLogicForAllIdxOrClmOfTable

    }

    def parseColSpecificGivenSubstitutionsAndReturnActualString(self,actualStringToProcess,strToBeReplaced,tableName,idxOrColSymbol):
        if isinstance(strToBeReplaced,str):
            foundIndex = -1
            foundIndex = actualStringToProcess.find(strToBeReplaced)
            if foundIndex >= 0:
                actualStringToProcess = actualStringToProcess.replace(strToBeReplaced,self.ColSpecificSubstitutionStringFnsMap[strToBeReplaced](self,tableName,idxOrColSymbol))
        elif isinstance(strToBeReplaced,list):
            for replStr in strToBeReplaced:
                foundIndex = -1
                foundIndex = actualStringToProcess.find(replStr)
                if foundIndex >= 0:
                    actualStringToProcess = actualStringToProcess.replace(replStr,self.ColSpecificSubstitutionStringFnsMap[replStr](self,tableName,idxOrColSymbol))
        return actualStringToProcess

    def parseColSpecificSubstitutionsAndReturnActualString(self,actualStringToProcess,tableName,idxOrColSymbol):
        for handleStr in self.ColSpecificSubstitutionStringFnsMap.keys():
            actualStringToProcess = self.parseColSpecificGivenSubstitutionsAndReturnActualString(actualStringToProcess,handleStr,tableName,idxOrColSymbol)
        return actualStringToProcess

    def parseTableSpecificGivenSubstitutionsAndReturnActualString(self,actualStringToProcess,strToBeReplaced,tableName):
        if isinstance(strToBeReplaced,str):
            foundIndex = -1
            foundIndex = actualStringToProcess.find(strToBeReplaced)
            if foundIndex >= 0:
                actualStringToProcess = actualStringToProcess.replace(strToBeReplaced,self.TableSpecificSubstitutionStringFnsMap[strToBeReplaced](self,tableName))
        elif isinstance(strToBeReplaced,list):
            for replStr in strToBeReplaced:
                foundIndex = -1
                foundIndex = actualStringToProcess.find(replStr)
                if foundIndex >= 0:
                    actualStringToProcess = actualStringToProcess.replace(replStr,self.TableSpecificSubstitutionStringFnsMap[replStr](self,tableName))
        return actualStringToProcess

    def parseTableSpecificSubstitutionsAndReturnActualString(self,actualStringToProcess,tableName):

        for handleStr in self.TableSpecificSubstitutionStringFnsMap.keys():
            actualStringToProcess = self.parseTableSpecificGivenSubstitutionsAndReturnActualString(actualStringToProcess,handleStr,tableName)
        return actualStringToProcess;


    def generateTableNameDotCSourceFile(self,tableName):
        tableFileString = self.loadNetSnmpTemplateCodeFromFile('tableName.c.template')
        tableFileString = self.parseTableSpecificSubstitutionsAndReturnActualString(tableFileString,tableName)
        self.fileWrite(fileName=tableName + '.c',data=tableFileString)
        tableFileString = ''
    ##end of function



    def generateTableNameDotHFile(self,tableName):
        tableFileHeaderString = self.loadNetSnmpTemplateCodeFromFile('tableName.h.template')
        tableFileHeaderString = self.parseTableSpecificSubstitutionsAndReturnActualString(tableFileHeaderString,tableName)
        self.fileWrite(fileName= tableName + '.h',data=tableFileHeaderString)
        tableFileHeaderString  = ''
    #end of generate function for tableName.h file



    def generateTableNameOidsDotHFile(self,tableName):
        tableOidsHeaderString = self.loadNetSnmpTemplateCodeFromFile('tableName_oids.h.template')
        tableOidsHeaderString = self.parseTableSpecificSubstitutionsAndReturnActualString(tableOidsHeaderString,tableName)
        self.fileWrite(fileName=tableName + '_oids.h',data=tableOidsHeaderString)
        tableOidsHeaderString = ''


    def generateTableDataGetDotCFile(self,tableName):
        tableDataGetString = self.loadNetSnmpTemplateCodeFromFile('tableName_data_get.c.template')
        tableDataGetString = self.parseTableSpecificSubstitutionsAndReturnActualString(tableDataGetString,tableName)
        self.fileWrite(fileName=tableName + '_data_get.c',data=tableDataGetString)
        tableDataGetString = ''


    def generateTableDataGetDotHFile(self,tableName):
        tableDataGetHeaderString = self.loadNetSnmpTemplateCodeFromFile('tableName_data_get.h.template')
        tableDataGetHeaderString = self.parseTableSpecificSubstitutionsAndReturnActualString(tableDataGetHeaderString,tableName)
        self.fileWrite(fileName=tableName + '_data_get.h',data=tableDataGetHeaderString)
        tableDataGetHeaderString = ''


    def generateTableDataSetDotCFile(self,tableName):
        tableDataSetString = self.loadNetSnmpTemplateCodeFromFile('tableName_data_set.c.template')
        tableDataSetString = self.parseTableSpecificSubstitutionsAndReturnActualString(tableDataSetString,tableName)
        self.fileWrite(fileName=tableName + '_data_set.c',data=tableDataSetString)
        tableDataSetString = ''


    def generateTableDataSetDotHFile(self,tableName):
        tableDataSetHeaderString = self.loadNetSnmpTemplateCodeFromFile('tableName_data_set.h.template')
        tableDataSetHeaderString = self.parseTableSpecificSubstitutionsAndReturnActualString(tableDataSetHeaderString,tableName)
        self.fileWrite(fileName=tableName + '_data_set.h',data=tableDataSetHeaderString)
        tableDataSetHeaderString = ''


    def generateTableInterfaceDotHFile(self,tableName):
        tableInterfaceHeaderString = self.loadNetSnmpTemplateCodeFromFile('tableName_interface.h.template')
        tableInterfaceHeaderString = self.parseTableSpecificSubstitutionsAndReturnActualString(tableInterfaceHeaderString,tableName)
        self.fileWrite(fileName=tableName + '_interface.h',data=tableInterfaceHeaderString)
        tableInterfaceHeaderString = ''


    def generateTableEnumsDotHFile(self,tableName):
        tableEnumsHeaderString = self.loadNetSnmpTemplateCodeFromFile('tableName_enums.h.template')
        tableEnumsHeaderString = self.parseTableSpecificSubstitutionsAndReturnActualString(tableEnumsHeaderString,tableName)
        self.fileWrite(fileName=tableName + '_enums.h',data=tableEnumsHeaderString)
        tableEnumsHeaderString = ''


    def generateTableDataAccessDotCFile(self,moduleName,tableName):
        tableDataAccessString = self.loadNetSnmpTemplateCodeFromFile('tableName_data_access.c.template')
        tableDataAccessString = tableDataAccessString.replace('@@SUBSTITUTE_MODULE_NAME@@',moduleName)
        tableDataAccessString = self.parseTableSpecificSubstitutionsAndReturnActualString(tableDataAccessString,tableName)
        self.fileWrite(fileName=tableName + '_data_access.c',data=tableDataAccessString)
        tableDataAccessString = ''


    def generateTableDataAccessDotHFile(self,tableName):
        tableDataAccessHeaderString  = self.loadNetSnmpTemplateCodeFromFile('tableName_data_access.h.template')
        timeout = '30'
        if self.jsonData[tableName]['CacheTimeout']:
            timeout = str(self.jsonData[tableName]['CacheTimeout'])
        tableDataAccessHeaderString = tableDataAccessHeaderString.replace('@@TIMEOUT_VAL@@',timeout)
        tableDataAccessHeaderString = self.parseTableSpecificSubstitutionsAndReturnActualString(tableDataAccessHeaderString,tableName)
        self.fileWrite(fileName=tableName + '_data_access.h',data=tableDataAccessHeaderString)
        tableDataAccessHeaderString = ''


    def generateTableInterfaceDotCFile(self,tableName):
        tableInterfaceString = self.loadNetSnmpTemplateCodeFromFile('tableName_interface.c.template')
        #@@SUBSTITUTE_NET_SNMP_TYPES_OF_ALL_IDX@@
        indexes = self.getIndexesForTable(tableName)

        netSnmpTypesOfAllIdx = ''
        for idx in indexes:
            netSnmpTypesOfAllIdx += ', ' + self.netsnmpTypes[self.getObjTypeString(idx)]
        tableInterfaceString = tableInterfaceString.replace('@@SUBSTITUTE_NET_SNMP_TYPES_OF_ALL_IDX@@',netSnmpTypesOfAllIdx)

        _tmp_var_list = ''

        for idx in indexes:
            _tmp_var_list += """
                        netsnmp_variable_list var_@@SUBSTITUTE_IDX_OR_CLM_NAME@@;
"""
            _tmp_var_list = _tmp_var_list.replace('@@SUBSTITUTE_IDX_OR_CLM_NAME@@',idx['name'])


        _tmp_var_list_initialization = ''
        for index, idx in enumerate(indexes):
            _tmp_var_list_initialization += """
                memset(&var_@@SUBSTITUTE_IDX_OR_CLM_NAME@@, 0x00, sizeof(var_@@SUBSTITUTE_IDX_OR_CLM_NAME@@));
                var_@@SUBSTITUTE_IDX_OR_CLM_NAME@@.type = @@SUBSTITUTE_NET_SNMP_TYPE_FOR_GIVEN_IDX_OR_COL@@;
                var_@@SUBSTITUTE_IDX_OR_CLM_NAME@@.next_variable = @@SUBSTITUTE_PTR_TO_NXT_VAR@@;

"""
            _nxt_var_list = ''
            if index is not len(indexes) - 1:
                 _nxt_var_list = '&var_' + indexes[index + 1]['name']
            else:
                _nxt_var_list = 'NULL'

            #_tmp_var_list_initialization = self.parseColSpecificGivenSubstitutionsAndReturnActualString(_tmp_var_list_initialization,'@@SUBSTITUTE_IDX_OR_CLM_NAME@@',idx)
            #_tmp_var_list_initialization = self.parseColSpecificGivenSubstitutionsAndReturnActualString(_tmp_var_list_initialization,'@@SUBSTITUTE_NET_SNMP_TYPE_FOR_GIVEN_IDX_OR_COL@@',idx)
            _tmp_var_list_initialization = self.parseColSpecificGivenSubstitutionsAndReturnActualString(_tmp_var_list_initialization,
                                                                                                        ['@@SUBSTITUTE_IDX_OR_CLM_NAME@@','@@SUBSTITUTE_NET_SNMP_TYPE_FOR_GIVEN_IDX_OR_COL@@'],
                                                                                                        tableName,idx)
            _tmp_var_list_initialization = _tmp_var_list_initialization.replace('@@SUBSTITUTE_PTR_TO_NXT_VAR@@',_nxt_var_list)


        snmp_set_var_value = ''
        for idx in indexes:
            idxType = self.getObjTypeString(idx)
            if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
                snmp_set_var_value += """
snmp_set_var_value(&var_@@SUBSTITUTE_IDX_OR_CLM_NAME@@,&mib_idx->@@SUBSTITUTE_IDX_OR_CLM_NAME@@,mib_idx->@@SUBSTITUTE_IDX_OR_CLM_NAME@@_len * sizeof(mib_idx->@@SUBSTITUTE_IDX_OR_CLM_NAME@@[0]));
"""
            else:
                snmp_set_var_value += """
snmp_set_var_value(&var_@@SUBSTITUTE_IDX_OR_CLM_NAME@@, &mib_idx->@@SUBSTITUTE_IDX_OR_CLM_NAME@@, sizeof(mib_idx->@@SUBSTITUTE_IDX_OR_CLM_NAME@@));
"""
            snmp_set_var_value = snmp_set_var_value.replace('@@SUBSTITUTE_IDX_OR_CLM_NAME@@',idx['name'])

        mib_idx_ptr_val = ''
        for idx in indexes:
            idxType = self.getObjTypeString(idx)
            if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
                mib_idx_ptr_val += """
            if (var_@@SUBSTITUTE_IDX_OR_CLM_NAME@@.val_len > sizeof(mib_idx->@@SUBSTITUTE_IDX_OR_CLM_NAME@@)) {
                err = SNMP_ERR_GENERR;
            }
            else {
                    memcpy(mib_idx->@@SUBSTITUTE_IDX_OR_CLM_NAME@@, var_@@SUBSTITUTE_IDX_OR_CLM_NAME@@.val.string, var_@@SUBSTITUTE_IDX_OR_CLM_NAME@@.val_len);
                    mib_idx->@@SUBSTITUTE_IDX_OR_CLM_NAME@@_len = var_@@SUBSTITUTE_IDX_OR_CLM_NAME@@.val_len/ sizeof(mib_idx->@@SUBSTITUTE_IDX_OR_CLM_NAME@@[0]);
            }
"""
            else:
                mib_idx_ptr_val += """
            mib_idx->@@SUBSTITUTE_IDX_OR_CLM_NAME@@ = *((@@SUBSTITUTE_GET_OBJECT_TYPE_EQUIVALENT_IN_C@@*)var_@@SUBSTITUTE_IDX_OR_CLM_NAME@@.val.string);
"""
            mib_idx_ptr_val = self.parseColSpecificGivenSubstitutionsAndReturnActualString(mib_idx_ptr_val,
                                                                                            ['@@SUBSTITUTE_IDX_OR_CLM_NAME@@','@@SUBSTITUTE_GET_OBJECT_TYPE_EQUIVALENT_IN_C@@'],
                                                                                            tableName,idx)


        tableInterfaceString = tableInterfaceString.replace('@@SUBSTITUTE_UPDATE_MIB_IDX_FOR_ALL_INDEXES@@',mib_idx_ptr_val)
        tableInterfaceString = tableInterfaceString.replace('@@SUBSTITUTE_SNMP_VAR_VALUE_FOR_ALL_INDEXES@@',snmp_set_var_value)
        tableInterfaceString = tableInterfaceString.replace('@@SUBSTITUTE_NET_SNMP_VARIABLE_LIST_FOR_ALL_INDEXES@@',_tmp_var_list)
        tableInterfaceString = tableInterfaceString.replace('@@SUBSTITUTE_INITIALIZE_NET_SNMP_VARIABLE_LIST_OF_INDEXES@@',_tmp_var_list_initialization)
        tableInterfaceString = tableInterfaceString.replace('@@SUBSTITUTE_FIRST_IDX_NAME@@',indexes[0]['name'])

        #tableInterfaceString = self.parseTableSpecificGivenSubstitutionAndReturnActualString(tableInterfaceString,'@@SUBSTITUTE_NET_SNMP_INTERNAL_GET_LOGIC_FOR_ALL_IDX_OR_COL@@',tableName)
        #tableInterfaceString = self.parseTableSpecificGivenSubstitutionAndReturnActualString(tableInterfaceString,'@@SUBSTITUTE_TABLE_NAME@@',tableName)
        #tableInterfaceString = self.parseTableSpecificGivenSubstitutionAndReturnActualString(tableInterfaceString,'@@SUBSTITUTE_TABLE_NAME_UPPER@@',tableName)
        #All the above are covered within the foll fun..
        tableInterfaceString = self.parseTableSpecificSubstitutionsAndReturnActualString(tableInterfaceString,tableName)

        self.fileWrite(fileName=tableName + '_interface.c',data=tableInterfaceString)
       #templateJsonObject = ''
        tableInterfaceString = ''


    def getOvsdbGetFnDeclnsForGivenClmOrIdx(self,tableName,idxOrClmSymbol,rootDbTable,useSchemaSpecifiedCardinality,tmpAppendConditionFlagParameterName,tmpAppendConditionTypeFlagParameterDefn,tmpAppendConditionFlagParameterVal):
        idx = idxOrClmSymbol
        appendConditionFlagParameterName = tmpAppendConditionFlagParameterName
        appendConditionTypeFlagParameterDefn = tmpAppendConditionTypeFlagParameterDefn # NOTE : must be last parameter always
        appendConditionFlagParameterVal = tmpAppendConditionFlagParameterVal
        if useSchemaSpecifiedCardinality:
            if self.mibObjectParticipatesInMultipleCardinality(tableName,idxOrClmSymbol):
                appendConditionFlagParameterName = tmpAppendConditionFlagParameterName
                appendConditionTypeFlagParameterDefn = tmpAppendConditionTypeFlagParameterDefn # NOTE : must be last parameter always
                appendConditionFlagParameterVal = tmpAppendConditionFlagParameterVal
            else:
                appendConditionTypeFlagParameterDefn = ''
                appendConditionFlagParameterName = ''
                appendConditionFlagParameterVal = ''

        tableOvsdbGetHeaderString = ''
        dbIdx = self.getSchemaDataObjectFromMappingFileForGivenMibObject(tableName,idxOrClmSymbol) # self.jsonData[tableName]['Indexes'][idx['name']]
        idxTable = dbIdx['OvsTable']
        idxType = self.getObjTypeString(idxOrClmSymbol)
        if not idxTable:
            tableOvsdbGetHeaderString = """
void ovsdb_get_@@SUBSTITUTE_IDX_OR_CLM_NAME@@(struct ovsdb_idl *idl,
                                              const struct ovsrec_@@SUBSTITUTE_ROOT_OVS_TBL_NAME@@ *@@SUBSTITUTE_ROOT_OVS_TBL_NAME@@_row, 
                                              @@SUBSTITUTE_IDX_OR_CLM_DECLN_4_OVSDB_GET_FN_DEFN@@  @@SUBSTITUTE_COND_FLAG_PARAM_DEFN@@);
"""

        elif idxTable != rootDbTable:
            tableOvsdbGetHeaderString = """
void ovsdb_get_@@SUBSTITUTE_IDX_OR_CLM_NAME@@(struct ovsdb_idl *idl,
                                              const struct ovsrec_@@SUBSTITUTE_ROOT_OVS_TBL_NAME@@ *@@SUBSTITUTE_ROOT_OVS_TBL_NAME@@_row, 
                                              const struct ovsrec_@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@ *@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@_row, 
                                              @@SUBSTITUTE_IDX_OR_CLM_DECLN_4_OVSDB_GET_FN_DEFN@@  @@SUBSTITUTE_COND_FLAG_PARAM_DEFN@@);
"""

        else:
            tableOvsdbGetHeaderString = """
void ovsdb_get_@@SUBSTITUTE_IDX_OR_CLM_NAME@@(struct ovsdb_idl *idl,
                                              const struct ovsrec_@@SUBSTITUTE_ROOT_OVS_TBL_NAME@@ *@@SUBSTITUTE_ROOT_OVS_TBL_NAME@@_row, 
                                              @@SUBSTITUTE_IDX_OR_CLM_DECLN_4_OVSDB_GET_FN_DEFN@@  @@SUBSTITUTE_COND_FLAG_PARAM_DEFN@@);
"""

        tableOvsdbGetHeaderString = tableOvsdbGetHeaderString.replace('@@SUBSTITUTE_IDX_OR_CLM_DECLN_4_OVSDB_GET_FN_DEFN@@',
                                                                self.getDeclarationOfTblClmOrIdxAsFunctionDefnParameter4OvsdbGetFn(tableName,idx))
        tableOvsdbGetHeaderString = tableOvsdbGetHeaderString.replace('@@SUBSTITUTE_COND_FLAG_PARAM_DEFN@@',appendConditionTypeFlagParameterDefn)
        tableOvsdbGetHeaderString = tableOvsdbGetHeaderString.replace('@@SUBSTITUTE_IDX_OR_CLM_NAME@@',idx['name'])
        tableOvsdbGetHeaderString = tableOvsdbGetHeaderString.replace('@@SUBSTITUTE_ROOT_OVS_TBL_NAME@@',rootDbTable)
        if idxTable:
            tableOvsdbGetHeaderString = tableOvsdbGetHeaderString.replace('@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@',idxTable)

        return tableOvsdbGetHeaderString;



    def getOvsdbGetFnDeclnsForAllIdxAndCols(self,tableName):
    #@@SUBSTITUTE_OVSDB_GET_FN_DECL_FOR_ALL_IDX_AND_COL@@
        indexes = self.getIndexesForTable(tableName)
        tableOvsdbGetHeaderString = ''
        tmpAppendConditionTypeFlagParameterDefn = ''
        tmpAppendConditionFlagParameterName = ''
        tmpAppendConditionFlagParameterVal = ''
        useSchemaSpecifiedCardinality = self.doesTableSupportMultipleCardinality(tableName)
        rootDbTable = self.jsonData[tableName]['RootOvsTable']
        if useSchemaSpecifiedCardinality:
            #tmpAppendConditionFlagParameterName = 'conditional_string_type'
            #tmpAppendConditionTypeFlagParameterDefn = ', const char *' + tmpAppendConditionFlagParameterName # NOTE : must be last parameter always
            #tmpAppendConditionFlagParameterVal = ', ' + tmpAppendConditionFlagParameterName
            tmpAppendConditionFlagParameterName = 'conditional_enum_type'
            tmpAppendConditionTypeFlagParameterDefn = ', int ' + tmpAppendConditionFlagParameterName # NOTE : must be last parameter always
            tmpAppendConditionFlagParameterVal = ', ' + tmpAppendConditionFlagParameterName
        else:
            if(self.tables[tableName]['supportsBothIpv4Ipv6']):
                tmpAppendConditionFlagParameterName = 'is_for_ip_req_type'
                tmpAppendConditionTypeFlagParameterDefn = ', int ' + tmpAppendConditionFlagParameterName # NOTE : must be last parameter always
                tmpAppendConditionFlagParameterVal = ', ' + tmpAppendConditionFlagParameterName

        for idx in indexes:
            tableOvsdbGetHeaderString += self.getOvsdbGetFnDeclnsForGivenClmOrIdx(tableName,idx,rootDbTable,useSchemaSpecifiedCardinality,tmpAppendConditionFlagParameterName,tmpAppendConditionTypeFlagParameterDefn,tmpAppendConditionFlagParameterVal)

        for col in self.tableRows[self.tables[tableName]['row']]['columns']:
            if col['name'] in [idx['name'] for idx in indexes]:
                continue
            tableOvsdbGetHeaderString += self.getOvsdbGetFnDeclnsForGivenClmOrIdx(tableName,col,rootDbTable,useSchemaSpecifiedCardinality,tmpAppendConditionFlagParameterName,tmpAppendConditionTypeFlagParameterDefn,tmpAppendConditionFlagParameterVal)

        return tableOvsdbGetHeaderString


    def generateTableNameOvsdbGetDotHFile(self,tableName):

        tableOvsdbGetHeaderString = self.loadNetSnmpTemplateCodeFromFile('tableName_ovsdb_get.h.template')
        tableOvsdbGetHeaderString = tableOvsdbGetHeaderString.replace('@@SUBSTITUTE_OVSDB_GET_FN_DECL_FOR_ALL_IDX_AND_COL@@',self.getOvsdbGetFnDeclnsForAllIdxAndCols(tableName))
        tableOvsdbGetHeaderString = self.parseTableSpecificSubstitutionsAndReturnActualString(tableOvsdbGetHeaderString ,tableName)
        self.fileWrite(fileName=tableName + '_ovsdb_get.h',data=tableOvsdbGetHeaderString)
        tableOvsdbGetHeaderString = ''



    def addCustomFnToCustomHeader(self,tableName,idxOrClmSymbol,dbIdx,rootDbTable,idxTable,appendConditionTypeFlagParameterDefn,appendConditionFlagParameterName,alsoDefineFn=False):
        idx = idxOrClmSymbol
        if dbIdx['CustomFunction']:
            if not idxTable:
#                tmpFnPrototype = """
#void @@SUBSTITUTE_CUSTOM_FN_NAME@@(struct ovsdb_idl *idl,
#                            const struct ovsrec_@@SUBSTITUTE_ROOT_OVS_TBL_NAME@@ *@@SUBSTITUTE_ROOT_OVS_TBL_NAME@@_row, 
#                            @@SUBSTITUTE_IDX_OR_CLM_DECLN_4_OVSDB_GET_FN_DEFN@@ @@SUBSTITUTE_COND_FLAG_PARAM_DEFN@@ )
#"""
                tmpFnPrototype = self.getNetSnmpCodeTemplateFromHelperFile('custom_fn_prototype_4_only_rootOvsTbl')
            elif idxTable != rootDbTable:
#                tmpFnPrototype = """
#void @@SUBSTITUTE_CUSTOM_FN_NAME@@(struct ovsdb_idl *idl,
#                            const struct ovsrec_@@SUBSTITUTE_ROOT_OVS_TBL_NAME@@ *@@SUBSTITUTE_ROOT_OVS_TBL_NAME@@_row,
#                            const struct ovsrec_@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@ *@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@_row,
#                            @@SUBSTITUTE_IDX_OR_CLM_DECLN_4_OVSDB_GET_FN_DEFN@@ @@SUBSTITUTE_COND_FLAG_PARAM_DEFN@@ )
#"""
                tmpFnPrototype = self.getNetSnmpCodeTemplateFromHelperFile('custom_fn_prototype_4_local_ovsTbl')
            else:
#                tmpFnPrototype = """
#void @@SUBSTITUTE_CUSTOM_FN_NAME@@(struct ovsdb_idl *idl,
#                            const struct ovsrec_@@SUBSTITUTE_ROOT_OVS_TBL_NAME@@ *@@SUBSTITUTE_ROOT_OVS_TBL_NAME@@_row, 
#                            @@SUBSTITUTE_IDX_OR_CLM_DECLN_4_OVSDB_GET_FN_DEFN@@ @@SUBSTITUTE_COND_FLAG_PARAM_DEFN@@ )
#"""
                tmpFnPrototype = self.getNetSnmpCodeTemplateFromHelperFile('custom_fn_prototype_4_same_root_and_local_ovsTbl')

            tmpFnPrototype = tmpFnPrototype.replace('@@SUBSTITUTE_IDX_OR_CLM_DECLN_4_OVSDB_GET_FN_DEFN@@',
                                                                    self.getDeclarationOfTblClmOrIdxAsFunctionDefnParameter4OvsdbGetFn(tableName,idx))
            tmpFnPrototype = tmpFnPrototype.replace('@@SUBSTITUTE_COND_FLAG_PARAM_DEFN@@',appendConditionTypeFlagParameterDefn)
            tmpFnPrototype = tmpFnPrototype.replace('@@SUBSTITUTE_CUSTOM_FN_NAME@@',dbIdx['CustomFunction'])
            tmpFnPrototype = tmpFnPrototype.replace('@@SUBSTITUTE_ROOT_OVS_TBL_NAME@@',rootDbTable)
            if idxTable:
                tmpFnPrototype = tmpFnPrototype.replace('@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@',idxTable)

            self.customFileHeaderString += tmpFnPrototype  + ';\n\n'
            useSchemaSpecifiedCardinality = self.doesTableSupportMultipleCardinality(tableName)
            if alsoDefineFn:
                if useSchemaSpecifiedCardinality and self.mibObjectParticipatesInMultipleCardinality(tableName,idx):
                    self.customFileString += self.getCustomFnDefinitions(fnPrototype = tmpFnPrototype,tableName=tableName,idxOrColSymbol=idx,appendConditionFlagParameterName=appendConditionFlagParameterName)
        return


    #@@SUBSTITUTE_FN_BODY_4_OVS_TBL_NOT_SPECIFIED@@
    def getOvsdbGetFnBody4NotIdxTbl(self,tableName,idxOrClmSymbol,dbIdx,idxType,idxTable,rootDbTable,appendConditionTypeFlagParameterDefn,appendConditionFlagParameterVal,appendConditionFlagParameterName):
        idx = idxOrClmSymbol
        fnBody = ''
        if dbIdx['CustomFunction']:
#            fnBody = """
#@@SUBSTITUTE_CUSTOM_FN_NAME@@(idl, @@SUBSTITUTE_ROOT_OVS_TBL_NAME@@_row, 
#                            @@SUBSTITUTE_IDX_OR_CLM_DECLN_4_OVSDB_GET_FN_CALL@@ @@SUBSTITUTE_COND_FLAG_PARAM_VAL@@);
#"""
            fnBody = self.getNetSnmpCodeTemplateFromHelperFile('custom_fn_call_for_only_root_ovs_tbl')

            fnBody = fnBody.replace('@@SUBSTITUTE_IDX_OR_CLM_DECLN_4_OVSDB_GET_FN_CALL@@',
                                                                    self.getDeclarationOfTblClmOrIdxAsFunctionCallParameter4OvsdbGetFn(tableName,idx))
            fnBody = fnBody.replace('@@SUBSTITUTE_COND_FLAG_PARAM_VAL@@',appendConditionFlagParameterVal)
            fnBody = fnBody.replace('@@SUBSTITUTE_CUSTOM_FN_NAME@@',dbIdx['CustomFunction'])
            fnBody = fnBody.replace('@@SUBSTITUTE_ROOT_OVS_TBL_NAME@@',rootDbTable)
            if idxTable:
                fnBody = fnBody.replace('@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@',idxTable)

            self.addCustomFnToCustomHeader(tableName,idx,dbIdx,rootDbTable,idxTable,appendConditionTypeFlagParameterDefn,appendConditionFlagParameterName)

        else:
            if idxType == 'OctetString':
                #<Ph> check if it is '\\0' or '\0'
#                fnBody = """
#    *@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr = '\\0';
#    *@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_len = 0;
#"""
                fnBody = self.getNetSnmpCodeTemplateFromHelperFile('ovsdg_get_fn_body_4_root_ovsTbl_and_octet_str_type')
            elif idxType == 'ObjectIdentifier':
#                fnBody = """
#    *@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr = (oid)NULL;
#    *@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_len = 0;
#"""
                fnBody = self.getNetSnmpCodeTemplateFromHelperFile('ovsdg_get_fn_body_4_root_ovsTbl_and_object_identifier_type')
            else:
#                fnBody = """
#    *@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr = (@@SUBSTITUTE_GET_OBJECT_TYPE_EQUIVALENT_IN_C@@)NULL;
#"""
                fnBody = self.getNetSnmpCodeTemplateFromHelperFile('ovsdg_get_fn_body_4_root_ovsTbl_and_primitive_type')
        fnBody = self.parseColSpecificSubstitutionsAndReturnActualString(fnBody,tableName,idx)

        return fnBody


    def getCommonOvsdbGetFnBody(self,tableName,idxOrClmSymbol,dbIdx,idxType,idxTable,rootDbTable,appendConditionTypeFlagParameterDefn,appendConditionFlagParameterVal,appendConditionFlagParameterName):
        idx = idxOrClmSymbol
        fnBody = ''
        if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
            fnBody = 'char *temp = NULL;\n'
            if dbIdx['Type']['Key']: #For handling smap and value-types.
                if type(dbIdx['Type']['Key']) == dict and 'Value' in dbIdx['Type']['Key'] and 'Type' in dbIdx['Type']['Key']: #For handling value-map types
                    tmpOvsdbGetStringForKeyIntType = ''
                    tmpOvsdbGetStringForKeyStrType = ''

#                    tmpOvsdbGetStringForKeyStrType = """
#for (int i = 0; i < @@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@_row->n_@@SUBSTITUTE_OVS_COL_NAME@@; i++) {
#    if(strcmp("##PUT_MULTIPLE_KEY_VALUES_HERE_IF_AVAILABLE##", @@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@_row->key_@@SUBSTITUTE_OVS_COL_NAME@@[i]) == 0) {
#        temp = (char*)@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@_row->value_@@SUBSTITUTE_OVS_COL_NAME@@[i];
#    }
#}
#"""
                    tmpOvsdbGetStringForKeyStrType = self.getNetSnmpCodeTemplateFromHelperFile('ovsdb_get_fn_body_4_value_map_ovsCol_where_key_is_str_and_value_is_str')

#                    tmpOvsdbGetStringForKeyIntType = """
#for (int i = 0; i < @@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@_row->n_@@SUBSTITUTE_OVS_COL_NAME@@; i++) {
#    if(##PUT_MULTIPLE_KEY_VALUES_HERE_IF_AVAILABLE## == @@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@_row->key_@@SUBSTITUTE_OVS_COL_NAME@@[i]) {
#        temp = (char*)@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@_row->value_@@SUBSTITUTE_OVS_COL_NAME@@[i];
#    }
#}
#"""
                    tmpOvsdbGetStringForKeyIntType = self.getNetSnmpCodeTemplateFromHelperFile('ovsdb_get_fn_body_4_value_map_ovsCol_where_key_is_int_and_value_is_str')

                    tmpOvsdbGetStringForKeyIntType = tmpOvsdbGetStringForKeyIntType.replace('@@SUBSTITUTE_OVS_COL_NAME@@',dbIdx['OvsColumn'])
                    tmpOvsdbGetStringForKeyIntType = tmpOvsdbGetStringForKeyIntType.replace('@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@',idxTable)

                    tmpOvsdbGetStringForKeyStrType = tmpOvsdbGetStringForKeyStrType.replace('@@SUBSTITUTE_OVS_COL_NAME@@',dbIdx['OvsColumn'])
                    tmpOvsdbGetStringForKeyStrType = tmpOvsdbGetStringForKeyStrType.replace('@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@',idxTable)

                    fnBody += self.getAutoGeneratedCodeForSingleOrMultipleKeys(tableName,idx,appendConditionFlagParameterName,'##PUT_MULTIPLE_KEY_VALUES_HERE_IF_AVAILABLE##',tmpOvsdbGetStringForKeyStrType,tmpOvsdbGetStringForKeyIntType)
                    tmpOvsdbGetStringForKeyIntType = ''
                    tmpOvsdbGetStringForKeyStrType = ''
                elif 'Value' not in dbIdx['Type']['Key'] and 'Type' not in dbIdx['Type']['Key']  :#should be handled for multiple-cols and singe key specification??
#                    fnBody += """
#temp = (char*)smap_get(&@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@_row->@@SUBSTITUTE_OVS_COL_NAME@@, "##PUT_MULTIPLE_KEY_VALUES_HERE_IF_AVAILABLE##");
#"""
                    tmpOvsdbGetStringForSmapType = self.getNetSnmpCodeTemplateFromHelperFile('ovsdb_get_fn_body_4_smap_ovsCol_and_value_is_str')
                    fnBody += self.getAutoGeneratedCodeForSingleOrMultipleKeys(tableName,idx,appendConditionFlagParameterName,'##PUT_MULTIPLE_KEY_VALUES_HERE_IF_AVAILABLE##','','',tmpOvsdbGetStringForSmapType)
                else:
                    assert(0 and 'Reached Dead End in code. Should not reach execution here')

            else:#currently handling only for ovscolumn, need to handle for key pairs.
#                tmpOvsdbGetString = """
#temp = (char*)@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@_row->##PUT_MULTIPLE_OVSDB_COLUMNS_HERE_IF_AVAILABLE##;
#"""
                tmpOvsdbGetString = self.getNetSnmpCodeTemplateFromHelperFile('ovsdg_get_fn_body_4_ovsCol_string_type')
                tmpOvsdbGetString = tmpOvsdbGetString.replace('@@SUBSTITUTE_OVS_COL_NAME@@',dbIdx['OvsColumn'])
                tmpOvsdbGetString = tmpOvsdbGetString.replace('@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@',idxTable)

                fnBody += self.getAutoGeneratedCodeForSingleOrMultipleOvsColumns(tableName,idx,appendConditionFlagParameterName,'##PUT_MULTIPLE_OVSDB_COLUMNS_HERE_IF_AVAILABLE##',tmpOvsdbGetString)
                tmpOvsdbGetString = ''

            if idxType == 'OctetString':
#                fnBody += """
#    *@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_len = temp != NULL ? strlen(temp) : 0;
#    memcpy(@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr, temp, *@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_len);
#"""
                fnBody += self.getNetSnmpCodeTemplateFromHelperFile('copy_ovsdb_val_to_snmp_response_as_octet_str')

            elif idxType == 'ObjectIdentifier':
#                fnBody += """
#oid temp_oid[MAX_OID_LEN] = {0};
#*@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_len = MAX_OID_LEN;
#if (temp != NULL) {
#snmp_parse_oid(temp, temp_oid, @@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_len);
#}
#memcpy(@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr, temp_oid, *@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr_len);

#"""
                fnBody += self.getNetSnmpCodeTemplateFromHelperFile('copy_ovsdb_val_to_snmp_response_as_object_identifier')

        else:
            if dbIdx['Type']['Key']:
                if type(dbIdx['Type']['Key']) == dict and 'Value' in dbIdx['Type']['Key'] and 'Type' in dbIdx['Type']['Key']:#handling Value-map types
                    tmpOvsdbGetStringForKeyIntType = ''
                    tmpOvsdbGetStringForKeyStrType = ''

#                    tmpOvsdbGetStringForKeyStrType = """
#for (int i = 0; i < @@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@_row->n_@@SUBSTITUTE_OVS_COL_NAME@@; i++) {
#if(strcmp("##PUT_MULTIPLE_KEY_VALUES_HERE_IF_AVAILABLE##", @@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@_row->key_@@SUBSTITUTE_OVS_COL_NAME@@[i]) == 0) {
#    *@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr = (@@SUBSTITUTE_GET_OBJECT_TYPE_EQUIVALENT_IN_C@@)@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@_row->value_@@SUBSTITUTE_OVS_COL_NAME@@[i];
#}
#}

#"""
                    tmpOvsdbGetStringForKeyStrType = self.getNetSnmpCodeTemplateFromHelperFile('ovsdb_get_fn_body_4_value_map_ovsCol_where_key_is_str_and_value_is_int');

#                    tmpOvsdbGetStringForKeyIntType = """
#for (int i = 0; i < @@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@_row->n_@@SUBSTITUTE_OVS_COL_NAME@@; i++) {
#if(##PUT_MULTIPLE_KEY_VALUES_HERE_IF_AVAILABLE## == @@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@_row->key_@@SUBSTITUTE_OVS_COL_NAME@@[i]) {
#    *@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr = (@@SUBSTITUTE_GET_OBJECT_TYPE_EQUIVALENT_IN_C@@)@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@_row->value_@@SUBSTITUTE_OVS_COL_NAME@@[i];
#}
#}

#"""
                    tmpOvsdbGetStringForKeyIntType = self.getNetSnmpCodeTemplateFromHelperFile('ovsdb_get_fn_body_4_value_map_ovsCol_where_key_is_int_and_value_is_int')

                    tmpOvsdbGetStringForKeyIntType = tmpOvsdbGetStringForKeyIntType.replace('@@SUBSTITUTE_OVS_COL_NAME@@',dbIdx['OvsColumn'])
                    tmpOvsdbGetStringForKeyIntType = tmpOvsdbGetStringForKeyIntType.replace('@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@',idxTable)
                    tmpOvsdbGetStringForKeyIntType = self.parseColSpecificSubstitutionsAndReturnActualString(tmpOvsdbGetStringForKeyIntType ,tableName,idx)

                    tmpOvsdbGetStringForKeyStrType = tmpOvsdbGetStringForKeyStrType.replace('@@SUBSTITUTE_OVS_COL_NAME@@',dbIdx['OvsColumn'])
                    tmpOvsdbGetStringForKeyStrType = tmpOvsdbGetStringForKeyStrType.replace('@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@',idxTable)
                    tmpOvsdbGetStringForKeyStrType  = self.parseColSpecificSubstitutionsAndReturnActualString(tmpOvsdbGetStringForKeyStrType ,tableName,idx)

                    fnBody += self.getAutoGeneratedCodeForSingleOrMultipleKeys(tableName,idx,appendConditionFlagParameterName,'##PUT_MULTIPLE_KEY_VALUES_HERE_IF_AVAILABLE##',tmpOvsdbGetStringForKeyStrType,tmpOvsdbGetStringForKeyIntType)
                    tmpOvsdbGetStringForKeyIntType = ''
                    tmpOvsdbGetStringForKeyStrType = ''

                elif 'Value' not in dbIdx['Type']['Key'] and 'Type' not in dbIdx['Type']['Key']:#handling smap types
#                    fnBody += """
#char *temp = (char*)smap_get(&@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@_row->@@SUBSTITUTE_OVS_COL_NAME@@, "##PUT_MULTIPLE_KEY_VALUES_HERE_IF_AVAILABLE##");
#if(temp == NULL) {
#    *@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr = 0;
#}
#else {
#    *@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr = (@@SUBSTITUTE_GET_OBJECT_TYPE_EQUIVALENT_IN_C@@)atoi(temp);
#}

#"""
                    tmpOvsdbGetStringForSmapType = self.getNetSnmpCodeTemplateFromHelperFile('ovsdb_get_fn_body_4_smap_col_and_value_is_int')
                    fnBody += self.getAutoGeneratedCodeForSingleOrMultipleKeys(tableName,idx,appendConditionFlagParameterName,'##PUT_MULTIPLE_KEY_VALUES_HERE_IF_AVAILABLE##','','',tmpOvsdbGetStringForSmapType)
                    #fnBody = fnBody.replace('@@SUBSTITUTE_TYPE_KEY@@',dbIdx['Type']['Key'])
                else:
                    assert(0 and 'Reached Dead End in code. Should not reach execution here')

            else:#currently handling only for ovscolumn, need to handle for key pairs.
#                tmpOvsdbGetString = """
#*@@SUBSTITUTE_IDX_OR_CLM_NAME@@_val_ptr = (@@SUBSTITUTE_GET_OBJECT_TYPE_EQUIVALENT_IN_C@@)*(@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@_row->##PUT_MULTIPLE_OVSDB_COLUMNS_HERE_IF_AVAILABLE##);
#"""
                tmpOvsdbGetString = self.getNetSnmpCodeTemplateFromHelperFile('ovsdg_get_fn_body_4_ovsCol_primitive_type')
                tmpOvsdbGetString = tmpOvsdbGetString.replace('@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@',idxTable)
                tmpOvsdbGetString = tmpOvsdbGetString.replace('@@SUBSTITUTE_IDX_OR_CLM_NAME@@',idx['name'])
                #handle this also '@@SUBSTITUTE_GET_OBJECT_TYPE_EQUIVALENT_IN_C@@)'
                tmpOvsdbGetString = self.parseColSpecificSubstitutionsAndReturnActualString(tmpOvsdbGetString,tableName,idx)

                fnBody += self.getAutoGeneratedCodeForSingleOrMultipleOvsColumns(tableName,idx,appendConditionFlagParameterName,'##PUT_MULTIPLE_OVSDB_COLUMNS_HERE_IF_AVAILABLE##',tmpOvsdbGetString)

                tmpOvsdbGetString = ''

        if not isinstance(dbIdx['OvsColumn'],dict):
            fnBody = fnBody.replace('@@SUBSTITUTE_OVS_COL_NAME@@',dbIdx['OvsColumn'])
        fnBody = fnBody.replace('@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@',idxTable)
        fnBody = fnBody.replace('@@SUBSTITUTE_IDX_OR_CLM_NAME@@',idx['name'])
        #handle this also '@@SUBSTITUTE_GET_OBJECT_TYPE_EQUIVALENT_IN_C@@)'
        fnBody = self.parseColSpecificSubstitutionsAndReturnActualString(fnBody,tableName,idx)
        return fnBody


    #@@SUBSTITUTE_FN_BODY_4_DIFFERENT_OVS_TBL_SPECIFIED@@
    def getOvsdbGetFnBody4DiffOvsTblSpecified(self,tableName,idxOrClmSymbol,dbIdx,idxType,idxTable,rootDbTable,appendConditionTypeFlagParameterDefn,appendConditionFlagParameterVal,appendConditionFlagParameterName):
        idx = idxOrClmSymbol
        fnBody = ''
        if dbIdx['CustomFunction']:
#            fnBody = """
#@@SUBSTITUTE_CUSTOM_FN_NAME@@(idl, @@SUBSTITUTE_ROOT_OVS_TBL_NAME@@_row, @@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@_row,
#                            @@SUBSTITUTE_IDX_OR_CLM_DECLN_4_OVSDB_GET_FN_CALL@@ @@SUBSTITUTE_COND_FLAG_PARAM_VAL@@);
#"""
            fnBody = self.getNetSnmpCodeTemplateFromHelperFile('custom_fn_call_4_local_ovsTbl')

            fnBody = fnBody.replace('@@SUBSTITUTE_IDX_OR_CLM_DECLN_4_OVSDB_GET_FN_CALL@@',
                                                                    self.getDeclarationOfTblClmOrIdxAsFunctionCallParameter4OvsdbGetFn(tableName,idx))
            fnBody = fnBody.replace('@@SUBSTITUTE_COND_FLAG_PARAM_VAL@@',appendConditionFlagParameterVal)
            fnBody = fnBody.replace('@@SUBSTITUTE_CUSTOM_FN_NAME@@',dbIdx['CustomFunction'])
            fnBody = fnBody.replace('@@SUBSTITUTE_ROOT_OVS_TBL_NAME@@',rootDbTable)
            fnBody = fnBody.replace('@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@',idxTable)

            self.addCustomFnToCustomHeader(tableName,idx,dbIdx,rootDbTable,idxTable,appendConditionTypeFlagParameterDefn,appendConditionFlagParameterName,True)

        else:
            fnBody = self.getCommonOvsdbGetFnBody(tableName,idxOrClmSymbol,dbIdx,idxType,idxTable,rootDbTable,appendConditionTypeFlagParameterDefn,appendConditionFlagParameterVal,appendConditionFlagParameterName)

        fnBody = self.parseColSpecificSubstitutionsAndReturnActualString(fnBody,tableName,idx)
        return fnBody


    #@@SUBSTITUTE_FN_BODY_4_SAME_OVS_TBL_SPECIFIED@@
    def getOvsdbGetFnBody4SpecifiedOvsTbl(self,tableName,idxOrClmSymbol,dbIdx,idxType,idxTable,rootDbTable,appendConditionTypeFlagParameterDefn,appendConditionFlagParameterVal,appendConditionFlagParameterName):
        fnBody = ''
        idx = idxOrClmSymbol

        if dbIdx['CustomFunction']:
#            fnBody = """
#@@SUBSTITUTE_CUSTOM_FN_NAME@@(idl, @@SUBSTITUTE_ROOT_OVS_TBL_NAME@@_row, 
#                            @@SUBSTITUTE_IDX_OR_CLM_DECLN_4_OVSDB_GET_FN_CALL@@ @@SUBSTITUTE_COND_FLAG_PARAM_VAL@@);
#"""
            fnBody = self.getNetSnmpCodeTemplateFromHelperFile('custom_fn_call_for_same_rootOvsTbl_and_LocalOvsTbl')

            fnBody = fnBody.replace('@@SUBSTITUTE_IDX_OR_CLM_DECLN_4_OVSDB_GET_FN_CALL@@',
                                                                    self.getDeclarationOfTblClmOrIdxAsFunctionCallParameter4OvsdbGetFn(tableName,idx))
            fnBody = fnBody.replace('@@SUBSTITUTE_COND_FLAG_PARAM_VAL@@',appendConditionFlagParameterVal)
            fnBody = fnBody.replace('@@SUBSTITUTE_CUSTOM_FN_NAME@@',dbIdx['CustomFunction'])
            fnBody = fnBody.replace('@@SUBSTITUTE_ROOT_OVS_TBL_NAME@@',rootDbTable)
            fnBody = fnBody.replace('@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@',idxTable)

            self.addCustomFnToCustomHeader(tableName,idx,dbIdx,rootDbTable,idxTable,appendConditionTypeFlagParameterDefn,appendConditionFlagParameterName,True)

        else:#now idxTable and rootDbTable are same, so send rootDbTable as parameter 2wise here.
            fnBody = self.getCommonOvsdbGetFnBody(tableName,idxOrClmSymbol,dbIdx,idxType,rootDbTable,rootDbTable,appendConditionTypeFlagParameterDefn,appendConditionFlagParameterVal,appendConditionFlagParameterName)

        fnBody = self.parseColSpecificSubstitutionsAndReturnActualString(fnBody,tableName,idx)
        return fnBody


    def getOvsdbGetFnDefnForGivenColumn(self,tableName,idxOrClmSymbol,useSchemaSpecifiedCardinality,tmpAppendConditionFlagParameterName,tmpAppendConditionTypeFlagParameterDefn ,tmpAppendConditionFlagParameterVal):
            #dbIdx = self.jsonData[tableName]['Indexes'][idx['name']]
            dbIdx = self.getSchemaDataObjectFromMappingFileForGivenMibObject(tableName,idxOrClmSymbol)
            rootDbTable = self.jsonData[tableName]['RootOvsTable']

            appendConditionFlagParameterName = tmpAppendConditionFlagParameterName
            appendConditionTypeFlagParameterDefn = tmpAppendConditionTypeFlagParameterDefn # NOTE : must be last parameter always
            appendConditionFlagParameterVal = tmpAppendConditionFlagParameterVal

            if useSchemaSpecifiedCardinality:
                #if idx['name'] in self.jsonData[tableName]['Table_MibColumnsParticipatingInMultipleCardinality']:
                if self.mibObjectParticipatesInMultipleCardinality(tableName,idxOrClmSymbol):
                    appendConditionFlagParameterName = tmpAppendConditionFlagParameterName
                    appendConditionTypeFlagParameterDefn = tmpAppendConditionTypeFlagParameterDefn # NOTE : must be last parameter always
                    appendConditionFlagParameterVal = tmpAppendConditionFlagParameterVal
                else:
                    appendConditionTypeFlagParameterDefn = ''
                    appendConditionFlagParameterName = ''
                    appendConditionFlagParameterVal = ''

            idxTable = dbIdx['OvsTable']
            idxType = self.getObjTypeString(idxOrClmSymbol)
            if idxOrClmSymbol['name'] in self.generatedSymbols:
                return ""

            idx = idxOrClmSymbol
            tableOvsdbGetString  = ''

            if not idxTable:
#                tableOvsdbGetString = """
#void ovsdb_get_@@SUBSTITUTE_IDX_OR_CLM_NAME@@(struct ovsdb_idl *idl, const struct ovsrec_@@SUBSTITUTE_ROOT_OVS_TBL_NAME@@ *@@SUBSTITUTE_ROOT_OVS_TBL_NAME@@_row, 
#                                              @@SUBSTITUTE_IDX_OR_CLM_DECLN_4_OVSDB_GET_FN_DEFN@@ @@SUBSTITUTE_COND_FLAG_PARAM_DEFN@@) {
#    @@SUBSTITUTE_FN_BODY_4_OVS_TBL_NOT_SPECIFIED@@
#}

#"""
                tableOvsdbGetString = self.getNetSnmpCodeTemplateFromHelperFile('ovsdb_get_fn_defn_with_root_ovstable')
                tableOvsdbGetString = tableOvsdbGetString.replace('@@SUBSTITUTE_FN_BODY_4_OVS_TBL_NOT_SPECIFIED@@',
                                                                  self.getOvsdbGetFnBody4NotIdxTbl(tableName,idx,dbIdx,idxType,idxTable,rootDbTable,appendConditionTypeFlagParameterDefn,appendConditionFlagParameterVal,appendConditionFlagParameterName))

                self.generatedSymbols[idx['name']] = 1

            elif idxTable != rootDbTable:
#                tableOvsdbGetString = """
#void ovsdb_get_@@SUBSTITUTE_IDX_OR_CLM_NAME@@(struct ovsdb_idl *idl, const struct ovsrec_@@SUBSTITUTE_ROOT_OVS_TBL_NAME@@ *@@SUBSTITUTE_ROOT_OVS_TBL_NAME@@_row, 
#                                              const struct ovsrec_@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@ *@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@_row,
#                                              @@SUBSTITUTE_IDX_OR_CLM_DECLN_4_OVSDB_GET_FN_DEFN@@ @@SUBSTITUTE_COND_FLAG_PARAM_DEFN@@) {
#    @@SUBSTITUTE_FN_BODY_4_DIFFERENT_OVS_TBL_SPECIFIED@@
#}

#"""
                tableOvsdbGetString = self.getNetSnmpCodeTemplateFromHelperFile('ovsdb_get_fn_defn_with_new_ovstable')
                tableOvsdbGetString = tableOvsdbGetString.replace('@@SUBSTITUTE_FN_BODY_4_DIFFERENT_OVS_TBL_SPECIFIED@@',
                                                                  self.getOvsdbGetFnBody4DiffOvsTblSpecified(tableName,idx,dbIdx,idxType,idxTable,rootDbTable,appendConditionTypeFlagParameterDefn,appendConditionFlagParameterVal,appendConditionFlagParameterName))

                self.generatedSymbols[idx['name']] = 1

            else:
#                tableOvsdbGetString = """
#void ovsdb_get_@@SUBSTITUTE_IDX_OR_CLM_NAME@@(struct ovsdb_idl *idl, const struct ovsrec_@@SUBSTITUTE_ROOT_OVS_TBL_NAME@@ *@@SUBSTITUTE_ROOT_OVS_TBL_NAME@@_row,
#                                              @@SUBSTITUTE_IDX_OR_CLM_DECLN_4_OVSDB_GET_FN_DEFN@@ @@SUBSTITUTE_COND_FLAG_PARAM_DEFN@@) {
#    @@SUBSTITUTE_FN_BODY_4_SAME_OVS_TBL_SPECIFIED@@
#}
#"""
                tableOvsdbGetString = self.getNetSnmpCodeTemplateFromHelperFile('ovsdb_get_fn_defn_4_same_root_and_new_ovs_tbl')
                self.generatedSymbols[idx['name']] = 1
                tableOvsdbGetString = tableOvsdbGetString.replace('@@SUBSTITUTE_FN_BODY_4_SAME_OVS_TBL_SPECIFIED@@',
                                                                  self.getOvsdbGetFnBody4SpecifiedOvsTbl(tableName,idxOrClmSymbol,dbIdx,idxType,idxTable,rootDbTable,appendConditionTypeFlagParameterDefn,appendConditionFlagParameterVal,appendConditionFlagParameterName))

            tableOvsdbGetString = tableOvsdbGetString.replace('@@SUBSTITUTE_IDX_OR_CLM_DECLN_4_OVSDB_GET_FN_DEFN@@',
                                                                    self.getDeclarationOfTblClmOrIdxAsFunctionDefnParameter4OvsdbGetFn(tableName,idx))
            tableOvsdbGetString = tableOvsdbGetString.replace('@@SUBSTITUTE_COND_FLAG_PARAM_DEFN@@',appendConditionTypeFlagParameterDefn)
            tableOvsdbGetString = tableOvsdbGetString.replace('@@SUBSTITUTE_IDX_OR_CLM_NAME@@',idx['name'])
            tableOvsdbGetString = tableOvsdbGetString.replace('@@SUBSTITUTE_ROOT_OVS_TBL_NAME@@',rootDbTable)
            if idxTable:
                tableOvsdbGetString = tableOvsdbGetString.replace('@@SUBSTITUTE_LOCAL_OVS_TBL_NAME@@',idxTable)

            return tableOvsdbGetString


    #SUBSTITUTE_GENERATE_OVSDB_GET_FN_DECLNS_FOR_ALL_IDX_AND_COLUMNS_OF_TBL
    def getOvsdbGetFnDefnsForAllColumns(self,tableName):
        indexes = self.getIndexesForTable(tableName)

        tmpAppendConditionFlagParameterName = ''
        tmpAppendConditionTypeFlagParameterDefn = ''
        tmpAppendConditionFlagParameterVal = ''

        tableOvsdbGetString = ''
        #useSchemaSpecifiedCardinality = 1 < self.tables[tableName]['Table_MibSchemaCardinalityCount']
        useSchemaSpecifiedCardinality = self.doesTableSupportMultipleCardinality(tableName)
        if useSchemaSpecifiedCardinality:
            #tmpAppendConditionFlagParameterName = 'conditional_string_type'
            #tmpAppendConditionTypeFlagParameterDefn = ', const char *' + tmpAppendConditionFlagParameterName # NOTE : must be last parameter always
            #tmpAppendConditionFlagParameterVal = ', ' + tmpAppendConditionFlagParameterName
            tmpAppendConditionFlagParameterName = 'conditional_enum_type'
            tmpAppendConditionTypeFlagParameterDefn = ', int ' + tmpAppendConditionFlagParameterName # NOTE : must be last parameter always
            tmpAppendConditionFlagParameterVal = ', ' + tmpAppendConditionFlagParameterName
        else:
            if(self.tables[tableName]['supportsBothIpv4Ipv6']):
                #appendConditionFlagParameterName = 'is_for_ip_req_type'
                #appendConditionTypeFlagParameterDefn = ', int ' + appendConditionFlagParameterName # NOTE : must be last parameter always
                #appendConditionFlagParameterVal = ', ' + appendConditionFlagParameterName
                tmpAppendConditionFlagParameterName = 'is_for_ip_req_type'
                tmpAppendConditionTypeFlagParameterDefn = ', int ' + tmpAppendConditionFlagParameterName # NOTE : must be last parameter always
                tmpAppendConditionFlagParameterVal = ', ' + tmpAppendConditionFlagParameterName

        for idx in indexes:
            tableOvsdbGetString += self.getOvsdbGetFnDefnForGivenColumn(tableName,idx,useSchemaSpecifiedCardinality,tmpAppendConditionFlagParameterName,tmpAppendConditionTypeFlagParameterDefn,tmpAppendConditionFlagParameterVal)

        for col in self.tableRows[self.tables[tableName]['row']]['columns']:
            if col['name'] in [idx['name'] for idx in indexes] or col['name'] in self.generatedSymbols:
                continue
            tableOvsdbGetString += self.getOvsdbGetFnDefnForGivenColumn(tableName,col,useSchemaSpecifiedCardinality,tmpAppendConditionFlagParameterName,tmpAppendConditionTypeFlagParameterDefn,tmpAppendConditionFlagParameterVal)

        return tableOvsdbGetString



    def generateTableNameOvsdbGetDotCFile(self,moduleName,tableName):
        tableOvsdbGetString = self.loadNetSnmpTemplateCodeFromFile('tableName_ovsdb_get.c.template')
        #@@SUBSTITUTE_ADD_OVSDB_COLS_TO_IDL@@
        idlAddClmCode = ''
        for (ovsdbRow, ovsdbCol) in self.getOvsdbTableColumnsForTable(tableName):
            tmpIdlCode = """
ovsdb_idl_add_column(idl, &ovsrec_@@SUBSTITUTE_OVSDB_ROW@@_col_@@SUBSTITUTE_OVSDB_COL@@);
"""
            tmpIdlCode = tmpIdlCode.replace('@@SUBSTITUTE_OVSDB_ROW@@',ovsdbRow)
            tmpIdlCode = tmpIdlCode.replace('@@SUBSTITUTE_OVSDB_COL@@',ovsdbCol)
            idlAddClmCode += tmpIdlCode

        tableOvsdbGetString = tableOvsdbGetString.replace('@@SUBSTITUTE_MODULE_NAME@@',moduleName)
        tableOvsdbGetString = tableOvsdbGetString.replace('@@SUBSTITUTE_TABLE_NAME@@',tableName)
        tableOvsdbGetString = tableOvsdbGetString.replace('@@SUBSTITUTE_ADD_OVSDB_COLS_TO_IDL@@',idlAddClmCode)
        tableOvsdbGetString = tableOvsdbGetString.replace('@@SUBSTITUTE_GENERATE_OVSDB_GET_FN_DECLNS_FOR_ALL_IDX_AND_COLUMNS_OF_TBL@@',self.getOvsdbGetFnDefnsForAllColumns(tableName))

        tableOvsdbGetString  = self.parseTableSpecificSubstitutionsAndReturnActualString(tableOvsdbGetString,tableName)

        self.fileWrite(fileName=tableName + '_ovsdb_get.c',data=tableOvsdbGetString)
        tableOvsdbGetString = ''

    def genCTableFiles(self, moduleName):
        for key in self.tables.keys():
            tableName = key
            if tableName in self.jsonData:
                if self.jsonData[tableName]['MibType'] != 'Table':
                    raise Exception('%s is not a table',tableName)
            else:
                continue
            self.tables[tableName]['Table_MibSchemaCardinalityCount'] = 1
            self.tables[tableName]['supportsBothIpv4Ipv6'] = False
            ignoreCardinality = False

            if 'Table_MibSchemaCardinality' in self.jsonData[tableName]:
                try:
                    self.tables[tableName]['Table_MibSchemaCardinalityCount'] = int(self.jsonData[tableName]['Table_MibSchemaCardinality' ][self.jsonData[tableName]['Table_MibSchemaCardinality' ].index(':')+1:] )
                    if 'Table_MibSchemaCardinalityConditions' in self.jsonData[tableName] and self.jsonData[tableName]['Table_MibSchemaCardinalityConditions' ]:
                        if not isinstance(self.jsonData[tableName]['Table_MibSchemaCardinalityConditions'],list) or len(self.jsonData[tableName]['Table_MibSchemaCardinalityConditions']) != self.tables[tableName]['Table_MibSchemaCardinalityCount']:
                            print 'Error while parsing  Table_MibSchemaCardinalityConditions for the table ' + tableName 
                            print 'Cardinality count and Cardinality condition entries count must match in the mapping file.'
                            ignoreCardinality = True
                        else:
                            self.tables[tableName]['CardinalityConditionTypeConstants'] = {}
                            for conditionType in self.jsonData[tableName]['Table_MibSchemaCardinalityConditions']:
                                self.tables[tableName]['CardinalityConditionTypeConstants'][conditionType] = tableName.upper() + '_CONDITION_TYPE_' + conditionType.upper()
                            ignoreCardinality = False
                    else:
                        print 'Error while parsing  Table_MibSchemaCardinalityConditions for the table ' + tableName + 'Table_MibSchemaCardinalityConditions tag not found in the json mapping file for this table.'
                        ignoreCardinality = True
                except :
                    print 'Error while parsing  Table_MibSchemaCardinality for the table ' + tableName + ', check the json mapping file for this table.'
                    ignoreCardinality = True

            if ignoreCardinality:
                print 'Ignoring the cardinality for the table ' + tableName
                self.tables[tableName]['Table_MibSchemaCardinalityCount'] = 1


            if 1 == self.tables[tableName]['Table_MibSchemaCardinalityCount']:
                #check if any one of the indexes are of type 'InetAddressType' or 'InetVersion'
                #for tempidx in indexes:
                for tempidx in self.getIndexesForTable(tableName):
                    if 'SimpleSyntax' in tempidx['syntax'] and 'objType' in tempidx['syntax']['SimpleSyntax']:
                        tempVal = tempidx['syntax']['SimpleSyntax']['objType']
                        if 'InetAddressType' == tempVal or 'InetVersion' == tempVal :
                            self.tables[tableName]['supportsBothIpv4Ipv6'] = True
                            break
            self.generateTableNameDotCSourceFile(tableName)
            self.generateTableNameDotHFile(tableName)

            self.generateTableNameOidsDotHFile(tableName)

            self.generateTableDataGetDotCFile(tableName)
            self.generateTableDataGetDotHFile(tableName)

            self.generateTableDataSetDotCFile(tableName)
            self.generateTableDataSetDotHFile(tableName)

            self.generateTableDataAccessDotCFile(moduleName, tableName)
            self.generateTableDataAccessDotHFile(tableName)

            self.generateTableNameOvsdbGetDotCFile(moduleName,tableName)
            self.generateTableNameOvsdbGetDotHFile(tableName)

            self.generateTableEnumsDotHFile(tableName)

            self.generateTableInterfaceDotCFile(tableName)
            self.generateTableInterfaceDotHFile(tableName)
        return

    def genNotificationFile(self, moduleName):
        if self.notificationSymbols.count == 0:
            return

        notificationFileString = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <fcntl.h>
#include <unistd.h>
#include <sched.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "vswitch-idl.h"
#include "ovsdb-idl.h"
#include "openswitch-idl.h"
#include "openvswitch/vlog.h"
#include "smap.h"
#include "snmptrap_lib.h"
"""
        notificationFileString += '\nVLOG_DEFINE_THIS_MODULE(' + moduleName + '_snmp_traps);\n\n'
        notificationFileString += 'oid objid_enterprise[] = {1,3,6,1,4,1,3,1,1};\n'
        notificationFileString += 'oid objid_sysdescr[] = {1,3,6,1,2,1,1,1,0};\n'
        notificationFileString += 'oid objid_sysuptime[] = {1,3,6,1,2,1,1,3,0};\n'
        notificationFileString += 'oid objid_snmptrap[] = {1,3,6,1,6,3,1,1,4,1,0};\n\n'
        notificationFileString += 'void init_ovsdb_snmp_notifications(struct ovsdb_idl* idl) {\n'
        notificationFileString += 'ovsdb_idl_add_column(idl, &ovsrec_system_col_system_mac);\n\n'
        notificationFileString += 'ovsdb_idl_add_table(idl, &ovsrec_table_snmp_trap);\n'
        notificationFileString += 'ovsdb_idl_add_column(idl, &ovsrec_snmp_trap_col_community_name);\n'
        notificationFileString += 'ovsdb_idl_add_column(idl, &ovsrec_snmp_trap_col_receiver_address);\n'
        notificationFileString += 'ovsdb_idl_add_column(idl, &ovsrec_snmp_trap_col_receiver_udp_port);\n'
        notificationFileString += 'ovsdb_idl_add_column(idl, &ovsrec_snmp_trap_col_type);\n'
        notificationFileString += 'ovsdb_idl_add_column(idl, &ovsrec_snmp_trap_col_version);\n\n'
        notificationFileString += 'ovsdb_idl_add_table(idl, &ovsrec_table_snmpv3_user);\n'
        notificationFileString += 'ovsdb_idl_add_column(idl, &ovsrec_snmpv3_user_col_auth_protocol);\n'
        notificationFileString += 'ovsdb_idl_add_column(idl, &ovsrec_snmpv3_user_col_auth_pass_phrase);\n'
        notificationFileString += 'ovsdb_idl_add_column(idl, &ovsrec_snmpv3_user_col_priv_pass_phrase);\n'
        notificationFileString += 'ovsdb_idl_add_column(idl, &ovsrec_snmpv3_user_col_user_name);\n'
        notificationFileString += 'ovsdb_idl_add_column(idl, &ovsrec_snmpv3_user_col_priv_protocol);\n'
        notificationFileString += '}\n\n'

        # Need this to avoid duplicate generation for symbols
        tempSymCache = set()

        for trap in self.notificationSymbols:
            trapSym = self._out[trap]
            trapOid = trapSym['oid'][0]
            trapOid = trapOid.replace('[','{').replace(']','}')
            for obj in trapSym['objects']:
                objItemStr = obj.items()[0][1]
                objSym = self.symbolTable[obj.items()[0][0]][obj.items()[0][1]]
                if objItemStr in tempSymCache:
                    continue
                else:
                    tempSymCache.add(objItemStr)
                objOid = str(self.genNumericOid(objSym['oid'])).replace('[','{').replace(']','}')
                notificationFileString += 'static oid objid_' + objItemStr + '[] = ' + objOid + ';\n'
            notificationFileString += '\nint send_' + trap + '(const namespace_type nm_type, struct ovsdb_idl* idl'
            for obj in trapSym['objects']:
                notificationFileString += ', const char* ' + obj.items()[0][1] + '_value'
            notificationFileString += ') {\n'
            notificationFileString += 'const struct ovsrec_snmp_trap *trap_row = ovsrec_snmp_trap_first(idl);'
            notificationFileString += 'if(trap_row == NULL){\n'
            notificationFileString += 'VLOG_DBG("ovsrec_snmp_trap_first failed to return trap row");\n'
            notificationFileString += 'return -1;\n'
            notificationFileString += '}\n\n'
            notificationFileString += 'OVSREC_SNMP_TRAP_FOR_EACH(trap_row, idl){\n'
            notificationFileString += 'init_snmp("snmpapp");\n'
            notificationFileString += 'netsnmp_session session, *ss = NULL;\n'
            notificationFileString += 'netsnmp_pdu *pdu = NULL, *response = NULL;\n'
            notificationFileString += 'int status = 0;\n'
            notificationFileString += 'int inform = 0;\n'
            notificationFileString += 'SOCK_STARTUP;\n'
            notificationFileString += 'snmp_sess_init(&session);\n\n'
            notificationFileString += 'const char *trap_type = trap_row->type;\n'
            notificationFileString += 'const char *trap_version = trap_row->version;\n'
            notificationFileString += 'if(strcmp(trap_version, OVSREC_SNMP_TRAP_VERSION_V1) == 0){\n'
            notificationFileString += 'session.version = SNMP_VERSION_1;\n'
            notificationFileString += 'pdu = snmp_pdu_create(SNMP_MSG_TRAP);\n'
            notificationFileString += 'if(ops_add_snmp_trap_community(&session, trap_row) < 0){\n'
            notificationFileString += 'VLOG_ERR("Failed in ops_add_snmp_trap_community");\n'
            notificationFileString += 'goto loop_cleanup;\n'
            notificationFileString += '}\n'
            notificationFileString += '}\n'
            notificationFileString += 'else if(strcmp(trap_version, OVSREC_SNMP_TRAP_VERSION_V2C) == 0){\n'
            notificationFileString += 'session.version = SNMP_VERSION_2c;\n'
            notificationFileString += 'if(ops_add_snmp_trap_community(&session, trap_row) < 0){\n'
            notificationFileString += 'VLOG_ERR("Failed in ops_add_snmp_trap_community");\n'
            notificationFileString += 'goto loop_cleanup;\n'
            notificationFileString += '}\n'
            notificationFileString += 'if(strcmp(trap_type, OVSREC_SNMP_TRAP_TYPE_INFORM) == 0){\n'
            notificationFileString += 'inform = 1;\n'
            notificationFileString += 'pdu = snmp_pdu_create(SNMP_MSG_INFORM);\n'
            notificationFileString += '}\n'
            notificationFileString += 'else{\n'
            notificationFileString += 'pdu = snmp_pdu_create(SNMP_MSG_TRAP2);\n'
            notificationFileString += '}\n'
            notificationFileString += '}\n'
            notificationFileString += 'else if(strcmp(trap_version, OVSREC_SNMP_TRAP_VERSION_V3) == 0){\n'
            notificationFileString += 'session.version = SNMP_VERSION_3;\n'
            notificationFileString += 'if(ops_add_snmpv3_user(idl, &session, trap_row) < 0){\n'
            notificationFileString += 'VLOG_ERR("Failed in adding ops_add_snmpv3_user");\n'
            notificationFileString += 'goto loop_cleanup;\n'
            notificationFileString += '}\n'
            notificationFileString += 'if(strcmp(trap_type, OVSREC_SNMP_TRAP_TYPE_INFORM) == 0){\n'
            notificationFileString += 'inform = 1;\n'
            notificationFileString += 'pdu = snmp_pdu_create(SNMP_MSG_INFORM);\n'
            notificationFileString += '}\n'
            notificationFileString += 'else{\n'
            notificationFileString += 'pdu = snmp_pdu_create(SNMP_MSG_TRAP2);\n'
            notificationFileString += '}\n'
            notificationFileString += '}\n\n'
            notificationFileString += 'if(pdu == NULL) {\n'
            notificationFileString += 'VLOG_ERR("Failed to create notification PDU");\n'
            notificationFileString += 'goto loop_cleanup;\n'
            notificationFileString += '}\n\n'
            notificationFileString += 'long sysuptime;\n'
            notificationFileString += 'char csysuptime[MAX_UPTIME_STR_LEN];\n\n'
            notificationFileString += 'sysuptime = get_uptime();\n'
            notificationFileString += 'sprintf(csysuptime,"%ld",sysuptime);\n'
            notificationFileString += 'status = snmp_add_var(pdu, objid_sysuptime, sizeof(objid_sysuptime)/sizeof(oid),\'t\',csysuptime);\n'
            notificationFileString += 'if (status != 0){\n'
            notificationFileString += 'VLOG_ERR("Failed to add var uptime to pdu: %d", status);\n'
            notificationFileString += 'goto loop_cleanup;\n'
            notificationFileString += '}\n\n'
            notificationFileString += 'status = snmp_add_var(pdu, objid_snmptrap, sizeof(objid_snmptrap)/sizeof(oid), \'o\',' + trapOid.replace('{','"').replace('}','"').replace(' ',"").replace(',','.') + ');\n'
            notificationFileString += 'if (status != 0) {\n'
            notificationFileString += 'VLOG_ERR("Failed to add var snmptrap to pdu %d",status);\n'
            notificationFileString += 'goto loop_cleanup;\n'
            notificationFileString += '}\n\n'
            for obj in trapSym['objects']:
                objSym = self.notificationTypes[self.getObjTypeString(self._out[obj.items()[0][1]])]
                notificationFileString += 'status = snmp_add_var(pdu, objid_' + obj.items()[0][1] + ', sizeof(objid_' + obj.items()[0][1] + ')/sizeof(oid), \'' + objSym + '\', ' + obj.items()[0][1] + '_value);\n'
                notificationFileString += 'if (status != 0) {\n'
                notificationFileString += 'VLOG_ERR("Failed to add var ' + obj.items()[0][1] + ' to pdu %d",status);\n'
                notificationFileString += 'goto loop_cleanup;\n'
                notificationFileString += '}\n\n'
            notificationFileString += 'status = ops_snmp_send_trap(nm_type, trap_row, &session,ss, pdu,response,inform);\n'
            notificationFileString += 'if(status < 0){\n'
            notificationFileString += 'VLOG_ERR("Failed in ops_snmp_send_trap");\n'
            notificationFileString += 'goto loop_cleanup;\n'
            notificationFileString += '}\n\n'
            notificationFileString += 'loop_cleanup:\n'
            notificationFileString += 'if(status){\n'
            notificationFileString += 'VLOG_ERR(inform ? "snmpinform failed with status: %d" : "snmptrap failed with status: %d", status);\n'
            notificationFileString += 'if(!inform && pdu != NULL){\n'
            notificationFileString += 'snmp_free_pdu(pdu);\n'
            notificationFileString += '}\n'
            notificationFileString += '}\n'
            notificationFileString += 'else if(inform && response != NULL){\n'
            notificationFileString += 'snmp_free_pdu(response);\n'
            notificationFileString += '}\n\n'
            notificationFileString += 'if(ss != NULL){'
            notificationFileString += 'snmp_close(ss);\n'
            notificationFileString += '}\n\n'
            notificationFileString += 'SOCK_CLEANUP;\n'
            notificationFileString += 'snmp_shutdown("snmptrap");\n'
            notificationFileString += '}\n'
            notificationFileString += 'return 0;\n'
            notificationFileString += '}\n\n'
        self.fileWrite(fileName=moduleName + '_traps.c', data=notificationFileString)

    def genHeaderFile(self, moduleName):
        headerString = '#ifndef ' + moduleName + '_H\n'
        headerString += '#define ' + moduleName + '_H\n'
        # headerString += 'void register_' + moduleName + '(void);\n'
        # headerString += 'void unregister_' + moduleName + '(void);\n'
        for codeSym in self.scalarSymbols:
            name = codeSym
            if name not in self.jsonData:
                continue
            headerString += 'void init_' + name + '(void);\n'
            #headerString += 'void shutdown_' + name + '(void);\n\n'
        headerString += '#endif'
        self.fileWriter.fileWrite(fileName=moduleName + '_scalars.h',data=headerString)

    def genIndex(self, mibsMap, **kwargs):
        out = '\nfrom pysnmp.proto.rfc1902 import ObjectName\n\noidToMibMap = {\n'
        count = 0
        for name, oid in mibsMap:
            out += 'ObjectName("%s"): "%s",\n' % (oid, name)
            count += 1
        out += '}\n'
        if 'comments' in kwargs:
            out = ''.join(['# %s\n' % x for x in kwargs['comments']]) + '#\n' + out
            out = '#\n# PySNMP MIB indices (http://pysnmp.sf.net)\n' + out
        debug.logger & debug.flagCodegen and debug.logger('OID->MIB index built, %s entries, %s bytes' % (count, len(out)))
        return out
