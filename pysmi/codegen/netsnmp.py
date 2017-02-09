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
        process = subprocess.Popen([self.clangPath + ' -style=\'{IndentWidth: 4, SortIncludes: false}\' ' + codeFile],stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
        process.poll
        stdout, stderr = process.communicate()
        if stderr != '':
            print stderr
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
        self.publisherTables = []
        self.tableRows = {}
        self.enumSymbols = {}
        self.fileWriter = fileWriter
        self.customTypes = {}
        self.parsedMibs = {}
        self.jsonData = None
        self.jsonTables = options.get('jsonTables', [])
        self.clangFormatPath = options.get('clangFormatPath','')
        self.mappingFile = options.get('mappingFile','')
        self.clangFormatter = ClangFormat(path = self.clangFormatPath, dstPath = fileWriter._path)
        self.mappingFilePath = ''
        self.customFileHeaderString = ''

        # Global Flag to tell the functions we are generating code
        # for the main AST
        self.mainModuleFlag = 1

    def fileWrite(self,fileName, data):
        self.fileWriter.fileWrite(fileName=fileName,data=data)
        if '.json' in fileName:
            return
        data = self.clangFormatter.format(fileName)
        if data != '':
            self.fileWriter.fileWrite(fileName=fileName,data=data)

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
        #return access != 'notaccessible' and '.setMaxAccess("' + access + '")'
        #or ''
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

    def addSymbolsFromImports(self, parsedMibs):
        for tempast in parsedMibs:
            self.moduleName[0], moduleOid, imports, declarations = parsedMibs[tempast][2]
            out, importedModules = self.genImports(imports and imports or {})
            for declr in declarations and declarations or []:
                if declr:
                    clausetype = declr[0]
                    classmode = clausetype == 'typeDeclaration'
                    self.handlersTable[declr[0]](self, self.prepData(declr[1:], classmode), classmode)

    def genCode(self, ast, symbolTable, **kwargs):
        self.genRules['text'] = kwargs.get('genTexts', False)
        self.parsedMibs = kwargs.get('parsedMibs', {})
        path = os.path.normpath(self.mappingFile)
        if len(self.jsonTables) == 0:
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
        if len(self.jsonTables) != 0:
            self.genJsonFile(self.moduleName[0].replace('-','_'),self.jsonTables)
            return MibInfo(oid=None, name=self.moduleName[0], imported=tuple([x for x in importedModules if x not in fakeMibs])), out
        self.genCFile(self.moduleName[0].replace('-','_'),out)
        self.genCTableFiles(self.moduleName[0].replace('-','_'))
        self.genNotificationFile(self.moduleName[0].replace('-','_'))
        self.genCustomFiles(self.moduleName[0].replace('-','_'))
        self.genPublisherFiles(self.moduleName[0].replace('-','_'))
        return MibInfo(oid=None, name=self.moduleName[0], imported=tuple([ x for x in importedModules if x not in fakeMibs])), out

    def genPublisherFiles(self, moduleName):
        publisherFileString = '#include "openvswitch/vlog.h"\n #include "snmp_utils.h"\n#include "openswitch-idl.h" \n#include "ovsdb-idl.h"\n #include "'+ moduleName + '_publisher.h"\n\n'

        publisherFileString += 'VLOG_DEFINE_THIS_MODULE('+ moduleName +'_publisher);\n\n'
        for table in set(self.publisherTables):
            table = table.lower()
            publisherFileString += '/* publish the Data into the table */\n'
            publisherFileString += 'bool '+table+'_publish_request(struct ovsdb_idl *idl) {\n\n'
            publisherFileString += 'enum ovsdb_idl_txn_status status;\n'
            publisherFileString += 'struct ovsdb_idl_txn *txn = NULL;\n'
            publisherFileString += 'struct ovsdb_idl_txn_wait_unblock *wait_req = NULL;\n'
            publisherFileString += '\n\nSNMP_OVSDB_LOCK;\n'
            publisherFileString += '\ntxn = ovsdb_idl_txn_create(idl);\n\n'
            publisherFileString += '/* Create the wait blocking request data */\n'
            publisherFileString += 'wait_req = ovsdb_idl_txn_create_wait_until_unblock(&ovsrec_table_' + table + ',SNMP_PUBLISHER_WAIT_TIMER);\n'
            publisherFileString += '/* Finish filling the request */\n'
            publisherFileString += 'ovsdb_idl_txn_add_wait_until_unblock(txn, wait_req);\n'
            publisherFileString += '\n/* commit the transaction*/\nstatus = ovsdb_idl_txn_commit_block(txn);\n if(status != TXN_SUCCESS || status != TXN_UNCHANGED) {\n VLOG_ERR("Error: ' + table + ' fetch failed - %s ",ovsdb_idl_txn_get_error(txn));\n }\n'
            publisherFileString += 'ovsdb_idl_txn_destroy(txn);\nSNMP_OVSDB_UNLOCK;\n'
            publisherFileString += 'switch(status) {\n\n'
            publisherFileString += 'case TXN_SUCCESS:\n case TXN_UNCHANGED:\nVLOG_DBG("Success: ' + table + ' fetch success");\nreturn true;\n'
            publisherFileString += 'default:\n return false;\n}\n}\n\n'

        self.fileWrite(fileName = moduleName + '_publisher.c', data=publisherFileString)

        publisherHeaderFileString = '#include "vswitch-idl.h"\n \n'
        publisherHeaderFileString += '#define SNMP_PUBLISHER_WAIT_TIMER 5000\n'
        for table in set(self.publisherTables):
            publisherHeaderFileString += 'bool '+table+'_publish_request(struct ovsdb_idl *idl);\n'

        self.fileWrite(fileName = moduleName + '_publisher.h', data=publisherHeaderFileString)

    def genCustomFiles(self, moduleName):
        customFileString = '// Define Custom Functions for ' + moduleName + ' MIB in this fileName\n'
        self.fileWrite(fileName = moduleName + '_custom.c', data=customFileString)

        tempStartString = '#ifndef ' + moduleName.upper() + '_CUSTOM_H\n'
        tempStartString += '#define ' + moduleName.upper() + '_CUSTOM_H\n\n'
        tempStartString += """#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "vswitch-idl.h"

"""
        self.customFileHeaderString = tempStartString + self.customFileHeaderString
        self.customFileHeaderString += '#endif'      
        self.fileWrite(fileName = moduleName + '_custom.h', data=self.customFileHeaderString)
        self.genHeaderFile(self.moduleName[0].replace('-','_'))

    def genJsonFile(self, moduleName, jsonTables):
        jsonFileString = '{\n'
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
        jsonFileString += '}'
        self.fileWrite(fileName=moduleName + '_mapping.json', data=jsonFileString)


    def genCFile(self, moduleName, data):
        scalarFileString = data
        scalarFileString += '#include "' + moduleName + '_custom.h"\n'
        scalarFileString += '#include "' + moduleName + '_publisher.h"\n'
        scalarFileString += '#include "' + moduleName + '_scalars.h"\n'
        scalarFileString += '#include "' + moduleName + '_scalars_ovsdb_get.h"\n'
        scalarFileString += '#include "ovsdb-idl.h"\n'
        scalarFileString += '#include "vswitch-idl.h"\n'
        scalarFileString += '#include "openvswitch/vlog.h"\n'
        scalarFileString += 'VLOG_DEFINE_THIS_MODULE('+ moduleName +'_scalars);\n\n'
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
                outStr += 'if(!' + jsonValue['OvsTable'] + '_row) {\n VLOG_ERR("not able to fetch ' + jsonValue['OvsTable'] + 'row ");\n return -1;\n}\n'
                if jsonValue.has_key('isPublisher') and jsonValue['isPublisher']:
                    if isinstance(jsonValue['isPublisher'],list) :
                        pubTbl = jsonValue['isPublisher']
                        for table in pubTbl:
                            outStr += 'if(!' + table + '_publish_request(idl)) {\n return -1;\n}\n\n'
                            self.publisherTables.append(table)
                    else:
                        outStr += 'if(!' + jsonValue['isPublisher'] + '_publish_request(idl)) {\n return -1;\n}\n\n'
                        self.publisherTables.append(jsonValue['isPublisher'])
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
        scalarOvsdbGetString += 'VLOG_DEFINE_THIS_MODULE('+ moduleName +'_scalars_ovsdb_get);\n\n'
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
                    scalarOvsdbGetString += 'char *temp = NULL;\n'
                    if scalarJson['Type']['Key']:
                        if type(scalarJson['Type']['Key']) == dict:
                            keyType = scalarJson['Type']['Key']['KeyType']
                            keyValue = scalarJson['Type']['Key']['KeyName']
                            if keyType == 'str':
                                scalarOvsdbGetString += 'for (int i = 0; i < ' + scalarJson['OvsTable']+'_row->n_'+scalarJson['OvsColumn']+'; i++) {\n'
                                scalarOvsdbGetString += 'if(strcmp("'+keyValue+'", '+scalarJson['OvsTable']+'_row->key_'+scalarJson['OvsColumn']+'[i]) == 0) {\n'
                                scalarOvsdbGetString += 'temp = (char*)'+scalarJson['OvsTable']+'_row->value_'+scalarJson['OvsColumn']+'[i];\n'
                                scalarOvsdbGetString += '}\n'
                                scalarOvsdbGetString += '}\n'
                            elif keyType == 'int':
                                scalarOvsdbGetString += 'for (int i = 0; i < ' + scalarJson['OvsTable']+'_row->n_'+scalarJson['OvsColumn']+'; i++) {\n'
                                scalarOvsdbGetString += 'if('+keyValue+' == '+scalarJson['OvsTable']+'_row->key_'+scalarJson['OvsColumn']+'[i]) {\n'
                                scalarOvsdbGetString += 'temp = (char*)'+scalarJson['OvsTable']+'_row->value_'+scalarJson['OvsColumn']+'[i];\n'
                                scalarOvsdbGetString += '}\n'
                                scalarOvsdbGetString += '}\n'
                        else:
                            scalarOvsdbGetString += 'temp = (char*)smap_get(&' + scalarJson['OvsTable'] + '_row->' + scalarJson['OvsColumn'] + ', "' + scalarJson['Type']['Key'] + '");\n'
                    else:
                        scalarOvsdbGetString += 'temp = (char*)'+ scalarJson['OvsTable'] + '_row->' + scalarJson['OvsColumn'] + ';\n'
                    scalarOvsdbGetString += '*' + scalar['name'] + '_val_ptr_len = (temp != NULL) ? strlen(temp) : 0;\n'
                    scalarOvsdbGetString += 'memcpy(' + scalar['name'] + '_val_ptr, temp, *' + scalar['name'] + '_val_ptr_len);\n'
            elif scalarType == 'ObjectIdentifier':
                scalarOvsdbGetString += 'void ovsdb_get_' + scalar['name'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + scalarJson['OvsTable'] + ' *' + scalarJson['OvsTable'] + '_row, oid *' + scalar['name'] + '_val_ptr, size_t *' + scalar['name'] + '_val_ptr_len) {\n'
                if scalarJson['CustomFunction']:
                    scalarOvsdbGetString += scalarJson['CustomFunction'] + '(idl,' + scalarJson['OvsTable'] + '_row, ' + scalar['name'] + '_val_ptr, ' + scalar['name'] + '_val_ptr_len);\n'
                    self.customFileHeaderString += 'void ' + scalarJson['CustomFunction'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + scalarJson['OvsTable'] + ' *' + scalarJson['OvsTable'] + '_row, oid *' + scalar['name'] + '_val_ptr, size_t *' + scalar['name'] + '_val_ptr_len);\n'
                else:
                    scalarOvsdbGetString += 'char *temp = NULL;\n'
                    if scalarJson['Type']['Key']:
                        if type(scalarJson['Type']['Key']) == dict:
                            keyType = scalarJson['Type']['Key']['KeyType']
                            keyValue = scalarJson['Type']['Key']['KeyName']
                            if keyType == 'str':
                                scalarOvsdbGetString += 'for (int i = 0; i < ' + scalarJson['OvsTable']+'_row->n_'+scalarJson['OvsColumn']+'; i++) {\n'
                                scalarOvsdbGetString += 'if(strcmp("'+keyValue+'", '+scalarJson['OvsTable']+'_row->key_'+scalarJson['OvsColumn']+'[i]) == 0) {\n'
                                scalarOvsdbGetString += 'temp = (char*)'+scalarJson['OvsTable']+'_row->value_'+scalarJson['OvsColumn']+'[i];\n'
                                scalarOvsdbGetString += '}\n'
                                scalarOvsdbGetString += '}\n'
                            elif keyType == 'int':
                                scalarOvsdbGetString += 'for (int i = 0; i < ' + scalarJson['OvsTable']+'_row->n_'+scalarJson['OvsColumn']+'; i++) {\n'
                                scalarOvsdbGetString += 'if('+keyValue+' == '+scalarJson['OvsTable']+'_row->key_'+scalarJson['OvsColumn']+'[i]) {\n'
                                scalarOvsdbGetString += 'temp = (char*)'+scalarJson['OvsTable']+'_row->value_'+scalarJson['OvsColumn']+'[i];\n'
                                scalarOvsdbGetString += '}\n'
                                scalarOvsdbGetString += '}\n'
                        else:
                            scalarOvsdbGetString += 'temp = (char*)smap_get(&' + scalarJson['OvsTable'] + '_row->' + scalarJson['OvsColumn'] + ', "' + scalarJson['Type']['Key'] + '");\n'
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
                scalarOvsdbGetString += 'void ovsdb_get_' + scalar['name'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + scalarJson['OvsTable'] + ' *' + scalarJson['OvsTable'] + '_row, ' + self.ctypeClasses[scalarType] + '* ' + scalar['name'] + '_val_ptr) {\n'
                if scalarJson['CustomFunction']:
                    scalarOvsdbGetString += scalarJson['CustomFunction'] + '(idl, ' + scalarJson['OvsTable'] + '_row, ' + scalar['name'] + '_val_ptr);\n'
                    self.customFileHeaderString += 'void ' + scalarJson['CustomFunction'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + scalarJson['OvsTable'] + ' *' + scalarJson['OvsTable'] + '_row, ' + self.ctypeClasses[scalarType] + ' *' + scalar['name'] + '_val_ptr);\n'
                else:
                    if scalarJson['Type']['Key']:
                        if type(scalarJson['Type']['Key']) == dict:
                            keyType = scalarJson['Type']['Key']['KeyType']
                            keyValue = scalarJson['Type']['Key']['KeyName']
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
                tables.append((val['OvsTable'], val['OvsColumn']))
        for idx, val in self.jsonData[tableName]['Indexes'].items():
            if val['OvsTable'] and (val['OvsTable'], val['OvsColumn']) not in tables:
                tables.append((val['OvsTable'],val['OvsColumn']))
        return tables

    def getOvsdbRowsStringForTable(self, tables):
        outStr = ''
        for tbl in tables:
            outStr += 'const struct ovsrec_' + tbl + ' *' + tbl + '_row = NULL;\n'
        return outStr + '\n'

    def getLocalsStringForTable(self, tableName, indexes):
        outStr = ''
        for idx in indexes:
            idxType = self.getObjTypeString(idx)
            if idxType == 'OctetString':
                stringLength = self.getStringLength(idx)
                outStr += 'char ' + idx['name'] + '[' + str(stringLength) + '] = {\'\\0\'};\n'
                outStr += 'size_t ' + idx['name'] + '_len = 0;\n'
            elif idxType == 'ObjectIdentifier':
                outStr += 'oid ' + idx['name'] + '[MAX_OID_LEN] = {0};\n'
                outStr += 'size_t ' + idx['name'] + '_len = 0;\n'
            else:
                outStr += self.ctypeClasses[idxType] + ' ' + idx['name'] + ' = 0;\n'
        outStr += '\n'
        for col in self.tableRows[self.tables[tableName]['row']]['columns']:
            if col['name'] not in [idx['name'] for idx in indexes]:
                colType = self.getObjTypeString(col)
                if colType == 'OctetString':
                    stringLength = self.getStringLength(col)
                    outStr += 'char ' + col['name'] + '[' + str(stringLength) + '] = {\'\\0\'};\n'
                    outStr += 'size_t ' + col['name'] + '_len = 0;\n'
                elif colType == 'ObjectIdentifier':
                    outStr += 'oid ' + col['name'] + '[MAX_OID_LEN] = {0};\n'
                    outStr += 'size_t ' + col['name'] + '_len = 0;\n'
                else:
                    outStr += self.ctypeClasses[colType] + ' ' + col['name'] + '; = 0\n'
        return outStr + '\n'

    def getFirstIntanceStringForTable(self, tableName, tables):
        outStr = ''
        for tbl in tables:
            outStr += tbl + '_row = ovsrec_' + tbl + '_first(idl);\n'
            outStr += 'if (!' + tbl + '_row) {\n'
            outStr += 'VLOG_ERR("not able to fetch ' + tbl + ' row");\n'
            outStr += 'return -1;\n'
            outStr += '}\n\n'
        return outStr

    def publishRequestStringForTable(self, tableName, indexes):
        outStr = '\n'
        PublisherTablesForThisTable = []
        for idx in indexes:
            
            if self.jsonData[tableName]['Indexes'][idx['name']].has_key('isPublisher') and self.jsonData[tableName]['Indexes'][idx['name']]['isPublisher'] :
                idxPubTbl = self.jsonData[tableName]['Indexes'][idx['name']]['isPublisher']
                if isinstance(idxPubTbl,list):
                    for tbl in idxPubTbl :
                        if tbl not in PublisherTablesForThisTable:
                            outStr += 'if(!' + tbl + '_publish_request(idl)) {\n return -1;\n}\n\n'
                            PublisherTablesForThisTable.append(tbl)
                            self.publisherTables.append(tbl)
                elif idxPubTbl not in PublisherTablesForThisTable:
                    outStr += 'if(!' + idxPubTbl + '_publish_request(idl)) {\n return -1;\n}\n\n'
                    PublisherTablesForThisTable.append(idxPubTbl)
                    self.publisherTables.append(idxPubTbl)
            else:
                continue

        for col in self.tableRows[self.tables[tableName]['row']]['columns']:
            if col['name'] in [idx['name'] for idx in indexes]:
                continue
            if self.jsonData[tableName]['Columns'][col['name']].has_key('isPublisher') and self.jsonData[tableName]['Columns'][col['name']]['isPublisher'] :
                colPubTbl = self.jsonData[tableName]['Columns'][col['name']]['isPublisher']
                if isinstance(colPubTbl,list):
                    for tbl in colPubTbl :
                        if tbl not in PublisherTablesForThisTable:
                           outStr += 'if(!' + tbl + '_publish_request(idl)) {\n return -1;\n}\n\n'
                           PublisherTablesForThisTable.append(tbl)
                           self.publisherTables.append(tbl)
                elif colPubTbl not in PublisherTablesForThisTable:
                    outStr += 'if(!' + colPubTbl + '_publish_request(idl)) {\n return -1;\n}\n\n'
                    PublisherTablesForThisTable.append(colPubTbl)
                    self.publisherTables.append(colPubTbl)
            else:
                continue

        return outStr

    def getForLoopStringForTable(self, tableName, indexes):
        outStr = ''
        table = self.jsonData[tableName]['RootOvsTable']
        outStr += 'OVSREC_' + table.upper() + '_FOR_EACH(' + table + '_row, idl) {\n'
        if self.jsonData[tableName]['SkipFunction']:
            outStr += 'if(' + self.jsonData[tableName]['SkipFunction'] + '(idl, ' + table + '_row)) {\n'
            outStr += 'continue;\n'
            outStr += '}\n'
            self.customFileHeaderString += 'int ' + self.jsonData[tableName]['SkipFunction'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + table + ' *' + table + '_row);\n\n'
        for idx in indexes:
            idxTable = self.jsonData[tableName]['Indexes'][idx['name']]['OvsTable']
            idxType = self.getObjTypeString(idx)
            if idxTable and idxTable != table:
                if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
                    outStr += 'ovsdb_get_' + idx['name'] + '(idl, ' + table + '_row, ' + idxTable + '_row, ' + idx['name'] + ', &' + idx['name'] + '_len);\n'
                else:
                    outStr += 'ovsdb_get_' + idx['name'] + '(idl, ' + table + '_row, ' + idxTable + '_row, &' + idx['name'] + ');\n'
            else:
                if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
                    outStr += 'ovsdb_get_' + idx['name'] + '(idl, ' + table + '_row, ' + idx['name'] + ', &' + idx['name'] + '_len);\n'
                else:
                    outStr += 'ovsdb_get_' + idx['name'] + '(idl, ' + table + '_row, &' + idx['name'] + ');\n'
        outStr += '\n'
        for col in self.tableRows[self.tables[tableName]['row']]['columns']:
            if col['name'] in [idx['name'] for idx in indexes]:
                continue
            colTable = self.jsonData[tableName]['Columns'][col['name']]['OvsTable']
            colType = self.getObjTypeString(col)
            if colTable and colTable != table:
                if colType == 'OctetString' or colType == 'ObjectIdentifier':
                    outStr += 'ovsdb_get_' + col['name'] + '(idl, ' + table + '_row, ' + colTable + '_row, ' + col['name'] + ', &' + col['name'] + '_len);\n'
                else:
                    outStr += 'ovsdb_get_' + col['name'] + '(idl, ' + table + '_row, ' + colTable + '_row, &' + col['name'] + ');\n'
            else:
                if colType == 'OctetString' or colType == 'ObjectIdentifier':
                    outStr += 'ovsdb_get_' + col['name'] + '(idl, ' + table + '_row, ' + col['name'] + ', &' + col['name'] + '_len);\n'
                else:
                    outStr += 'ovsdb_get_' + col['name'] + '(idl, ' + table + '_row, &' + col['name'] + ');\n'
        outStr += '\n'
        outStr += 'rowreq_ctx = ' + tableName + '_allocate_rowreq_ctx(NULL);\n'
        outStr += 'if (rowreq_ctx == NULL) {\n'
        outStr += 'snmp_log(LOG_ERR, "memory allocation failed");\n'
        outStr += 'return MFD_RESOURCE_UNAVAILABLE;\n'
        outStr += '}\n'
        outStr += 'if (MFD_SUCCESS != ' + tableName + '_indexes_set( rowreq_ctx'
        for idx in indexes:
            idxType = self.getObjTypeString(idx)
            if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
                outStr += ', ' + idx['name'] + ', ' + idx['name'] + '_len'
            else:
                outStr += ', ' + idx['name']
        outStr += ')) {\n'
        outStr += 'snmp_log(LOG_ERR, "error setting indexes while loading");\n'
        outStr += tableName + '_release_rowreq_ctx(rowreq_ctx);\n'
        outStr += 'continue;\n'
        outStr += '}\n\n'
        for col in self.tableRows[self.tables[tableName]['row']]['columns']:
            if col['name'] in [idx['name'] for idx in indexes]:
                continue
            colType = self.getObjTypeString(col)
            if colType == 'OctetString' or colType == 'ObjectIdentifier':
                outStr += 'rowreq_ctx->data.' + col['name'] + '_len = ' + col['name'] + '_len* sizeof(' + col['name'] + '[0]);\n'
                outStr += 'memcpy(rowreq_ctx->data.' + col['name'] + ', ' + col['name'] + ', ' + col['name'] + '_len* sizeof(' + col['name'] + '[0]));\n'
            else:
                outStr += 'rowreq_ctx->data.' + col['name'] + ' = ' + col['name'] + ';\n'
        outStr += 'CONTAINER_INSERT(container, rowreq_ctx);\n'
        outStr += '++count;\n'
        return outStr + '}\n'

    def getIndexesForTable(self, tableName):
        indexes = []
        for col in self.tableRows[self.tables[tableName]['row']]['index']:
            indexes.append(self._out[col])
        if len(indexes) is 0:
            augment = self.tableRows[self.tables[tableName]['row']]['data']['augmention']
            for col in self.tableRows[augment]['index']:
                indexes.append(self._out[col])
        return indexes

    def genCTableFiles(self, moduleName):
        for key in self.tables.keys():
            tableName = key
            indexes = self.getIndexesForTable(tableName)
            ovsdbTables = self.getOvsdbRowsForTable(tableName)
            if tableName in self.jsonData:
                if self.jsonData[tableName]['MibType'] != 'Table':
                    raise Exception('%s is not a table',tableName)
                rootDbTable = self.jsonData[tableName]['RootOvsTable']
            else:
                continue
            tableFileString = """#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/mib_modules.h>
#include "vswitch-idl.h"
#include "ovsdb-idl.h"

"""
            tableFileString += '#include "' + tableName + '.h"\n'
            tableFileString += '#include "' + tableName + '_interface.h"\n'
            tableFileString += '#include "' + tableName + '_ovsdb_get.h"\n\n'
            tableFileString += 'const oid ' + tableName + '_oid[] = {' + tableName.upper() + '_OID };\n'
            tableFileString += 'const int ' + tableName + '_oid_size = OID_LENGTH(' + tableName + '_oid);\n\n'
            tableFileString += tableName + '_registration ' + tableName + '_user_context;\n'
            tableFileString += 'void initialize_table_' + tableName + '(void);\n'
            tableFileString += 'void shutdown_table_' + tableName + '(void);\n\n'
            tableFileString += 'void init_' + tableName + '(void) {\n'
            tableFileString += 'DEBUGMSGTL(("verbose:' + tableName + ':init_' + tableName + '", "called\\n"));\n\n'
            tableFileString += tableName + '_registration * user_context;\n'
            tableFileString += 'u_long flags;\n\n'
            tableFileString += 'user_context = netsnmp_create_data_list("' + tableName + '",NULL,NULL);\n'
            tableFileString += 'flags = 0;\n\n'
            tableFileString += '_' + tableName + '_initialize_interface(user_context,flags);\n\n'
            tableFileString += tableName + '_ovsdb_idl_init(idl);\n'
            tableFileString += '}\n\n'
            tableFileString += 'void shutdown_' + tableName + '(void) {\n'
            tableFileString += '_' + tableName + '_shutdown_interface(&' + tableName + '_user_context);\n'
            tableFileString += '}\n\n'
            tableFileString += 'int ' + tableName + '_rowreq_ctx_init(' + tableName + '_rowreq_ctx *rowreq_ctx, void *user_init_ctx) {\n'
            tableFileString += 'DEBUGMSGTL(("verbose:' + tableName + ':' + tableName + '_rowreq_ctx_init","called\\n"));\n\n'
            tableFileString += 'netsnmp_assert(NULL != rowreq_ctx);\n\n'
            tableFileString += 'return MFD_SUCCESS;\n'
            tableFileString += '}\n\n'
            tableFileString += 'void ' + tableName + '_rowreq_ctx_cleanup(' + tableName + '_rowreq_ctx *rowreq_ctx) {\n'
            tableFileString += 'DEBUGMSGTL(("verbose:' + tableName + ':' + tableName + '_rowreq_ctx_cleanup","called\\n"));\n'
            tableFileString += 'netsnmp_assert(NULL != rowreq_ctx);\n'
            tableFileString += '}\n\n'
            tableFileString += 'int ' + tableName + '_pre_request(' + tableName + '_registration *user_context) {\n'
            tableFileString += 'DEBUGMSGTL(("verbose:' + tableName + ':' + tableName + '_pre_request","called\\n"));\n'
            tableFileString += 'return MFD_SUCCESS;\n'
            tableFileString += '}\n\n'
            tableFileString += 'int ' + tableName + '_post_request(' + tableName + '_registration *user_context, int rc) {\n'
            tableFileString += 'DEBUGMSGTL(("verbose:' + tableName + ':' + tableName + '_post_request","called\\n"));\n'
            tableFileString += 'return MFD_SUCCESS;\n'
            tableFileString += '}\n'
            self.fileWrite(fileName=tableName + '.c',data=tableFileString)

            tableFileHeaderString = '#ifndef ' + tableName.upper() + '_H\n'
            tableFileHeaderString += '#define ' + tableName.upper() + '_H\n'
            tableFileHeaderString += '#include <net-snmp/library/asn1.h>\n'
            tableFileHeaderString += '#include "' + tableName + '_oids.h"\n'
            tableFileHeaderString += '#include "' + tableName + '_enums.h"\n\n'
            tableFileHeaderString += 'void init_' + tableName + '(void);\n'
            tableFileHeaderString += 'void shutdown_' + tableName + '(void);\n\n'
            tableFileHeaderString += 'typedef netsnmp_data_list ' + tableName + '_registration;\n\n'
            tableFileHeaderString += 'typedef struct ' + tableName + '_data_s {\n'
            for col in self.tableRows[self.tables[tableName]['row']]['columns']:
                if col['name'] not in self.tableRows[self.tables[tableName]['row']]['index']:
                    if self.getObjTypeString(col) == 'OctetString':
                        stringLength = self.getStringLength(col)
                        tableFileHeaderString += 'char ' + col['name'] + '[' + str(stringLength) + '];\n'
                        tableFileHeaderString += 'size_t ' + col['name'] + '_len;\n'
                    elif self.getObjTypeString(col) == 'ObjectIdentifier':
                        tableFileHeaderString += 'oid ' + col['name'] + '[MAX_OID_LEN];\n'
                        tableFileHeaderString += 'size_t ' + col['name'] + '_len;\n'
                    else:
                        tableFileHeaderString += self.ctypeClasses[self.getObjTypeString(col)] + ' ' + col['name'] + ';\n'
            tableFileHeaderString += '} ' + tableName + '_data;\n\n'
            tableFileHeaderString += 'typedef struct ' + tableName + '_mib_index_s {\n'
            for idx in indexes:
                if self.getObjTypeString(idx) == 'OctetString':
                    stringLength = self.getStringLength(idx)
                    tableFileHeaderString += 'char ' + idx['name'] + '[' + str(stringLength) + '];\n'
                    tableFileHeaderString += 'size_t ' + idx['name'] + '_len;\n'
                elif self.getObjTypeString(idx) == 'ObjectIdentifier':
                    tableFileHeaderString += 'oid ' + idx['name'] + '[MAX_OID_LEN];\n'
                    tableFileHeaderString += 'size_t ' + idx['name'] + '_len;\n'
                else:
                    tableFileHeaderString += self.ctypeClasses[self.getObjTypeString(idx)] + ' ' + idx['name'] + ';\n'
            tableFileHeaderString += '} ' + tableName + '_mib_index;\n\n'
            #tableFileHeaderString += '#define MAX_' + tableName+'_IDX_LEN 1'
            tableFileHeaderString += 'typedef struct ' + tableName + '_rowreq_ctx_s {\n'
            tableFileHeaderString += 'netsnmp_index oid_idx;\n'
            tableFileHeaderString += 'oid oid_tmp[MAX_OID_LEN];\n'
            tableFileHeaderString += tableName + '_mib_index tbl_idx;\n'
            tableFileHeaderString += tableName + '_data data;\n'
            tableFileHeaderString += 'u_int rowreq_flags;\n'
            tableFileHeaderString += 'netsnmp_data_list *' + tableName + '_data_list;\n'
            tableFileHeaderString += '} ' + tableName + '_rowreq_ctx;\n\n'
            tableFileHeaderString += 'typedef struct ' + tableName + '_ref_rowreq_ctx_s {\n'
            tableFileHeaderString += tableName + '_rowreq_ctx *rowreq_ctx;\n'
            tableFileHeaderString += '} ' + tableName + '_ref_rowreq_ctx;\n\n'
            tableFileHeaderString += 'int ' + tableName + '_pre_request(' + tableName + '_registration *user_context);\n'
            tableFileHeaderString += 'int ' + tableName + '_post_request(' + tableName + '_registration *user_context, int rc);\n'
            tableFileHeaderString += 'int ' + tableName + '_rowreq_ctx_init(' + tableName + '_rowreq_ctx *rowreq_ctx, void *user_init_ctx);\n'
            tableFileHeaderString += 'void ' + tableName + '_rowreq_ctx_cleanup(' + tableName + '_rowreq_ctx *rowreq_ctx);\n'
            tableFileHeaderString += tableName + '_rowreq_ctx* ' + tableName + '_row_find_by_mib_index(' + tableName + '_mib_index *mib_idx);\n'
            tableFileHeaderString += 'extern const oid ' + tableName + '_oid[];\n'
            tableFileHeaderString += 'extern const int ' + tableName + '_oid_size;\n'
            tableFileHeaderString += '#include "' + tableName + '_interface.h"\n'
            tableFileHeaderString += '#include "' + tableName + '_data_access.h"\n'
            tableFileHeaderString += '#include "' + tableName + '_data_get.h"\n'
            tableFileHeaderString += '#include "' + tableName + '_data_set.h"\n\n'
            tableFileHeaderString += '#endif'
            self.fileWrite(fileName= tableName + '.h',data=tableFileHeaderString)

            tableOidsHeaderString = '#ifndef ' + tableName.upper() + '_OIDS_H\n'
            tableOidsHeaderString += '#define ' + tableName.upper() + '_OIDS_H\n'
            tableOidsHeaderString += '#include <sys/types.h>\n\n'
            oidStr,parentOid = self.tables[tableName]['data']['oid']
            oidStr = oidStr.replace('[','').replace(']','')
            tableOidsHeaderString += '#define ' + tableName.upper() + '_OID ' + oidStr + '\n'
            minColumn = None
            for col in self.tableRows[self.tables[tableName]['row']]['columns']:
                tempOid, tempParentOid = col['oid']
                tempOid = tempOid[tempOid.rfind(',') + 1:tempOid.rfind(']')]
                if col not in indexes and not minColumn:
                    minColumn = col
                tableOidsHeaderString += '#define COLUMN_' + col['name'].upper() + ' ' + tempOid + '\n'
            tableOidsHeaderString += '\n\n#define ' + tableName.upper() + '_MIN_COL COLUMN_' + minColumn['name'].upper() + '\n'
            tableOidsHeaderString += '#define ' + tableName.upper() + '_MAX_COL COLUMN_' + self.tableRows[self.tables[tableName]['row']]['columns'][-1]['name'].upper() + '\n'
            tableOidsHeaderString += '#endif'
            self.fileWrite(fileName=tableName + '_oids.h',data=tableOidsHeaderString)

            tableDataGetString = """#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
"""
            tableDataGetString += '#include "' + tableName + '.h"\n\n'
            tableDataGetString += 'int ' + tableName + '_indexes_set_tbl_idx(' + tableName + '_mib_index *tbl_idx'
            for idx in indexes:
                idxType = self.getObjTypeString(idx)
                if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
                    tableDataGetString += ', '
                    if idxType == 'OctetString':
                        tableDataGetString += 'char *'
                    else:
                        tableDataGetString += 'oid *'
                        # Verify if this is the thing for oid
                    tableDataGetString += idx['name'] + '_val_ptr, size_t ' + idx['name'] + '_val_ptr_len'
                else:
                    tableDataGetString += ', ' + self.ctypeClasses[idxType] + ' ' + idx['name'] + '_val'
            tableDataGetString += ') {\n'
            tableDataGetString += 'DEBUGMSGTL(("verbose:' + tableName + ':' + tableName + '_indexes_set_tbl_idx","called\\n"));\n\n'
            for idx in indexes:
                idxType = self.getObjTypeString(idx)
                if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
                    tableDataGetString += '\ntbl_idx->' + idx['name'] + '_len = sizeof(tbl_idx->' + idx['name'] + ')/sizeof(tbl_idx->' + idx['name'] + '[0]);\n'
                    tableDataGetString += 'if ((NULL == tbl_idx->' + idx['name'] + ') || (tbl_idx->' + idx['name'] + '_len < (' + idx['name'] + '_val_ptr_len))) {\n'
                    tableDataGetString += 'snmp_log(LOG_ERR, "not enough space for value (' + idx['name'] + '_val_ptr)\\n");\n'
                    tableDataGetString += 'return MFD_ERROR;\n'
                    tableDataGetString += '}\n'
                    tableDataGetString += 'tbl_idx->' + idx['name'] + '_len = ' + idx['name'] + '_val_ptr_len;\n'
                    tableDataGetString += 'memcpy(tbl_idx->' + idx['name'] + ', ' + idx['name'] + '_val_ptr, ' + idx['name'] + '_val_ptr_len* sizeof(' + idx['name'] + '_val_ptr[0]));\n'
                else:
                    tableDataGetString += 'tbl_idx->' + idx['name'] + ' = ' + idx['name'] + '_val;\n'
            tableDataGetString += 'return MFD_SUCCESS;\n'
            tableDataGetString += '}\n\n'
            tableDataGetString += 'int ' + tableName + '_indexes_set(' + tableName + '_rowreq_ctx *rowreq_ctx'
            for idx in indexes:
                idxType = self.getObjTypeString(idx)
                if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
                    tableDataGetString += ', '
                    if idxType == 'OctetString':
                        tableDataGetString += 'char *'
                    else:
                        tableDataGetString += 'oid *'
                    tableDataGetString += idx['name'] + '_val_ptr, size_t ' + idx['name'] + '_val_ptr_len'
                else:
                    tableDataGetString += ', ' + self.ctypeClasses[self.getObjTypeString(idx)] + ' ' + idx['name'] + '_val'
            tableDataGetString += ') {\n'
            tableDataGetString += 'DEBUGMSGTL(("verbose:' + tableName + ':' + tableName + '_indexes_set","called\\n"));\n'
            tableDataGetString += 'if (MFD_SUCCESS != ' + tableName + '_indexes_set_tbl_idx(&rowreq_ctx->tbl_idx'
            for idx in indexes:
                idxType = self.getObjTypeString(idx)
                if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
                    tableDataGetString += ', ' + idx['name'] + '_val_ptr, ' + idx['name'] + '_val_ptr_len\n'
                else:
                    tableDataGetString += ', ' + idx['name'] + '_val'
            tableDataGetString += ')) {\n'
            tableDataGetString += 'return MFD_ERROR;\n'
            tableDataGetString += '}\n'
            tableDataGetString += 'rowreq_ctx->oid_idx.len = sizeof(rowreq_ctx->oid_tmp)/sizeof(oid);\n'
            tableDataGetString += 'if (0 != ' + tableName + '_index_to_oid(&rowreq_ctx->oid_idx, &rowreq_ctx->tbl_idx)) {\n'
            tableDataGetString += 'return MFD_ERROR;\n'
            tableDataGetString += '}\n'
            tableDataGetString += 'return MFD_SUCCESS;\n'
            tableDataGetString += '}\n\n'
            for idx in indexes:
                if idx['maxaccess'] == 'notaccessible':
                    continue
                tableDataGetString += 'int ' + idx['name'] + '_get(' + tableName + '_rowreq_ctx *rowreq_ctx, '
                idxType = self.getObjTypeString(idx)
                if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
                    if idxType == 'OctetString':
                        tableDataGetString += 'char **'
                    else:
                        tableDataGetString += 'oid **'
                    tableDataGetString += idx['name'] + '_val_ptr_ptr, size_t *' + idx['name'] + '_val_ptr_len_ptr) {\n'
                    tableDataGetString += 'netsnmp_assert( (NULL != ' + idx['name'] + '_val_ptr_ptr) && (NULL != *' + idx['name'] + '_val_ptr_ptr));\n'
                    tableDataGetString += 'netsnmp_assert(NULL != ' + idx['name'] + '_val_ptr_len_ptr);\n'
                else:
                    tableDataGetString += self.ctypeClasses[idxType] + ' *' + idx['name'] + '_val_ptr) {\n'
                    tableDataGetString += 'netsnmp_assert(NULL != ' + idx['name'] + '_val_ptr);\n'
                tableDataGetString += 'DEBUGMSGTL(("verbose:' + tableName + ':' + idx['name'] + '_get","called\\n"));\n'
                tableDataGetString += 'netsnmp_assert(NULL != rowreq_ctx);\n\n'
                if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
                    tableDataGetString += 'if ((NULL == (*' + idx['name'] + '_val_ptr_ptr)) || ((*' + idx['name'] + '_val_ptr_len_ptr) < (rowreq_ctx->tbl_idx.' + idx['name'] + '_len* sizeof(rowreq_ctx->tbl_idx.' + idx['name'] + '[0])))) {\n'
                    tableDataGetString += '(* ' + idx['name'] + '_val_ptr_ptr) = malloc(rowreq_ctx->tbl_idx.' + idx['name'] + '_len* sizeof(rowreq_ctx->tbl_idx.' + idx['name'] + '[0]));\n'
                    tableDataGetString += 'if (NULL == (*' + idx['name'] + '_val_ptr_ptr)) {\n'
                    tableDataGetString += 'snmp_log(LOG_ERR, "could not allocate memory (rowreq_ctx->tbl_idx.' + idx['name'] + ')\\n");\n'
                    tableDataGetString += 'return MFD_ERROR;\n'
                    tableDataGetString += '}\n'
                    tableDataGetString += '}\n'
                    tableDataGetString += '(* ' + idx['name'] + '_val_ptr_len_ptr) = rowreq_ctx->tbl_idx.' + idx['name'] + '_len* sizeof(rowreq_ctx->tbl_idx.' + idx['name'] + '[0]);\n'
                    tableDataGetString += 'memcpy((*' + idx['name'] + '_val_ptr_ptr), rowreq_ctx->tbl_idx.' + idx['name'] + ', rowreq_ctx->tbl_idx.' + idx['name'] + '_len* sizeof(rowreq_ctx->tbl_idx.' + idx['name'] + '[0]));\n'
                else:
                    tableDataGetString += '(*' + idx['name'] + '_val_ptr) = rowreq_ctx->tbl_idx.' + idx['name'] + ';\n'
                tableDataGetString += 'return MFD_SUCCESS;\n'
                tableDataGetString += '}\n\n'
            for col in self.tableRows[self.tables[tableName]['row']]['columns']:
                if col['name'] in [idx['name'] for idx in indexes] or col['maxaccess'] == 'notaccessible':
                    continue
                tableDataGetString += 'int ' + col['name'] + '_get(' + tableName + '_rowreq_ctx *rowreq_ctx, '
                colType = self.getObjTypeString(col)
                if colType == 'OctetString' or colType == 'ObjectIdentifier':
                    if colType == 'OctetString':
                        tableDataGetString += 'char **'
                    else:
                        tableDataGetString += 'oid **'
                    tableDataGetString += col['name'] + '_val_ptr_ptr, size_t *' + col['name'] + '_val_ptr_len_ptr) {\n'
                    tableDataGetString += 'netsnmp_assert( (NULL != ' + col['name'] + '_val_ptr_ptr) && (NULL != *' + col['name'] + '_val_ptr_ptr));\n'
                    tableDataGetString += 'netsnmp_assert(NULL != ' + col['name'] + '_val_ptr_len_ptr);\n'
                else:
                    tableDataGetString += self.ctypeClasses[colType] + ' *' + col['name'] + '_val_ptr) {\n'
                    tableDataGetString += 'netsnmp_assert(NULL != ' + col['name'] + '_val_ptr);\n'
                tableDataGetString += 'DEBUGMSGTL(("verbose:' + tableName + ':' + col['name'] + '_get","called\\n"));\n'
                tableDataGetString += 'netsnmp_assert(NULL != rowreq_ctx);\n\n'
                if colType == 'OctetString' or colType == 'ObjectIdentifier':
                    tableDataGetString += 'if ((NULL == (*' + col['name'] + '_val_ptr_ptr)) || ((*' + col['name'] + '_val_ptr_len_ptr) < (rowreq_ctx->data.' + col['name'] + '_len* sizeof(rowreq_ctx->data.' + col['name'] + '[0])))) {\n'
                    tableDataGetString += '(* ' + col['name'] + '_val_ptr_ptr) = malloc(rowreq_ctx->data.' + col['name'] + '_len* sizeof(rowreq_ctx->data.' + col['name'] + '[0]));\n'
                    tableDataGetString += 'if (NULL == (*' + col['name'] + '_val_ptr_ptr)) {\n'
                    tableDataGetString += 'snmp_log(LOG_ERR, "could not allocate memory (rowreq_ctx->data.' + col['name'] + ')\\n");\n'
                    tableDataGetString += 'return MFD_ERROR;\n'
                    tableDataGetString += '}\n'
                    tableDataGetString += '}\n'
                    tableDataGetString += '(* ' + col['name'] + '_val_ptr_len_ptr) = rowreq_ctx->data.' + col['name'] + '_len* sizeof(rowreq_ctx->data.' + col['name'] + '[0]);\n'
                    tableDataGetString += 'memcpy((*' + col['name'] + '_val_ptr_ptr), rowreq_ctx->data.' + col['name'] + ', rowreq_ctx->data.' + col['name'] + '_len* sizeof(rowreq_ctx->data.' + col['name'] + '[0]));\n'
                else:
                    tableDataGetString += '(*' + col['name'] + '_val_ptr) = rowreq_ctx->data.' + col['name'] + ';\n'
                tableDataGetString += 'return MFD_SUCCESS;\n'
                tableDataGetString += '}\n\n'
            self.fileWrite(fileName=tableName + '_data_get.c',data=tableDataGetString)

            tableDataGetHeaderString = '#ifndef ' + tableName.upper() + '_DATA_GET_H\n'
            tableDataGetHeaderString += '#define ' + tableName.upper() + '_DATA_GET_H\n\n'
            for idx in indexes:
                if idx['maxaccess'] == 'notaccessible':
                    continue
                idxType = self.getObjTypeString(idx)
                if idxType == 'OctetString':
                    tableDataGetHeaderString += 'int ' + idx['name'] + '_get(' + tableName + '_rowreq_ctx *rowreq_ctx, char **' + idx['name'] + '_val_ptr_ptr, size_t *' + idx['name'] + '_val_ptr_len_ptr);\n\n'
                elif idxType == 'ObjectIdentifier':
                    tableDataGetHeaderString += 'int ' + idx['name'] + '_get(' + tableName + '_rowreq_ctx *rowreq_ctx, oid **' + idx['name'] + '_val_ptr_ptr, size_t *' + idx['name'] + '_val_ptr_len_ptr);\n\n'
                else:
                    tableDataGetHeaderString += 'int ' + idx['name'] + '_get(' + tableName + '_rowreq_ctx *rowreq_ctx,' + self.ctypeClasses[idxType] + ' *' + idx['name'] + '_val_ptr);\n\n'
            for col in self.tableRows[self.tables[tableName]['row']]['columns']:
                if col['name'] in [idx['name'] for idx in indexes] or col['maxaccess'] == 'notaccessible':
                    continue
                colType = self.getObjTypeString(col)
                if colType == 'OctetString':
                    tableDataGetHeaderString += 'int ' + col['name'] + '_get(' + tableName + '_rowreq_ctx *rowreq_ctx, char **' + col['name'] + '_val_ptr_ptr, size_t *' + col['name'] + '_val_ptr_len_ptr);\n\n'
                elif colType == 'ObjectIdentifier':
                    tableDataGetHeaderString += 'int ' + col['name'] + '_get(' + tableName + '_rowreq_ctx *rowreq_ctx, oid **' + col['name'] + '_val_ptr_ptr, size_t *' + col['name'] + '_val_ptr_len_ptr);\n\n'
                else:
                    tableDataGetHeaderString += 'int ' + col['name'] + '_get(' + tableName + '_rowreq_ctx *rowreq_ctx,' + self.ctypeClasses[colType] + ' *' + col['name'] + '_val_ptr);\n\n'
            tableDataGetHeaderString += 'int ' + tableName + '_indexes_set_tbl_idx(' + tableName + '_mib_index *tbl_idx'
            for idx in indexes:
                idxType = self.getObjTypeString(idx)
                if idxType == 'OctetString':
                    tableDataGetHeaderString += ', char *' + idx['name'] + '_val_ptr, size_t ' + idx['name'] + '_val_ptr_len'
                elif idxType == 'ObjectIdentifier':
                    tableDataGetHeaderString += ', oid *' + idx['name'] + '_val_ptr, size_t ' + idx['name'] + '_val_ptr_len'
                else:
                    tableDataGetHeaderString += ', ' + self.ctypeClasses[idxType] + ' ' + idx['name'] + '_val'
            tableDataGetHeaderString += ');\n\n'
            tableDataGetHeaderString += 'int ' + tableName + '_indexes_set(' + tableName + '_rowreq_ctx *rowreq_ctx'
            for idx in indexes:
                idxType = self.getObjTypeString(idx)
                if idxType == 'OctetString':
                    tableDataGetHeaderString += ', char *' + idx['name'] + '_val_ptr, size_t ' + idx['name'] + '_val'
                elif idxType == 'ObjectIdentifier':
                    tableDataGetHeaderString += ', oid *' + idx['name'] + '_val_ptr, size_t ' + idx['name'] + '_val'
                else:
                    tableDataGetHeaderString += ', ' + self.ctypeClasses[idxType] + ' ' + idx['name'] + '_val'
            tableDataGetHeaderString += ');\n'
            tableDataGetHeaderString += '#endif\n'
            self.fileWrite(fileName=tableName + '_data_get.h',data=tableDataGetHeaderString)

            tableDataSetString = """#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
"""
            tableDataSetString += '#include "' + tableName + '.h"\n'
            self.fileWrite(fileName=tableName + '_data_set.c',data=tableDataSetString)

            tableDataSetHeaderString = '#ifndef ' + tableName.upper() + '_DATA_SET_H\n'
            tableDataSetHeaderString += '#define ' + tableName.upper() + '_DATA_SET_H\n'
            tableDataSetHeaderString += '#endif\n'
            self.fileWrite(fileName=tableName + '_data_set.h',data=tableDataSetHeaderString)

            tableDataAccessString = """#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
"""
            tableDataAccessString += '#include "' + moduleName + '_custom.h"\n'
            tableDataAccessString += '#include "' + moduleName + '_publisher.h"\n'
            tableDataAccessString += '#include "' + tableName + '.h"\n'
            tableDataAccessString += '#include "' + tableName + '_data_access.h"\n'
            tableDataAccessString += '#include "' + tableName + '_ovsdb_get.h"\n\n'
            tableDataAccessString += '#include "openswitch-idl.h"\n'
            tableDataAccessString += '#include "ovsdb-idl.h"\n'
            tableDataAccessString += '#include "vswitch-idl.h"\n'
            tableDataAccessString += '#include "openvswitch/vlog.h"\n\n'
            tableDataAccessString += 'VLOG_DEFINE_THIS_MODULE('+ tableName +'data_access);\n\n'
            tableDataAccessString += 'int ' + tableName + '_init_data(' + tableName + '_registration *' + tableName + '_reg) {\n'
            tableDataAccessString += 'DEBUGMSGTL(("verbose:' + tableName + ':' + tableName + '_init_data","called\\n"));\n'
            tableDataAccessString += 'return MFD_SUCCESS;\n'
            tableDataAccessString += '}\n\n'
            tableDataAccessString += 'void ' + tableName + '_container_init(netsnmp_container **container_ptr_ptr, netsnmp_cache *cache) {\n'
            tableDataAccessString += 'DEBUGMSGTL(("verbose:' + tableName + ':' + tableName + '_container_init","called\\n"));\n'
            tableDataAccessString += 'if (NULL == container_ptr_ptr) {\n'
            tableDataAccessString += 'snmp_log(LOG_ERR,"bad container param to ' + tableName + '_container_init\\n");\n'
            tableDataAccessString += 'return;\n'
            tableDataAccessString += '}\n'
            tableDataAccessString += '*container_ptr_ptr = NULL;\n'
            tableDataAccessString += 'if (NULL == cache) {\n'
            tableDataAccessString += 'snmp_log(LOG_ERR,"bad cache param to ' + tableName + '_container_init\\n");\n'
            tableDataAccessString += 'return;\n'
            tableDataAccessString += '}\n'
            tableDataAccessString += 'cache->timeout = ' + tableName.upper() + '_CACHE_TIMEOUT;\n'
            tableDataAccessString += '}\n\n'
            tableDataAccessString += 'void ' + tableName + '_container_shutdown(netsnmp_container *container_ptr) {\n'
            tableDataAccessString += 'DEBUGMSGTL(("verbose:' + tableName + ':' + tableName + '_container_shutdown","called\\n"));\n'
            tableDataAccessString += 'if (NULL == container_ptr) {\n'
            tableDataAccessString += 'snmp_log(LOG_ERR, "bad params to ' + tableName + '_container_shutdown\\n");\n'
            tableDataAccessString += 'return;\n'
            tableDataAccessString += '}\n'
            tableDataAccessString += '}\n\n'
            tableDataAccessString += 'int ' + tableName + '_container_load(netsnmp_container *container) {\n'
            tableDataAccessString += 'DEBUGMSGTL(("verbose:' + tableName + ':' + tableName + '_container_load","called\\n"));\n'
            tableDataAccessString += tableName + '_rowreq_ctx *rowreq_ctx;\n'
            tableDataAccessString += 'size_t count = 0;\n\n'
            tableDataAccessString += self.getOvsdbRowsStringForTable(ovsdbTables)
            tableDataAccessString += self.getLocalsStringForTable(tableName, indexes)
            tableDataAccessString += self.getFirstIntanceStringForTable(tableName,ovsdbTables)
            tableDataAccessString += self.publishRequestStringForTable(tableName, indexes)
            tableDataAccessString += self.getForLoopStringForTable(tableName, indexes)
            tableDataAccessString += 'DEBUGMSGTL(("verbose:' + tableName + ':' + tableName + '_container_load","inserted %d records\\n",(int)count));\n'
            tableDataAccessString += 'return MFD_SUCCESS;\n'
            tableDataAccessString += '}\n\n'
            tableDataAccessString += 'void ' + tableName + '_container_free(netsnmp_container *container) {\n'
            tableDataAccessString += 'DEBUGMSGTL(("verbose:' + tableName + ':' + tableName + '_container_free","called\\n"));\n'
            tableDataAccessString += '}\n\n'
            tableDataAccessString += 'int ' + tableName + '_row_prep(' + tableName + '_rowreq_ctx *rowreq_ctx) {\n'
            tableDataAccessString += 'DEBUGMSGTL(("verbose:' + tableName + ':' + tableName + '_row_prep","called\\n"));\n'
            tableDataAccessString += 'netsnmp_assert(NULL != rowreq_ctx);\n'
            tableDataAccessString += 'return MFD_SUCCESS;\n'
            tableDataAccessString += '}\n'
            self.fileWrite(fileName=tableName + '_data_access.c',data=tableDataAccessString)

            tableDataAccessHeaderString = '#ifndef ' + tableName.upper() + '_DATA_ACCESS_H\n'
            tableDataAccessHeaderString += '#define ' + tableName.upper() + '_DATA_ACCESS_H\n\n'
            tableDataAccessHeaderString += 'extern struct ovsdb_idl *idl;\n\n'
            tableDataAccessHeaderString += 'int ' + tableName + '_init_data(' + tableName + '_registration *' + tableName + '_reg);\n'
            if self.jsonData[tableName]['CacheTimeout']:
                tableDataAccessHeaderString += '#define ' + tableName.upper() + '_CACHE_TIMEOUT ' + str(self.jsonData[tableName]['CacheTimeout']) + '\n'
            else:
                tableDataAccessHeaderString += '#define ' + tableName.upper() + '_CACHE_TIMEOUT 30\n'
            tableDataAccessHeaderString += 'void ' + tableName + '_container_init(netsnmp_container ** container_ptr_ptr, netsnmp_cache *cache);\n'
            tableDataAccessHeaderString += 'void ' + tableName + '_container_shutdown(netsnmp_container *container_ptr);\n'
            tableDataAccessHeaderString += 'int ' + tableName + '_container_load(netsnmp_container *container);\n'
            tableDataAccessHeaderString += 'void ' + tableName + '_container_free(netsnmp_container *container);\n'
            tableDataAccessHeaderString += 'int ' + tableName + '_cache_load(netsnmp_container *container);\n'
            tableDataAccessHeaderString += 'void ' + tableName + '_cache_free(netsnmp_container *container);\n'
            tableDataAccessHeaderString += 'int ' + tableName + '_row_prep(' + tableName + '_rowreq_ctx *rowreq_ctx);\n'
            tableDataAccessHeaderString += '#endif'
            self.fileWrite(fileName=tableName + '_data_access.h',data=tableDataAccessHeaderString)

            tableOvsdbGetString = """#include "openswitch-idl.h"
#include "ovsdb-idl.h"
#include "vswitch-idl.h"
#include "openvswitch/vlog.h"
"""
            tableOvsdbGetString += '#include "' + moduleName + '_custom.h"\n'
            tableOvsdbGetString += '#include "' + tableName + '_ovsdb_get.h"\n\n'
            tableOvsdbGetString += 'void ' + tableName + '_ovsdb_idl_init(struct ovsdb_idl* idl){\n'
            for (ovsdbRow, ovsdbCol) in self.getOvsdbTableColumnsForTable(tableName):
                tableOvsdbGetString += 'ovsdb_idl_add_column(idl, &ovsrec_' + ovsdbRow + '_col_' + ovsdbCol + ');\n'
            tableOvsdbGetString += '}\n\n'
            for idx in indexes:
                dbIdx = self.jsonData[tableName]['Indexes'][idx['name']]
                idxTable = dbIdx['OvsTable']
                idxType = self.getObjTypeString(idx)
                if idx['name'] in self.generatedSymbols:
                    continue
                if not idxTable:
                    tableOvsdbGetString += 'void ovsdb_get_' + idx['name'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, '
                    if idxType == 'OctetString':
                        tableOvsdbGetString += 'char *' + idx['name'] + '_val_ptr, size_t* ' + idx['name'] + '_val_ptr_len) {\n'
                        if dbIdx['CustomFunction']:
                            tableOvsdbGetString += dbIdx['CustomFunction'] + '(idl, ' + rootDbTable + '_row, ' + idx['name'] + '_val_ptr, ' + idx['name'] + '_val_ptr_len);\n'
                            self.customFileHeaderString += 'void ' + dbIdx['CustomFunction'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, char *' + idx['name'] + '_val_ptr, size_t* ' + idx['name'] + '_val_ptr_len);\n\n'
                        else:
                            tableOvsdbGetString += '*' + idx['name'] + '_val_ptr = \'\\0\';\n'
                            tableOvsdbGetString += '*' + idx['name'] + '_val_ptr_len = 0;\n'
                    elif idxType == 'ObjectIdentifier':
                        tableOvsdbGetString += 'oid *' + idx['name'] + '_val_ptr, size_t* ' + idx['name'] + '_val_ptr_len) {\n'
                        if dbIdx['CustomFunction']:
                            tableOvsdbGetString += dbIdx['CustomFunction'] + '(idl, ' + rootDbTable + '_row, ' + idx['name'] + '_val_ptr, ' + idx['name'] + '_val_ptr_len);\n'
                            self.customFileHeaderString += 'void ' + dbIdx['CustomFunction'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, oid *' + idx['name'] + '_val_ptr, size_t* ' + idx['name'] + '_val_ptr_len);\n\n'
                        else:
                            tableOvsdbGetString += '*' + idx['name'] + '_val_ptr = (oid)NULL;\n'
                            tableOvsdbGetString += '*' + idx['name'] + '_val_ptr_len = 0;\n'
                    else:
                        tableOvsdbGetString += self.ctypeClasses[idxType] + ' *' + idx['name'] + '_val_ptr) {\n'
                        if dbIdx['CustomFunction']:
                            tableOvsdbGetString += dbIdx['CustomFunction'] + '(idl, ' + rootDbTable + '_row, ' + idx['name'] + '_val_ptr);\n'
                            self.customFileHeaderString += 'void ' + dbIdx['CustomFunction'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, ' + self.ctypeClasses[idxType] + ' *' + idx['name'] + '_val_ptr);\n\n'
                        else:
                            tableOvsdbGetString += '*' + idx['name'] + '_val_ptr = (' + self.ctypeClasses[idxType] + ')NULL;\n'
                    tableOvsdbGetString += '}\n\n'
                    self.generatedSymbols[idx['name']] = 1
                elif idxTable != rootDbTable:
                    tableOvsdbGetString += 'void ovsdb_get_' + idx['name'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, const struct ovsrec_' + idxTable + ' *' + idxTable + '_row, '
                    if idxType == 'OctetString':
                        tableOvsdbGetString += 'char *' + idx['name'] + '_val_ptr, size_t* ' + idx['name'] + '_val_ptr_len) {\n'
                        if dbIdx['CustomFunction']:
                            tableOvsdbGetString += dbIdx['CustomFunction'] + '(idl, ' + rootDbTable + '_row, ' + idxTable + '_row, ' + idx['name'] + '_val_ptr, ' + idx['name'] + '_val_ptr_len);\n'
                            self.customFileHeaderString += 'void ' + dbIdx['CustomFunction'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, const struct ovsrec_' + idxTable + ' *' + idxTable + '_row, char *' + idx['name'] + '_val_ptr, size_t* ' + idx['name'] + '_val_ptr_len);\n\n'
                        else:
                            tableOvsdbGetString += 'char *temp = NULL;\n'
                            if dbIdx['Type']['Key']:
                                if type(dbIdx['Type']['Key']) == dict:
                                    keyType = dbIdx['Type']['Key']['KeyType']
                                    keyValue = dbIdx['Type']['Key']['KeyName']
                                    if keyType == 'str':
                                        tableOvsdbGetString += 'for (int i = 0; i < ' + idxTable+'_row->n_'+dbIdx['OvsColumn']+'; i++) {\n'
                                        tableOvsdbGetString += 'if(strcmp("'+keyValue+'", '+idxTable+'_row->key_'+dbIdx['OvsColumn']+'[i]) == 0) {\n'
                                        tableOvsdbGetString += 'temp = (char*)'+idxTable+'_row->value_'+dbIdx['OvsColumn']+'[i];\n'
                                        tableOvsdbGetString += '}\n'
                                        tableOvsdbGetString += '}\n'
                                    elif keyType == 'int':
                                        tableOvsdbGetString += 'for (int i = 0; i < ' + idxTable+'_row->n_'+dbIdx['OvsColumn']+'; i++) {\n'
                                        tableOvsdbGetString += 'if('+keyValue+' == '+idxTable+'_row->key_'+dbIdx['OvsColumn']+'[i]) {\n'
                                        tableOvsdbGetString += 'temp = (char*)'+idxTable+'_row->value_'+dbIdx['OvsColumn']+'[i];\n'
                                        tableOvsdbGetString += '}\n'
                                        tableOvsdbGetString += '}\n'
                                else:
                                    tableOvsdbGetString += 'temp = (char*)smap_get(&' + idxTable + '_row->' + dbIdx['OvsColumn'] + ', "' + dbIdx['Type']['Key'] + '");\n'
                            else:
                                tableOvsdbGetString += 'temp = (char*)'+idxTable + '_row->' + dbIdx['OvsColumn'] + ';\n'
                            tableOvsdbGetString += '*' + idx['name'] + '_val_ptr_len = temp != NULL ? strlen(temp) : 0;\n'
                            tableOvsdbGetString += 'memcpy(' + idx['name'] + '_val_ptr' + ', temp, *' + idx['name'] + '_val_ptr_len);\n'
                    elif idxType == 'ObjectIdentifier':
                        tableOvsdbGetString += 'oid *' + idx['name'] + '_val_ptr, size_t* ' + idx['name'] + '_val_ptr_len) {\n'
                        if dbIdx['CustomFunction']:
                            tableOvsdbGetString += dbIdx['CustomFunction'] + '(idl, ' + rootDbTable + '_row, ' + idxTable + '_row, ' + idx['name'] + '_val_ptr, ' + idx['name'] + '_val_ptr_len);\n'
                            self.customFileHeaderString += 'void ' + dbIdx['CustomFunction'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, const struct ovsrec_' + idxTable + ' *' + idxTable + '_row, oid *' + idx['name'] + '_val_ptr, size_t* ' + idx['name'] + '_val_ptr_len);\n\n'
                        else:
                            tableOvsdbGetString += 'char *temp = NULL;\n'
                            if dbIdx['Type']['Key']:
                                if type(dbIdx['Type']['Key']) == dict:
                                    keyType = dbIdx['Type']['Key']['KeyType']
                                    keyValue = dbIdx['Type']['Key']['KeyName']
                                    if keyType == 'str':
                                        tableOvsdbGetString += 'for (int i = 0; i < ' + idxTable+'_row->n_'+dbIdx['OvsColumn']+'; i++) {\n'
                                        tableOvsdbGetString += 'if(strcmp("'+keyValue+'", '+idxTable+'_row->key_'+dbIdx['OvsColumn']+'[i]) == 0) {\n'
                                        tableOvsdbGetString += 'temp = (char*)'+idxTable+'_row->value_'+dbIdx['OvsColumn']+'[i];\n'
                                        tableOvsdbGetString += '}\n'
                                        tableOvsdbGetString += '}\n'
                                    elif keyType == 'int':
                                        tableOvsdbGetString += 'for (int i = 0; i < ' + idxTable+'_row->n_'+dbIdx['OvsColumn']+'; i++) {\n'
                                        tableOvsdbGetString += 'if('+keyValue+' == '+idxTable+'_row->key_'+dbIdx['OvsColumn']+'[i]) {\n'
                                        tableOvsdbGetString += 'temp = (char*)'+idxTable+'_row->value_'+dbIdx['OvsColumn']+'[i];\n'
                                        tableOvsdbGetString += '}\n'
                                        tableOvsdbGetString += '}\n'
                                else:
                                    tableOvsdbGetString += 'temp = (char*)smap_get(&' + idxTable + '_row->' + dbIdx['OvsColumn'] + ', "' + dbIdx['Type']['Key'] + '");\n'
                            else:
                                tableOvsdbGetString += 'temp = (char*)'+idxTable + '_row->' + dbIdx['OvsColumn'] + ';\n'
                            tableOvsdbGetString += 'oid temp_oid[MAX_OID_LEN] = {0};\n'
                            tableOvsdbGetString += '*' + idx['name'] + '_val_ptr_len = MAX_OID_LEN;\n'
                            tableOvsdbGetString += 'if (temp != NULL) {\n'
                            tableOvsdbGetString += 'snmp_parse_oid(temp, temp_oid, ' + idx['name'] + '_val_ptr_len);\n'
                            tableOvsdbGetString += '}\n'
                            tableOvsdbGetString += 'memcpy(' + idx['name'] + '_val_ptr, temp_oid, *' + idx['name'] + '_val_ptr_len);\n'
                    else:
                        tableOvsdbGetString += self.ctypeClasses[idxType] + ' *' + idx['name'] + '_val_ptr) {\n'
                        if dbIdx['CustomFunction']:
                            tableOvsdbGetString += dbIdx['CustomFunction'] + '(idl, ' + rootDbTable + '_row, ' + idxTable + '_row, ' + idx['name'] + '_val_ptr);\n'
                            self.customFileHeaderString += 'void ' + dbIdx['CustomFunction'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, const struct ovsrec_' + idxTable + ' *' + idxTable + '_row, ' + self.ctypeClasses[idxType] + ' *' + idx['name'] + '_val_ptr);\n\n'
                        else:
                            if dbIdx['Type']['Key']:
                                if type(dbIdx['Type']['Key']) == dict:
                                    keyType = dbIdx['Type']['Key']['KeyType']
                                    keyValue = dbIdx['Type']['Key']['KeyName']
                                    if keyType == 'str':
                                        tableOvsdbGetString += 'for (int i = 0; i < ' + idxTable+'_row->n_'+dbIdx['OvsColumn']+'; i++) {\n'
                                        tableOvsdbGetString += 'if(strcmp("'+keyValue+'", '+idxTable+'_row->key_'+dbIdx['OvsColumn']+'[i]) == 0) {\n'
                                        tableOvsdbGetString += '*'+idx['name']+'_val_ptr = ('+self.ctypeClasses[idxType]+')'+idxTable+'_row->value_'+dbIdx['OvsColumn']+'[i];\n'
                                        tableOvsdbGetString += '}\n'
                                        tableOvsdbGetString += '}\n'
                                    elif keyType == 'int':
                                        tableOvsdbGetString += 'for (int i = 0; i < ' + idxTable+'_row->n_'+dbIdx['OvsColumn']+'; i++) {\n'
                                        tableOvsdbGetString += 'if('+keyValue+' == '+idxTable+'_row->key_'+dbIdx['OvsColumn']+'[i]) {\n'
                                        tableOvsdbGetString += '*'+idx['name']+'_val_ptr = ('+self.ctypeClasses[idxType]+')'+idxTable+'_row->value_'+dbIdx['OvsColumn']+'[i];\n'
                                        tableOvsdbGetString += '}\n'
                                        tableOvsdbGetString += '}\n'
                                else:
                                    tableOvsdbGetString += 'char *temp = (char*)'
                                    tableOvsdbGetString += 'smap_get(&' + idxTable + '_row->' + dbIdx['OvsColumn'] + ', "' + dbIdx['Type']['Key'] + '");\n'
                                    tableOvsdbGetString += 'if(temp == NULL) {\n'
                                    tableOvsdbGetString += '*' + idx['name'] + '_val_ptr = 0;\n'
                                    tableOvsdbGetString += '}\n'
                                    tableOvsdbGetString += 'else {\n'
                                    tableOvsdbGetString += '*' + idx['name'] + '_val_ptr = (' + self.ctypeClasses[idxType] + ')atoi(temp);\n'
                                    tableOvsdbGetString += '}\n'
                            else:
                                tableOvsdbGetString += '*' + idx['name'] + '_val_ptr = (' + self.ctypeClasses[idxType] + ')*('
                                tableOvsdbGetString += idxTable + '_row->' + dbIdx['OvsColumn'] + ');\n'
                    tableOvsdbGetString += '}\n\n'
                    self.generatedSymbols[idx['name']] = 1
                else:
                    tableOvsdbGetString += 'void ovsdb_get_' + idx['name'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, '
                    if idxType == 'OctetString':
                        tableOvsdbGetString += 'char *' + idx['name'] + '_val_ptr, size_t* ' + idx['name'] + '_val_ptr_len) {\n'
                        if dbIdx['CustomFunction']:
                            tableOvsdbGetString += dbIdx['CustomFunction'] + '(idl, ' + rootDbTable + '_row, ' + idx['name'] + '_val_ptr, ' + idx['name'] + '_val_ptr_len);\n'
                            self.customFileHeaderString += 'void ' + dbIdx['CustomFunction'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, char *' + idx['name'] + '_val_ptr, size_t* ' + idx['name'] + '_val_ptr_len);\n\n'
                        else:
                            tableOvsdbGetString += 'char *temp = NULL;\n'
                            if dbIdx['Type']['Key']:
                                if type(dbIdx['Type']['Key']) == dict:
                                    keyType = dbIdx['Type']['Key']['KeyType']
                                    keyValue = dbIdx['Type']['Key']['KeyName']
                                    if keyType == 'str':
                                        tableOvsdbGetString += 'for (int i = 0; i < ' + rootDbTable+'_row->n_'+dbIdx['OvsColumn']+'; i++) {\n'
                                        tableOvsdbGetString += 'if(strcmp("'+keyValue+'", '+rootDbTable+'_row->key_'+dbIdx['OvsColumn']+'[i]) == 0) {\n'
                                        tableOvsdbGetString += 'temp = (char*)'+rootDbTable+'_row->value_'+dbIdx['OvsColumn']+'[i];\n'
                                        tableOvsdbGetString += '}\n'
                                        tableOvsdbGetString += '}\n'
                                    elif keyType == 'int':
                                        tableOvsdbGetString += 'for (int i = 0; i < ' + rootDbTable+'_row->n_'+dbIdx['OvsColumn']+'; i++) {\n'
                                        tableOvsdbGetString += 'if('+keyValue+' == '+rootDbTable+'_row->key_'+dbIdx['OvsColumn']+'[i]) {\n'
                                        tableOvsdbGetString += 'temp = (char*)'+rootDbTable+'_row->value_'+dbIdx['OvsColumn']+'[i];\n'
                                        tableOvsdbGetString += '}\n'
                                        tableOvsdbGetString += '}\n'
                                else:
                                    tableOvsdbGetString += 'temp = (char*)smap_get(&' + rootDbTable + '_row->' + dbIdx['OvsColumn'] + ', "' + dbIdx['Type']['Key'] + '");\n'
                            else:
                                tableOvsdbGetString += 'temp = (char*)' + rootDbTable + '_row->' + dbIdx['OvsColumn'] + ';\n'
                            tableOvsdbGetString += '*' + idx['name'] + '_val_ptr_len = temp != NULL ? strlen(temp) : 0;\n'
                            tableOvsdbGetString += 'memcpy(' + idx['name'] + '_val_ptr' + ', temp, *' + idx['name'] + '_val_ptr_len);\n'
                    elif idxType == 'ObjectIdentifier':
                        tableOvsdbGetString += 'oid *' + idx['name'] + '_val_ptr, size_t* ' + idx['name'] + '_val_ptr_len) {\n'
                        if dbIdx['CustomFunction']:
                            tableOvsdbGetString += dbIdx['CustomFunction'] + '(idl, ' + rootDbTable + '_row, ' + idx['name'] + '_val_ptr, ' + idx['name'] + '_val_ptr_len);\n'
                            self.customFileHeaderString += 'void ' + dbIdx['CustomFunction'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, oid *' + idx['name'] + '_val_ptr, size_t* ' + idx['name'] + '_val_ptr_len);\n\n'
                        else:
                            tableOvsdbGetString += 'char *temp = NULL;\n'
                            if dbIdx['Type']['Key']:
                                if type(dbIdx['Type']['Key']) == dict:
                                    keyType = dbIdx['Type']['Key']['KeyType']
                                    keyValue = dbIdx['Type']['Key']['KeyName']
                                    if keyType == 'str':
                                        tableOvsdbGetString += 'for (int i = 0; i < ' + rootDbTable+'_row->n_'+dbIdx['OvsColumn']+'; i++) {\n'
                                        tableOvsdbGetString += 'if(strcmp("'+keyValue+'", '+rootDbTable+'_row->key_'+dbIdx['OvsColumn']+'[i]) == 0) {\n'
                                        tableOvsdbGetString += 'temp = (char*)'+rootDbTable+'_row->value_'+dbIdx['OvsColumn']+'[i];\n'
                                        tableOvsdbGetString += '}\n'
                                        tableOvsdbGetString += '}\n'
                                    elif keyType == 'int':
                                        tableOvsdbGetString += 'for (int i = 0; i < ' + rootDbTable+'_row->n_'+dbIdx['OvsColumn']+'; i++) {\n'
                                        tableOvsdbGetString += 'if('+keyValue+' == '+rootDbTable+'_row->key_'+dbIdx['OvsColumn']+'[i]) {\n'
                                        tableOvsdbGetString += 'temp = (char*)'+rootDbTable+'_row->value_'+dbIdx['OvsColumn']+'[i];\n'
                                        tableOvsdbGetString += '}\n'
                                        tableOvsdbGetString += '}\n'
                                else:
                                    tableOvsdbGetString += 'temp = (char*)smap_get(&' + rootDbTable + '_row->' + dbIdx['OvsColumn'] + ', "' + dbIdx['Type']['Key'] + '");\n'
                            else:
                                tableOvsdbGetString += 'temp = (char*)' + rootDbTable + '_row->' + dbIdx['OvsColumn'] + ';\n'
                            tableOvsdbGetString += 'oid temp_oid[MAX_OID_LEN] = {0};\n'
                            tableOvsdbGetString += '*' + idx['name'] + '_val_ptr_len = MAX_OID_LEN;\n'
                            tableOvsdbGetString += 'if (temp != NULL) {\n'
                            tableOvsdbGetString += 'snmp_parse_oid(temp, temp_oid, ' + idx['name'] + '_val_ptr_len);\n'
                            tableOvsdbGetString += '}\n'
                            tableOvsdbGetString += 'memcpy(' + idx['name'] + '_val_ptr, temp_oid, *' + idx['name'] + '_val_ptr_len);\n'
                    else:
                        tableOvsdbGetString += self.ctypeClasses[idxType] + ' *' + idx['name'] + '_val_ptr) {\n'
                        if dbIdx['CustomFunction']:
                            tableOvsdbGetString += dbIdx['CustomFunction'] + '(idl, ' + rootDbTable + '_row, ' + idx['name'] + '_val_ptr);\n'
                            self.customFileHeaderString += 'void ' + dbIdx['CustomFunction'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, ' + self.ctypeClasses[idxType] + ' *' + idx['name'] + '_val_ptr);\n\n'
                        else:
                            if dbIdx['Type']['Key']:
                                if type(dbIdx['Type']['Key']) == dict:
                                    keyType = dbIdx['Type']['Key']['KeyType']
                                    keyValue = dbIdx['Type']['Key']['KeyName']
                                    if keyType == 'str':
                                        tableOvsdbGetString += 'for (int i = 0; i < ' + rootDbTable+'_row->n_'+dbIdx['OvsColumn']+'; i++) {\n'
                                        tableOvsdbGetString += 'if(strcmp("'+keyValue+'", '+rootDbTable+'_row->key_'+dbIdx['OvsColumn']+'[i]) == 0) {\n'
                                        tableOvsdbGetString += '*'+idx['name']+'_val_ptr = ('+self.ctypeClasses[idxType]+')'+rootDbTable+'_row->value_'+dbIdx['OvsColumn']+'[i];\n'
                                        tableOvsdbGetString += '}\n'
                                        tableOvsdbGetString += '}\n'
                                    elif keyType == 'int':
                                        tableOvsdbGetString += 'for (int i = 0; i < ' + rootDbTable+'_row->n_'+dbIdx['OvsColumn']+'; i++) {\n'
                                        tableOvsdbGetString += 'if('+keyValue+' == '+rootDbTable+'_row->key_'+dbIdx['OvsColumn']+'[i]) {\n'
                                        tableOvsdbGetString += '*'+idx['name']+'_val_ptr = ('+self.ctypeClasses[idxType]+')'+rootDbTable+'_row->value_'+dbIdx['OvsColumn']+'[i];\n'
                                        tableOvsdbGetString += '}\n'
                                        tableOvsdbGetString += '}\n'
                                else:
                                    tableOvsdbGetString += 'char *temp = (char*)'
                                    tableOvsdbGetString += 'smap_get(&' + rootDbTable + '_row->' + dbIdx['OvsColumn'] + ', "' + dbIdx['Type']['Key'] + '");\n'
                                    tableOvsdbGetString += 'if(temp == NULL) {\n'
                                    tableOvsdbGetString += '*' + idx['name'] + '_val_ptr = 0;\n'
                                    tableOvsdbGetString += '}\n'
                                    tableOvsdbGetString += 'else {\n'
                                    tableOvsdbGetString += '*' + idx['name'] + '_val_ptr = (' + self.ctypeClasses[idxType] + ')atoi(temp);\n'
                                    tableOvsdbGetString += '}\n'
                            else:
                                tableOvsdbGetString += '*' + idx['name'] + '_val_ptr = (' + self.ctypeClasses[idxType] + ')*('
                                tableOvsdbGetString += rootDbTable + '_row->' + dbIdx['OvsColumn'] + ');\n'
                    tableOvsdbGetString += '}\n\n'
                    self.generatedSymbols[idx['name']] = 1
            tableOvsdbGetString += '\n'
            for col in self.tableRows[self.tables[tableName]['row']]['columns']:
                if col['name'] in [idx['name'] for idx in indexes] or col['name'] in self.generatedSymbols:
                    continue
                dbCol = self.jsonData[tableName]['Columns'][col['name']]
                colTable = dbCol['OvsTable']
                colType = self.getObjTypeString(col)
                if not colTable:
                    tableOvsdbGetString += 'void ovsdb_get_' + col['name'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, '
                    if colType == 'OctetString':
                        tableOvsdbGetString += 'char *' + col['name'] + '_val_ptr, size_t* ' + col['name'] + '_val_ptr_len) {\n'
                        if dbCol['CustomFunction']:
                            tableOvsdbGetString += dbCol['CustomFunction'] + '(idl, ' + rootDbTable + '_row, ' + col['name'] + '_val_ptr, ' + col['name'] + '_val_ptr_len);\n'
                            self.customFileHeaderString += 'void ' + dbCol['CustomFunction'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, char *' + col['name'] + '_val_ptr, size_t* ' + col['name'] + '_val_ptr_len);\n\n'
                        else:
                            tableOvsdbGetString += '*' + col['name'] + '_val_ptr = \'\\0\';\n'
                            tableOvsdbGetString += '*' + col['name'] + '_val_ptr_len = 0;\n'
                    elif colType == 'ObjectIdentifier':
                        tableOvsdbGetString += 'oid *' + col['name'] + '_val_ptr, size_t* ' + col['name'] + '_val_ptr_len) {\n'
                        if dbCol['CustomFunction']:
                            tableOvsdbGetString += dbCol['CustomFunction'] + '(idl, ' + rootDbTable + '_row, ' + col['name'] + '_val_ptr, ' + col['name'] + '_val_ptr_len);\n'
                            self.customFileHeaderString += 'void ' + dbCol['CustomFunction'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, oid *' + col['name'] + '_val_ptr, size_t* ' + col['name'] + '_val_ptr_len);\n\n'
                        else:
                            tableOvsdbGetString += '*' + col['name'] + '_val_ptr = (oid)NULL;\n'
                            tableOvsdbGetString += '*' + col['name'] + '_val_ptr_len = 0;\n'
                    else:
                        tableOvsdbGetString += self.ctypeClasses[colType] + ' *' + col['name'] + '_val_ptr) {\n'
                        if dbCol['CustomFunction']:
                            tableOvsdbGetString += dbCol['CustomFunction'] + '(idl, ' + rootDbTable + '_row, ' + col['name'] + '_val_ptr);\n'
                            self.customFileHeaderString += 'void ' + dbCol['CustomFunction'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, ' + self.ctypeClasses[colType] + ' *' + col['name'] + '_val_ptr);\n\n'
                        else:
                            tableOvsdbGetString += '*' + col['name'] + '_val_ptr = (' + self.ctypeClasses[colType] + ')NULL;\n'
                    tableOvsdbGetString += '\n'
                    tableOvsdbGetString += '}\n\n'
                    self.generatedSymbols[col['name']] = 1
                elif colTable != rootDbTable:
                    tableOvsdbGetString += 'void ovsdb_get_' + col['name'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, const struct ovsrec_' + colTable + ' *' + colTable + '_row, '
                    if colType == 'OctetString':
                        tableOvsdbGetString += 'char *' + col['name'] + '_val_ptr, size_t* ' + col['name'] + '_val_ptr_len) {\n'
                        if dbCol['CustomFunction']:
                            tableOvsdbGetString += dbCol['CustomFunction'] + '(idl, ' + rootDbTable + '_row, ' + colTable + '_row, ' + col['name'] + '_val_ptr, ' + col['name'] + '_val_ptr_len);\n'
                            self.customFileHeaderString += 'void ' + dbCol['CustomFunction'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, const struct ovsrec_' + colTable + ' *' + colTable + '_row, char *' + col['name'] + '_val_ptr, size_t* ' + col['name'] + '_val_ptr_len);\n\n'
                        else:
                            tableOvsdbGetString += 'char *temp = NULL;\n'
                            if dbCol['Type']['Key']:
                                if type(dbCol['Type']['Key']) == dict:
                                    keyType = dbCol['Type']['Key']['KeyType']
                                    keyValue = dbCol['Type']['Key']['KeyName']
                                    if keyType == 'str':
                                        tableOvsdbGetString += 'for (int i = 0; i < ' + colTable+'_row->n_'+dbCol['OvsColumn']+'; i++) {\n'
                                        tableOvsdbGetString += 'if(strcmp("'+keyValue+'", '+colTable+'_row->key_'+dbCol['OvsColumn']+'[i]) == 0) {\n'
                                        tableOvsdbGetString += 'temp = (char*)'+colTable+'_row->value_'+dbCol['OvsColumn']+'[i];\n'
                                        tableOvsdbGetString += '}\n'
                                        tableOvsdbGetString += '}\n'
                                    elif keyType == 'int':
                                        tableOvsdbGetString += 'for (int i = 0; i < ' + colTable+'_row->n_'+dbCol['OvsColumn']+'; i++) {\n'
                                        tableOvsdbGetString += 'if('+keyValue+' == '+colTable+'_row->key_'+dbCol['OvsColumn']+'[i]) {\n'
                                        tableOvsdbGetString += 'temp = (char*)'+colTable+'_row->value_'+dbCol['OvsColumn']+'[i];\n'
                                        tableOvsdbGetString += '}\n'
                                        tableOvsdbGetString += '}\n'
                                else:
                                    tableOvsdbGetString += 'temp = (char*)smap_get(&' + colTable + '_row->' + dbCol['OvsColumn'] + ', "' + dbCol['Type']['Key'] + '");\n'
                            else:
                                tableOvsdbGetString += 'temp = (char*)'+colTable + '_row->' + dbCol['OvsColumn'] + ';\n'
                            tableOvsdbGetString += '*' + col['name'] + '_val_ptr_len = temp != NULL ? strlen(temp) : 0;\n'
                            tableOvsdbGetString += 'memcpy(' + col['name'] + '_val_ptr' + ', temp, *' + col['name'] + '_val_ptr_len);\n'
                    elif colType == 'ObjectIdentifier':
                        tableOvsdbGetString += 'oid *' + col['name'] + '_val_ptr, size_t* ' + col['name'] + '_val_ptr_len) {\n'
                        if dbCol['CustomFunction']:
                            tableOvsdbGetString += dbCol['CustomFunction'] + '(idl, ' + rootDbTable + '_row, ' + colTable + '_row, ' + col['name'] + '_val_ptr, ' + col['name'] + '_val_ptr_len);\n'
                            self.customFileHeaderString += 'void ' + dbCol['CustomFunction'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, const struct ovsrec_' + colTable + ' *' + colTable + '_row, oid *' + col['name'] + '_val_ptr, size_t* ' + col['name'] + '_val_ptr_len);\n\n'
                        else:
                            tableOvsdbGetString += 'char *temp = NULL;\n'
                            if dbCol['Type']['Key']:
                                if type(dbCol['Type']['Key']) == dict:
                                    keyType = dbCol['Type']['Key']['KeyType']
                                    keyValue = dbCol['Type']['Key']['KeyName']
                                    if keyType == 'str':
                                        tableOvsdbGetString += 'for (int i = 0; i < ' + colTable+'_row->n_'+dbCol['OvsColumn']+'; i++) {\n'
                                        tableOvsdbGetString += 'if(strcmp("'+keyValue+'", '+colTable+'_row->key_'+dbCol['OvsColumn']+'[i]) == 0) {\n'
                                        tableOvsdbGetString += 'temp = (char*)'+colTable+'_row->value_'+dbCol['OvsColumn']+'[i];\n'
                                        tableOvsdbGetString += '}\n'
                                        tableOvsdbGetString += '}\n'
                                    elif keyType == 'int':
                                        tableOvsdbGetString += 'for (int i = 0; i < ' + colTable+'_row->n_'+dbCol['OvsColumn']+'; i++) {\n'
                                        tableOvsdbGetString += 'if('+keyValue+' == '+colTable+'_row->key_'+dbCol['OvsColumn']+'[i]) {\n'
                                        tableOvsdbGetString += 'temp = (char*)'+colTable+'_row->value_'+dbCol['OvsColumn']+'[i];\n'
                                        tableOvsdbGetString += '}\n'
                                        tableOvsdbGetString += '}\n'
                                else:
                                    tableOvsdbGetString += 'temp = (char*)smap_get(&' + colTable + '_row->' + dbCol['OvsColumn'] + ', "' + dbCol['Type']['Key'] + '");\n'
                            else:
                                tableOvsdbGetString += 'temp = (char*)'+colTable + '_row->' + dbCol['OvsColumn'] + ';\n'
                            tableOvsdbGetString += 'oid temp_oid[MAX_OID_LEN] = {0};\n'
                            tableOvsdbGetString += '*' + col['name'] + '_val_ptr_len = MAX_OID_LEN;\n'
                            tableOvsdbGetString += 'if (temp != NULL) {\n'
                            tableOvsdbGetString += 'snmp_parse_oid(temp, temp_oid, ' + col['name'] + '_val_ptr_len);\n'
                            tableOvsdbGetString += '}\n'
                            tableOvsdbGetString += 'memcpy(' + col['name'] + '_val_ptr, temp_oid, *' + col['name'] + '_val_ptr_len);\n'
                    else:
                        tableOvsdbGetString += self.ctypeClasses[colType] + ' *' + col['name'] + '_val_ptr) {\n'
                        if dbCol['CustomFunction']:
                            tableOvsdbGetString += dbCol['CustomFunction'] + '(idl, ' + rootDbTable + '_row, ' + colTable + '_row, ' + col['name'] + '_val_ptr);\n'
                            self.customFileHeaderString += 'void ' + dbCol['CustomFunction'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, const struct ovsrec_' + colTable + ' *' + colTable + '_row, ' + self.ctypeClasses[colType] + ' *' + col['name'] + '_val_ptr);\n\n'
                        else:
                            if dbCol['Type']['Key']:
                                if type(dbCol['Type']['Key']) == dict:
                                    keyType = dbCol['Type']['Key']['KeyType']
                                    keyValue = dbCol['Type']['Key']['KeyName']
                                    if keyType == 'str':
                                        tableOvsdbGetString += 'for (int i = 0; i < ' + colTable+'_row->n_'+dbCol['OvsColumn']+'; i++) {\n'
                                        tableOvsdbGetString += 'if(strcmp("'+keyValue+'", '+colTable+'_row->key_'+dbCol['OvsColumn']+'[i]) == 0) {\n'
                                        tableOvsdbGetString += '*' + col['name'] + '_val_ptr = (' + self.ctypeClasses[colType] + ')'+colTable+'_row->value_'+dbCol['OvsColumn']+'[i];\n'
                                        tableOvsdbGetString += '}\n'
                                        tableOvsdbGetString += '}\n'
                                    elif keyType == 'int':
                                        tableOvsdbGetString += 'for (int i = 0; i < ' + colTable+'_row->n_'+dbCol['OvsColumn']+'; i++) {\n'
                                        tableOvsdbGetString += 'if('+keyValue+' == '+colTable+'_row->key_'+dbCol['OvsColumn']+'[i]) {\n'
                                        tableOvsdbGetString += '*' + col['name'] + '_val_ptr = (' + self.ctypeClasses[colType] + ')'+colTable+'_row->value_'+dbCol['OvsColumn']+'[i];\n'
                                        tableOvsdbGetString += '}\n'
                                        tableOvsdbGetString += '}\n'
                                else:
                                    tableOvsdbGetString += 'char *temp = (char*)'
                                    tableOvsdbGetString += 'smap_get(&' + colTable + '_row->' + dbCol['OvsColumn'] + ', "' + dbCol['Type']['Key'] + '");\n'
                                    tableOvsdbGetString += 'if(temp == NULL) {\n'
                                    tableOvsdbGetString += '*' + col['name'] + '_val_ptr = 0;\n'
                                    tableOvsdbGetString += '}\n'
                                    tableOvsdbGetString += 'else {\n'
                                    tableOvsdbGetString += '*' + col['name'] + '_val_ptr = (' + self.ctypeClasses[colType] + ')atoi(temp);\n'
                                    tableOvsdbGetString += '}\n'
                            else:
                                tableOvsdbGetString += '*' + col['name'] + '_val_ptr = (' + self.ctypeClasses[colType] + ')*('
                                tableOvsdbGetString += colTable + '_row->' + dbCol['OvsColumn'] + ');\n'
                    tableOvsdbGetString += '}\n\n'
                    self.generatedSymbols[col['name']] = 1
                else:
                    tableOvsdbGetString += 'void ovsdb_get_' + col['name'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, '
                    if colType == 'OctetString':
                        tableOvsdbGetString += 'char *' + col['name'] + '_val_ptr, size_t* ' + col['name'] + '_val_ptr_len) {\n'
                        if dbCol['CustomFunction']:
                            tableOvsdbGetString += dbCol['CustomFunction'] + '(idl, ' + rootDbTable + '_row, ' + col['name'] + '_val_ptr, ' + col['name'] + '_val_ptr_len);\n'
                            self.customFileHeaderString += 'void ' + dbCol['CustomFunction'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, char *' + col['name'] + '_val_ptr, size_t* ' + col['name'] + '_val_ptr_len);\n\n'
                        else:
                            tableOvsdbGetString += 'char *temp = NULL;\n'
                            if dbCol['Type']['Key']:
                                if type(dbCol['Type']['Key']) == dict:
                                    keyType = dbCol['Type']['Key']['KeyType']
                                    keyValue = dbCol['Type']['Key']['KeyName']
                                    if keyType == 'str':
                                        tableOvsdbGetString += 'for (int i = 0; i < ' + rootDbTable+'_row->n_'+dbCol['OvsColumn']+'; i++) {\n'
                                        tableOvsdbGetString += 'if(strcmp("'+keyValue+'", '+rootDbTable+'_row->key_'+dbCol['OvsColumn']+'[i]) == 0) {\n'
                                        tableOvsdbGetString += 'temp = (char*)'+rootDbTable+'_row->value_'+dbCol['OvsColumn']+'[i];\n'
                                        tableOvsdbGetString += '}\n'
                                        tableOvsdbGetString += '}\n'
                                    elif keyType == 'int':
                                        tableOvsdbGetString += 'for (int i = 0; i < ' + rootDbTable+'_row->n_'+dbCol['OvsColumn']+'; i++) {\n'
                                        tableOvsdbGetString += 'if('+keyValue+' == '+rootDbTable+'_row->key_'+dbCol['OvsColumn']+'[i]) {\n'
                                        tableOvsdbGetString += 'temp = (char*)'+rootDbTable+'_row->value_'+dbCol['OvsColumn']+'[i];\n'
                                        tableOvsdbGetString += '}\n'
                                        tableOvsdbGetString += '}\n'
                                else:
                                    tableOvsdbGetString += 'temp = (char*)smap_get(&' + rootDbTable + '_row->' + dbCol['OvsColumn'] + ', "' + dbCol['Type']['Key'] + '");\n'
                            else:
                                tableOvsdbGetString += 'temp = (char*)'+rootDbTable + '_row->' + dbCol['OvsColumn'] + ';\n'
                            tableOvsdbGetString += '*' + col['name'] + '_val_ptr_len = temp != NULL ? strlen(temp) : 0;\n'
                            tableOvsdbGetString += 'memcpy(' + col['name'] + '_val_ptr' + ', temp, *' + col['name'] + '_val_ptr_len);\n'
                    elif colType == 'ObjectIdentifier':
                        tableOvsdbGetString += 'oid *' + col['name'] + '_val_ptr, size_t* ' + col['name'] + '_val_ptr_len) {\n'
                        if dbCol['CustomFunction']:
                            tableOvsdbGetString += dbCol['CustomFunction'] + '(idl, ' + rootDbTable + '_row, ' + col['name'] + '_val_ptr, ' + col['name'] + '_val_ptr_len);\n'
                            self.customFileHeaderString += 'void ' + dbCol['CustomFunction'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, oid *' + col['name'] + '_val_ptr, size_t* ' + col['name'] + '_val_ptr_len);\n\n'
                        else:
                            tableOvsdbGetString += 'char *temp = NULL;\n'
                            if dbCol['Type']['Key']:
                                if type(dbCol['Type']['Key']) == dict:
                                    keyType = dbCol['Type']['Key']['KeyType']
                                    keyValue = dbCol['Type']['Key']['KeyName']
                                    if keyType == 'str':
                                        tableOvsdbGetString += 'for (int i = 0; i < ' + rootDbTable+'_row->n_'+dbCol['OvsColumn']+'; i++) {\n'
                                        tableOvsdbGetString += 'if(strcmp("'+keyValue+'", '+rootDbTable+'_row->key_'+dbCol['OvsColumn']+'[i]) == 0) {\n'
                                        tableOvsdbGetString += 'temp = (char*)'+rootDbTable+'_row->value_'+dbCol['OvsColumn']+'[i];\n'
                                        tableOvsdbGetString += '}\n'
                                        tableOvsdbGetString += '}\n'
                                    elif keyType == 'int':
                                        tableOvsdbGetString += 'for (int i = 0; i < ' + rootDbTable+'_row->n_'+dbCol['OvsColumn']+'; i++) {\n'
                                        tableOvsdbGetString += 'if('+keyValue+' == '+rootDbTable+'_row->key_'+dbCol['OvsColumn']+'[i]) {\n'
                                        tableOvsdbGetString += 'temp = (char*)'+rootDbTable+'_row->value_'+dbCol['OvsColumn']+'[i];\n'
                                        tableOvsdbGetString += '}\n'
                                        tableOvsdbGetString += '}\n'
                                else:
                                    tableOvsdbGetString += 'temp = (char*)smap_get(&' + rootDbTable + '_row->' + dbCol['OvsColumn'] + ', "' + dbCol['Type']['Key'] + '");\n'
                            else:
                                tableOvsdbGetString += 'temp = (char*)' +rootDbTable + '_row->' + dbCol['OvsColumn'] + ';\n'
                            tableOvsdbGetString += 'oid temp_oid[MAX_OID_LEN] = {0};\n'
                            tableOvsdbGetString += '*' + col['name'] + '_val_ptr_len = MAX_OID_LEN;\n'
                            tableOvsdbGetString += 'if (temp != NULL) {\n'
                            tableOvsdbGetString += 'snmp_parse_oid(temp, temp_oid, ' + col['name'] + '_val_ptr_len);\n'
                            tableOvsdbGetString += '}\n'
                            tableOvsdbGetString += 'memcpy(' + col['name'] + '_val_ptr, temp_oid, *' + col['name'] + '_val_ptr_len);\n'
                    else:
                        tableOvsdbGetString += self.ctypeClasses[colType] + ' *' + col['name'] + '_val_ptr) {\n'
                        if dbCol['CustomFunction']:
                            tableOvsdbGetString += dbCol['CustomFunction'] + '(idl, ' + rootDbTable + '_row, ' + col['name'] + '_val_ptr);\n'
                            self.customFileHeaderString += 'void ' + dbCol['CustomFunction'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, ' + self.ctypeClasses[colType] + ' *' + col['name'] + '_val_ptr);\n\n'
                        else:
                            if dbCol['Type']['Key']:
                                if type(dbCol['Type']['Key']) == dict:
                                    keyType = dbCol['Type']['Key']['KeyType']
                                    keyValue = dbCol['Type']['Key']['KeyName']
                                    if keyType == 'str':
                                        tableOvsdbGetString += 'for (int i = 0; i < ' + rootDbTable+'_row->n_'+dbCol['OvsColumn']+'; i++) {\n'
                                        tableOvsdbGetString += 'if(strcmp("'+keyValue+'", '+rootDbTable+'_row->key_'+dbCol['OvsColumn']+'[i]) == 0) {\n'
                                        tableOvsdbGetString += '*'+col['name'] +'_val_ptr = ('+self.ctypeClasses[colType]+')'+rootDbTable+'_row->value_'+dbCol['OvsColumn']+'[i];\n'
                                        tableOvsdbGetString += '}\n'
                                        tableOvsdbGetString += '}\n'
                                    elif keyType == 'int':
                                        tableOvsdbGetString += 'for (int i = 0; i < ' + rootDbTable+'_row->n_'+dbCol['OvsColumn']+'; i++) {\n'
                                        tableOvsdbGetString += 'if('+keyValue+' == '+rootDbTable+'_row->key_'+dbCol['OvsColumn']+'[i]) {\n'
                                        tableOvsdbGetString += '*'+col['name'] +'_val_ptr = ('+self.ctypeClasses[colType]+')'+rootDbTable+'_row->value_'+dbCol['OvsColumn']+'[i];\n'
                                        tableOvsdbGetString += '}\n'
                                        tableOvsdbGetString += '}\n'
                                else:
                                    tableOvsdbGetString += 'char *temp = (char*)'
                                    tableOvsdbGetString += 'smap_get(&' + rootDbTable + '_row->' + dbCol['OvsColumn'] + ', "' + dbCol['Type']['Key'] + '");\n'
                                    tableOvsdbGetString += 'if(temp == NULL) {\n'
                                    tableOvsdbGetString += '*' + col['name'] + '_val_ptr = 0;\n'
                                    tableOvsdbGetString += '}\n'
                                    tableOvsdbGetString += 'else {\n'
                                    tableOvsdbGetString += '*' + col['name'] + '_val_ptr = (' + self.ctypeClasses[colType] + ')atoi(temp);\n'
                                    tableOvsdbGetString += '}\n'
                            else:
                                tableOvsdbGetString += '*' + col['name'] + '_val_ptr = (' + self.ctypeClasses[colType] + ')*('
                                tableOvsdbGetString += rootDbTable + '_row->' + dbCol['OvsColumn'] + ');\n'
                    tableOvsdbGetString += '}\n\n'
                    self.generatedSymbols[col['name']] = 1
                self.fileWrite(fileName=tableName + '_ovsdb_get.c',data=tableOvsdbGetString)

            tableOvsdbGetHeaderString = '#ifndef ' + tableName.upper() + '_OVSDB_GET_H\n'
            tableOvsdbGetHeaderString += '#define ' + tableName.upper() + '_OVSDB_GET_H\n\n'
            tableOvsdbGetHeaderString += """#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
"""
            tableOvsdbGetHeaderString += '#include "vswitch-idl.h"\n'
            tableOvsdbGetHeaderString += '#include "ovsdb-idl.h"\n\n'
            tableOvsdbGetHeaderString += 'void ' + tableName + '_ovsdb_idl_init(struct ovsdb_idl *idl);\n'
            for idx in indexes:
                dbIdx = self.jsonData[tableName]['Indexes'][idx['name']]
                idxTable = dbIdx['OvsTable']
                idxType = self.getObjTypeString(idx)
                if not idxTable:
                    tableOvsdbGetHeaderString += 'void ovsdb_get_' + idx['name'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, '
                    if idxType == 'OctetString':
                        tableOvsdbGetHeaderString += 'char *' + idx['name'] + '_val_ptr, size_t* ' + idx['name'] + '_val_ptr_len);\n'
                    elif idxType == 'ObjectIdentifier':
                        tableOvsdbGetHeaderString += 'oid *' + idx['name'] + '_val_ptr, size_t* ' + idx['name'] + '_val_ptr_len);\n'
                    else:
                        tableOvsdbGetHeaderString += self.ctypeClasses[idxType] + ' *' + idx['name'] + '_val_ptr);\n'
                elif idxTable != rootDbTable:
                    tableOvsdbGetHeaderString += 'void ovsdb_get_' + idx['name'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, const struct ovsrec_' + idxTable + ' *' + idxTable + '_row, '
                    if idxType == 'OctetString':
                        tableOvsdbGetHeaderString += 'char *' + idx['name'] + '_val_ptr, size_t* ' + idx['name'] + '_val_ptr_len);\n'
                    elif idxType == 'ObjectIdentifier':
                        tableOvsdbGetHeaderString += 'oid *' + idx['name'] + '_val_ptr, size_t* ' + idx['name'] + '_val_ptr_len);\n'
                    else:
                        tableOvsdbGetHeaderString += self.ctypeClasses[idxType] + ' *' + idx['name'] + '_val_ptr);\n'
                else:
                    tableOvsdbGetHeaderString += 'void ovsdb_get_' + idx['name'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, '
                    if idxType == 'OctetString':
                        tableOvsdbGetHeaderString += 'char *' + idx['name'] + '_val_ptr, size_t* ' + idx['name'] + '_val_ptr_len);\n'
                    elif idxType == 'ObjectIdentifier':
                        tableOvsdbGetHeaderString += 'oid *' + idx['name'] + '_val_ptr, size_t* ' + idx['name'] + '_val_ptr_len);\n'
                    else:
                        tableOvsdbGetHeaderString += self.ctypeClasses[idxType] + ' *' + idx['name'] + '_val_ptr);\n'
            tableOvsdbGetHeaderString += '\n'
            for col in self.tableRows[self.tables[tableName]['row']]['columns']:
                if col['name'] in [idx['name'] for idx in indexes]:
                    continue
                dbCol = self.jsonData[tableName]['Columns'][col['name']]
                colTable = dbCol['OvsTable']
                colType = self.getObjTypeString(col)
                if not colTable:
                    tableOvsdbGetHeaderString += 'void ovsdb_get_' + col['name'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, '
                    if colType == 'OctetString':
                        tableOvsdbGetHeaderString += 'char *' + col['name'] + '_val_ptr, size_t* ' + col['name'] + '_val_ptr_len);\n'
                    elif colType == 'ObjectIdentifier':
                        tableOvsdbGetHeaderString += 'oid *' + col['name'] + '_val_ptr, size_t* ' + col['name'] + '_val_ptr_len);\n'
                    else:
                        tableOvsdbGetHeaderString += self.ctypeClasses[colType] + ' *' + col['name'] + '_val_ptr);\n'
                elif colTable != rootDbTable:
                    tableOvsdbGetHeaderString += 'void ovsdb_get_' + col['name'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, const struct ovsrec_' + colTable + ' *' + colTable + '_row, '
                    if colType == 'OctetString':
                        tableOvsdbGetHeaderString += 'char *' + col['name'] + '_val_ptr, size_t* ' + col['name'] + '_val_ptr_len);\n'
                    elif colType == 'ObjectIdentifier':
                        tableOvsdbGetHeaderString += 'oid *' + col['name'] + '_val_ptr, size_t* ' + col['name'] + '_val_ptr_len);\n'
                    else:
                        tableOvsdbGetHeaderString += self.ctypeClasses[colType] + ' *' + col['name'] + '_val_ptr);\n'
                else:
                    tableOvsdbGetHeaderString += 'void ovsdb_get_' + col['name'] + '(struct ovsdb_idl *idl, const struct ovsrec_' + rootDbTable + ' *' + rootDbTable + '_row, '
                    if colType == 'OctetString':
                        tableOvsdbGetHeaderString += 'char *' + col['name'] + '_val_ptr, size_t* ' + col['name'] + '_val_ptr_len);\n'
                    elif colType == 'ObjectIdentifier':
                        tableOvsdbGetHeaderString += 'oid *' + col['name'] + '_val_ptr, size_t* ' + col['name'] + '_val_ptr_len);\n'
                    else:
                        tableOvsdbGetHeaderString += self.ctypeClasses[colType] + ' *' + col['name'] + '_val_ptr);\n'
            tableOvsdbGetHeaderString += '#endif'
            self.fileWrite(fileName=tableName + '_ovsdb_get.h',data=tableOvsdbGetHeaderString)

            tableEnumsHeaderString = '#ifndef ' + tableName.upper() + '_ENUMS_H\n'
            tableEnumsHeaderString += '#define ' + tableName.upper() + '_ENUMS_H\n\n'
            for idx in indexes:
                if idx['name'] in self.enumSymbols:
                    for x in self.enumSymbols[idx['name']]:
                        name, val = x
                        tableEnumsHeaderString += '#define D_' + idx['name'].upper() + '_' + name.upper() + ' ' + str(val) + '\n'
                    tableEnumsHeaderString += '\n'

            for col in self.tableRows[self.tables[tableName]['row']]['columns']:
                if col['name'] in self.enumSymbols:
                    for x in self.enumSymbols[col['name']]:
                        name, val = x
                        tableEnumsHeaderString += '#define D_' + col['name'].upper() + '_' + name.upper() + ' ' + str(val) + '\n'
                    tableEnumsHeaderString += '\n'

            tableEnumsHeaderString += '#endif\n\n'
            self.fileWrite(fileName=tableName + '_enums.h',data=tableEnumsHeaderString)

            tableInterfaceString = """#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/table_container.h>
#include <net-snmp/library/container.h>
"""
            tableInterfaceString += '#include "' + tableName + '.h"\n'
            tableInterfaceString += '#include "' + tableName + '_interface.h"\n\n'
            tableInterfaceString += 'netsnmp_feature_require(baby_steps)\n'
            tableInterfaceString += 'netsnmp_feature_require(row_merge)\n'
            tableInterfaceString += 'netsnmp_feature_require(check_all_requests_error)\n\n'
            tableInterfaceString += 'typedef struct ' + tableName + '_interface_ctx_s {\n'
            tableInterfaceString += 'netsnmp_container *container;\n'
            tableInterfaceString += 'netsnmp_cache *cache;\n'
            tableInterfaceString += tableName + '_registration *user_ctx;\n'
            tableInterfaceString += 'netsnmp_table_registration_info tbl_info;\n'
            tableInterfaceString += 'netsnmp_baby_steps_access_methods access_multiplexer;\n'
            tableInterfaceString += '} ' + tableName + '_interface_ctx;\n\n'
            tableInterfaceString += 'static ' + tableName + '_interface_ctx ' + tableName + '_if_ctx;\n'
            tableInterfaceString += 'static void _' + tableName + '_container_init(' + tableName + '_interface_ctx *if_ctx);\n'
            tableInterfaceString += 'static void _' + tableName + '_container_shutdown(' + tableName + '_interface_ctx *if_ctx);\n\n'
            tableInterfaceString += 'netsnmp_container *' + tableName + '_container_get(void) {\n'
            tableInterfaceString += 'return ' + tableName + '_if_ctx.container;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += tableName + '_registration *' + tableName + '_registration_get(void) {\n'
            tableInterfaceString += 'return ' + tableName + '_if_ctx.user_ctx;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += tableName + '_registration *' + tableName + '_registration_set(' + tableName + '_registration *newreg) {\n'
            tableInterfaceString += tableName + '_registration *old = ' + tableName + '_if_ctx.user_ctx;\n'
            tableInterfaceString += tableName + '_if_ctx.user_ctx = newreg;\n'
            tableInterfaceString += 'return old;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'int ' + tableName + '_container_size(void) {\n'
            tableInterfaceString += 'return CONTAINER_SIZE(' + tableName + '_if_ctx.container);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'static Netsnmp_Node_Handler _mfd_' + tableName + '_pre_request;\n'
            tableInterfaceString += 'static Netsnmp_Node_Handler _mfd_' + tableName + '_post_request;\n'
            tableInterfaceString += 'static Netsnmp_Node_Handler _mfd_' + tableName + '_object_lookup;\n'
            tableInterfaceString += 'static Netsnmp_Node_Handler _mfd_' + tableName + '_get_values;\n\n'
            tableInterfaceString += 'void _' + tableName + '_initialize_interface(' + tableName + '_registration *reg_ptr, u_long flags) {\n'
            tableInterfaceString += 'netsnmp_baby_steps_access_methods *access_multiplexer = &' + tableName + '_if_ctx.access_multiplexer;\n'
            tableInterfaceString += 'netsnmp_table_registration_info *tbl_info = &' + tableName + '_if_ctx.tbl_info;\n'
            tableInterfaceString += 'netsnmp_handler_registration *reginfo;\n'
            tableInterfaceString += 'netsnmp_mib_handler *handler;\n'
            tableInterfaceString += 'int mfd_modes = 0;\n\n'
            tableInterfaceString += 'DEBUGMSGTL(("internal:' + tableName + ':_' + tableName + '_initialize_interface","called\\n"));\n\n'
            tableInterfaceString += 'netsnmp_table_helper_add_indexes(tbl_info'
            for idx in indexes:
                tableInterfaceString += ', ' + self.netsnmpTypes[self.getObjTypeString(idx)]
            tableInterfaceString += ', 0);\n\n'
            tableInterfaceString += 'tbl_info->min_column = ' + tableName.upper() + '_MIN_COL;\n'
            tableInterfaceString += 'tbl_info->max_column = ' + tableName.upper() + '_MAX_COL;\n'
            tableInterfaceString += tableName + '_if_ctx.user_ctx = reg_ptr;\n'
            tableInterfaceString += tableName + '_init_data(reg_ptr);\n'
            tableInterfaceString += '_' + tableName + '_container_init(&' + tableName + '_if_ctx);\n'
            tableInterfaceString += 'if ( NULL == ' + tableName + '_if_ctx.container) {\n'
            tableInterfaceString += 'snmp_log(LOG_ERR, "could not initialize container for ' + tableName + '\\n");\n'
            tableInterfaceString += 'return;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'access_multiplexer->object_lookup = _mfd_' + tableName + '_object_lookup;\n'
            tableInterfaceString += 'access_multiplexer->get_values = _mfd_' + tableName + '_get_values;\n\n'
            tableInterfaceString += 'access_multiplexer->pre_request = _mfd_' + tableName + '_pre_request;\n'
            tableInterfaceString += 'access_multiplexer->post_request = _mfd_' + tableName + '_post_request;\n\n'
            tableInterfaceString += 'DEBUGMSGTL(("' + tableName + ':init_' + tableName + '","Registering ' + tableName + ' as a mibs-for-dummies table.\\n"));\n\n'
            tableInterfaceString += 'handler = netsnmp_baby_steps_access_multiplexer_get(access_multiplexer);\n'
            tableInterfaceString += 'reginfo = netsnmp_handler_registration_create("' + tableName + '", handler, ' + tableName + '_oid, ' + tableName + '_oid_size, HANDLER_CAN_BABY_STEP | HANDLER_CAN_RONLY);\n\n'
            tableInterfaceString += 'if (NULL == reginfo) {\n'
            tableInterfaceString += 'snmp_log(LOG_ERR, "error registering table ' + tableName + '\\n");\n'
            tableInterfaceString += 'return;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'reginfo->my_reg_void = &' + tableName + '_if_ctx;\n\n'
            tableInterfaceString += 'if (access_multiplexer->object_lookup)\n'
            tableInterfaceString += 'mfd_modes |= BABY_STEP_OBJECT_LOOKUP;\n'
            tableInterfaceString += 'if (access_multiplexer->pre_request)\n'
            tableInterfaceString += 'mfd_modes |= BABY_STEP_PRE_REQUEST;\n'
            tableInterfaceString += 'if (access_multiplexer->post_request)\n'
            tableInterfaceString += 'mfd_modes |= BABY_STEP_POST_REQUEST;\n\n'
            #tableInterfaceString += 'if (access_multiplexer->set_values)\n'
            #tableInterfaceString += 'mfd_modes |= BABY_STEP_SET_VALUES;\n'
            #tableInterfaceString += 'if
            #(access_multiplexer->irreversible_commit)\n'
            #tableInterfaceString += 'mfd_modes |=
            #BABY_STEP_IRREVERSIBLE_COMMIT;\n'
            #tableInterfaceString += 'if
            #(access_multiplexer->object_syntax_checks)\n'
            #tableInterfaceString += 'mfd_modes |= BABY_STEP_CHECK_OBJECT;\n'
            #tableInterfaceString += 'if (access_multiplexer->undo_setup)\n'
            #tableInterfaceString += 'mfd_modes |= BABY_STEP_UNDO_SETUP;\n'
            #tableInterfaceString += 'if (access_multiplexer->undo_cleanup)\n'
            #tableInterfaceString += 'mfd_modes |= BABY_STEP_UNDO_CLEANUP;\n'
            #tableInterfaceString += 'if (access_multiplexer->undo_sets)\n'
            #tableInterfaceString += 'mfd_modes |= BABY_STEP_UNDO_SETS;\n'
            #tableInterfaceString += 'if(access_multiplexer->row_creation)\n'
            #tableInterfaceString += 'mfd_modes |= BABY_STEP_ROW_CREATE;\n'
            #tableInterfaceString +=
            #'if(access_multiplexer->consistency_checks)\n'
            #tableInterfaceString += 'mfd_modes |=
            #BABY_STEP_CHECK_CONSISTENCY;\n'
            #tableInterfaceString += 'if(access_multiplexer->commit)\n'
            #tableInterfaceString += 'mfd_modes |= BABY_STEP_COMMIT;\n'
            #tableInterfaceString += 'if(access_multiplexer->undo_commit)\n'
            #tableInterfaceString += 'mfd_modes |= BABY_STEP_UNDO_COMMIT;\n\n'
            tableInterfaceString += 'handler = netsnmp_baby_steps_handler_get(mfd_modes);\n'
            tableInterfaceString += 'netsnmp_inject_handler(reginfo, handler);\n\n'
            tableInterfaceString += 'handler = netsnmp_get_row_merge_handler(reginfo->rootoid_len + 2);\n'
            tableInterfaceString += 'netsnmp_inject_handler(reginfo, handler);\n\n'
            tableInterfaceString += 'handler = netsnmp_container_table_handler_get(tbl_info, ' + tableName + '_if_ctx.container, TABLE_CONTAINER_KEY_NETSNMP_INDEX);\n'
            tableInterfaceString += 'netsnmp_inject_handler(reginfo, handler);\n\n'
            tableInterfaceString += 'if(NULL != ' + tableName + '_if_ctx.cache) {\n'
            tableInterfaceString += 'handler = netsnmp_cache_handler_get(' + tableName + '_if_ctx.cache);\n'
            tableInterfaceString += 'netsnmp_inject_handler(reginfo, handler);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'netsnmp_register_table(reginfo, tbl_info);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'void _' + tableName + '_shutdown_interface(' + tableName + '_registration *reg_ptr) {\n'
            tableInterfaceString += '_' + tableName + '_container_shutdown(&' + tableName + '_if_ctx);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'void ' + tableName + '_valid_columns_set(netsnmp_column_info *vc) {\n'
            tableInterfaceString += tableName + '_if_ctx.tbl_info.valid_columns = vc;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'int ' + tableName + '_index_to_oid(netsnmp_index *oid_idx, ' + tableName + '_mib_index *mib_idx) {\n'
            tableInterfaceString += 'int err = SNMP_ERR_NOERROR;\n'
            for idx in indexes:
                tableInterfaceString += 'netsnmp_variable_list var_' + idx['name'] + ';\n'
            tableInterfaceString += '\n'
            for index, idx in enumerate(indexes):
                tableInterfaceString += 'memset( &var_' + idx['name'] + ', 0x00, sizeof(var_' + idx['name'] + '));\n'
                tableInterfaceString += 'var_' + idx['name'] + '.type = ' + self.netsnmpTypes[self.getObjTypeString(idx)] + ';\n'
                if index is not len(indexes) - 1:
                    tableInterfaceString += 'var_' + idx['name'] + '.next_variable = &var_' + indexes[index + 1]['name'] + ';\n\n'
                else:
                    tableInterfaceString += 'var_' + idx['name'] + '.next_variable = NULL;\n\n'
            tableInterfaceString += 'DEBUGMSGTL(("verbose:' + tableName + ':' + tableName + '_index_to_oid","called\\n"));\n\n'
            for idx in indexes:
                idxType = self.getObjTypeString(idx)
                if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
                    tableInterfaceString += 'snmp_set_var_value(&var_' + idx['name'] + ',&mib_idx->' + idx['name'] + ',mib_idx->' + idx['name'] + '_len * sizeof(mib_idx->' + idx['name'] + '[0]));\n'
                else:
                    tableInterfaceString += 'snmp_set_var_value(&var_' + idx['name'] + ', &mib_idx->' + idx['name'] + ', sizeof(mib_idx->' + idx['name'] + '));\n'
            tableInterfaceString += 'err = build_oid_noalloc(oid_idx->oids, oid_idx->len, &oid_idx->len, NULL, 0, &var_' + indexes[0]['name'] + ');\n'
            tableInterfaceString += 'if(err) {\n'
            tableInterfaceString += 'snmp_log(LOG_ERR, "error %d converting index to oid\\n",err);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'snmp_reset_var_buffers(&var_' + indexes[0]['name'] + ');\n'
            tableInterfaceString += 'return err;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'int ' + tableName + '_index_from_oid(netsnmp_index *oid_idx, ' + tableName + '_mib_index *mib_idx) {\n'
            tableInterfaceString += 'int err = SNMP_ERR_NOERROR;\n'
            for idx in indexes:
                tableInterfaceString += 'netsnmp_variable_list var_' + idx['name'] + ';\n'
            tableInterfaceString += '\n'
            for index, idx in enumerate(indexes):
                tableInterfaceString += 'memset(&var_' + idx['name'] + ', 0x00, sizeof(var_' + idx['name'] + '));\n'
                tableInterfaceString += 'var_' + idx['name'] + '.type = ' + self.netsnmpTypes[self.getObjTypeString(idx)] + ';\n'
                if index is not len(indexes) - 1:
                    tableInterfaceString += 'var_' + idx['name'] + '.next_variable = &var_' + indexes[index + 1]['name'] + ';\n\n'
                else:
                    tableInterfaceString += 'var_' + idx['name'] + '.next_variable = NULL;\n\n'
            tableInterfaceString += 'DEBUGMSGTL(("verbose:' + tableName + ':' + tableName + '_index_from_oid","called\\n"));\n\n'
            tableInterfaceString += 'err = parse_oid_indexes( oid_idx->oids, oid_idx->len, &var_' + indexes[0]['name'] + ');\n'
            tableInterfaceString += 'if (err == SNMP_ERR_NOERROR) {\n'
            for idx in indexes:
                idxType = self.getObjTypeString(idx)
                if idxType == 'OctetString' or idxType == 'ObjectIdentifier':
                    tableInterfaceString += 'if (var_' + idx['name'] + '.val_len > sizeof(mib_idx->' + idx['name'] + ')) {\n'
                    tableInterfaceString += 'err = SNMP_ERR_GENERR;\n'
                    tableInterfaceString += '}\n'
                    tableInterfaceString += 'else {\n'
                    tableInterfaceString += 'memcpy(mib_idx->' + idx['name'] + ', var_' + idx['name'] + '.val.string, var_' + idx['name'] + '.val_len);\n'
                    tableInterfaceString += 'mib_idx->' + idx['name'] + '_len = var_' + idx['name'] + '.val_len/ sizeof(mib_idx->' + idx['name'] + '[0]);\n'
                    tableInterfaceString += '}\n'
                else:
                    tableInterfaceString += 'mib_idx->' + idx['name'] + ' = *((' + self.ctypeClasses[self.getObjTypeString(idx)] + '*)var_' + idx['name'] + '.val.string);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'snmp_reset_var_buffers(&var_' + indexes[0]['name'] + ');\n'
            tableInterfaceString += 'return err;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += tableName + '_rowreq_ctx *' + tableName + '_allocate_rowreq_ctx(void *user_init_ctx) {\n'
            tableInterfaceString += tableName + '_rowreq_ctx *rowreq_ctx = SNMP_MALLOC_TYPEDEF(' + tableName + '_rowreq_ctx);\n\n'
            tableInterfaceString += 'DEBUGMSGTL(("internal:' + tableName + ':' + tableName + '_allocate_rowreq_ctx","called\\n"));\n\n'
            tableInterfaceString += 'if(NULL == rowreq_ctx) {\n'
            tableInterfaceString += 'snmp_log(LOG_ERR, "Could not allocate memory for a ' + tableName + '_rowreq_ctx.\\n" );\n'
            tableInterfaceString += 'return NULL;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'rowreq_ctx->oid_idx.oids = rowreq_ctx->oid_tmp;\n'
            tableInterfaceString += 'rowreq_ctx->' + tableName + '_data_list = NULL;\n'
            tableInterfaceString += 'if(!(rowreq_ctx->rowreq_flags & MFD_ROW_DATA_FROM_USER)) {\n'
            tableInterfaceString += 'if(SNMPERR_SUCCESS != ' + tableName + '_rowreq_ctx_init(rowreq_ctx, user_init_ctx)) {\n'
            tableInterfaceString += tableName + '_release_rowreq_ctx(rowreq_ctx);\n'
            tableInterfaceString += 'rowreq_ctx = NULL;\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += 'return rowreq_ctx;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'void ' + tableName + '_release_rowreq_ctx(' + tableName + '_rowreq_ctx *rowreq_ctx) {\n'
            tableInterfaceString += 'DEBUGMSGTL(("internal:' + tableName + ':' + tableName + '_release_rowreq_ctx","called\\n"));\n\n'
            tableInterfaceString += 'netsnmp_assert(NULL != rowreq_ctx);\n\n'
            tableInterfaceString += tableName + '_rowreq_ctx_cleanup(rowreq_ctx);\n'
            tableInterfaceString += 'if (rowreq_ctx->oid_idx.oids != rowreq_ctx->oid_tmp) {\n'
            tableInterfaceString += 'free(rowreq_ctx->oid_idx.oids);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'SNMP_FREE(rowreq_ctx);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'static int _mfd_' + tableName + '_pre_request(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *agtreq_info, netsnmp_request_info *requests) {\n'
            tableInterfaceString += 'int rc;\n'
            tableInterfaceString += 'DEBUGMSGTL(("internal:' + tableName + ':_mfd_' + tableName + '_pre_request","called\\n"));\n\n'
            tableInterfaceString += 'if (1 != netsnmp_row_merge_status_first(reginfo, agtreq_info)) {\n'
            tableInterfaceString += 'DEBUGMSGTL(("internal:' + tableName + '","skipping additional pre_request\\n"));\n'
            tableInterfaceString += 'return SNMP_ERR_NOERROR;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'rc = ' + tableName + '_pre_request(' + tableName + '_if_ctx.user_ctx);\n'
            tableInterfaceString += 'if(MFD_SUCCESS != rc) {\n'
            tableInterfaceString += 'DEBUGMSGTL(("' + tableName + '","error %d from ' + tableName + '_pre_requests\\n",rc));\n'
            tableInterfaceString += 'netsnmp_request_set_error_all(requests, SNMP_VALIDATE_ERR(rc));\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'return SNMP_ERR_NOERROR;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'static int _mfd_' + tableName + '_post_request(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *agtreq_info, netsnmp_request_info *requests) {\n'
            tableInterfaceString += tableName + '_rowreq_ctx *rowreq_ctx = (' + tableName + '_rowreq_ctx *)netsnmp_container_table_row_extract(requests);\n'
            tableInterfaceString += 'int rc, packet_rc;\n'
            tableInterfaceString += 'DEBUGMSGTL(("internal:' + tableName + ':_mfd_' + tableName + '_post_request","called\\n"));\n\n'
            tableInterfaceString += 'if(rowreq_ctx && (rowreq_ctx->rowreq_flags & MFD_ROW_DELETED)) {\n'
            tableInterfaceString += tableName + '_release_rowreq_ctx(rowreq_ctx);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'if (1 != netsnmp_row_merge_status_last(reginfo, agtreq_info)) {\n'
            tableInterfaceString += 'DEBUGMSGTL(("internal:' + tableName + '","waiting for last post_request\\n"));\n'
            tableInterfaceString += 'return SNMP_ERR_NOERROR;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'packet_rc = netsnmp_check_all_requests_error(agtreq_info->asp, 0);\n'
            tableInterfaceString += 'rc = ' + tableName + '_post_request(' + tableName + '_if_ctx.user_ctx, packet_rc);\n'
            tableInterfaceString += 'if(MFD_SUCCESS != rc) {\n'
            tableInterfaceString += 'DEBUGMSGTL(("' + tableName + '","error %d from ' + tableName + '_post_request\\n",rc));\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += 'return SNMP_ERR_NOERROR;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'static int _mfd_' + tableName + '_object_lookup(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *agtreq_info, netsnmp_request_info *requests) {\n'
            tableInterfaceString += 'int rc = SNMP_ERR_NOERROR;\n'
            tableInterfaceString += tableName + '_rowreq_ctx *rowreq_ctx = (' + tableName + '_rowreq_ctx*)netsnmp_container_table_row_extract(requests);\n\n'
            tableInterfaceString += 'DEBUGMSGTL(("internal:' + tableName + ':_mfd_' + tableName + '_object_lookup","called\\n"));\n\n'
            tableInterfaceString += 'if(NULL == rowreq_ctx) {\n'
            tableInterfaceString += 'rc = SNMP_ERR_NOCREATION;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'if(MFD_SUCCESS != rc) {\n'
            tableInterfaceString += 'netsnmp_request_set_error_all(requests, rc);\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += 'else {\n'
            tableInterfaceString += tableName + '_row_prep(rowreq_ctx);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'return SNMP_VALIDATE_ERR(rc);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'NETSNMP_STATIC_INLINE int _' + tableName + '_get_column(' + tableName + '_rowreq_ctx *rowreq_ctx, netsnmp_variable_list *var, int column) {\n'
            tableInterfaceString += 'int rc = SNMPERR_SUCCESS;\n\n'
            tableInterfaceString += 'DEBUGMSGTL(("internal:' + tableName + ':_mfd_' + tableName + '_get_column","called for %d\\n",column));\n\n'
            tableInterfaceString += 'netsnmp_assert(NULL != rowreq_ctx);\n\n'
            tableInterfaceString += 'switch(column) {\n'
            for idx in indexes:
                if idx['maxaccess'] == 'notaccessible':
                    continue
                tableInterfaceString += 'case COLUMN_' + idx['name'].upper() + ':{\n'
                idxType = self.getObjTypeString(idx)
                if idxType == 'Bits':
                    tableInterfaceString += 'u_long mask = (u_long)0xff << ((sizeof(char)-1)*8);\n'
                    tableInterfaceString += 'int idx = 0;\n'
                    tableInterfaceString += 'var->type =  ASN_OCTET_STR;\n'
                    tableInterfaceString += 'rc = ' + idx['name'] + '_get(rowreq_ctx, (u_long *)var->val.string);\n'
                    tableInterfaceString += 'var->val_len = 0;\n'
                    tableInterfaceString += 'while( 0 != mask) {\n'
                    tableInterfaceString += '++idx;\n'
                    tableInterfaceString += 'if(*((u_long*)var->val.string)&mask)\n'
                    tableInterfaceString += 'var->val_len = idx;\n'
                    tableInterfaceString += 'mask = mask >> 8;\n'
                    tableInterfaceString += '}\n'
                    tableInterfaceString += '}\n'
                elif idxType == 'OctetString':
                    tableInterfaceString += 'var->type = ' + self.netsnmpTypes[self.getObjTypeString(idx)] + ';\n'
                    tableInterfaceString += 'rc = ' + idx['name'] + '_get(rowreq_ctx, (char **)&var->val.string, &var->val_len);\n'
                    tableInterfaceString += '}\n'
                elif idxType == 'ObjectIdentifier':
                    tableInterfaceString += 'var->type = ' + self.netsnmpTypes[self.getObjTypeString(idx)] + ';\n'
                    tableInterfaceString += 'rc = ' + idx['name'] + '_get(rowreq_ctx, (oid **)&var->val.string, &var->val_len);\n'
                    tableInterfaceString += '}\n'
                else:
                    tableInterfaceString += 'var->type = ' + self.netsnmpTypes[self.getObjTypeString(idx)] + ';\n'
                    tableInterfaceString += 'var->val_len = sizeof(' + self.ctypeClasses[idxType] + ');\n'
                    tableInterfaceString += 'rc = ' + idx['name'] + '_get(rowreq_ctx, (' + self.ctypeClasses[idxType] + '*)var->val.string);\n'
                    tableInterfaceString += '}\n'
                tableInterfaceString += 'break;\n'
            for col in self.tableRows[self.tables[tableName]['row']]['columns']:
                if col['name'] in self.tableRows[self.tables[tableName]['row']]['index'] or col['maxaccess'] == 'notaccessible':
                    continue
                tableInterfaceString += 'case COLUMN_' + col['name'].upper() + ':{\n'
                colType = self.getObjTypeString(col)
                if colType == 'Bits':
                    tableInterfaceString += 'u_long mask = (u_long)0xff << ((sizeof(char)-1)*8);\n'
                    tableInterfaceString += 'int idx = 0;\n'
                    tableInterfaceString += 'var->type =  ASN_OCTET_STR;\n'
                    tableInterfaceString += 'rc = ' + col['name'] + '_get(rowreq_ctx, (u_long *)var->val.string);\n'
                    tableInterfaceString += 'var->val_len = 0;\n'
                    tableInterfaceString += 'while( 0 != mask) {\n'
                    tableInterfaceString += '++idx;\n'
                    tableInterfaceString += 'if(*((u_long*)var->val.string)&mask)\n'
                    tableInterfaceString += 'var->val_len = idx;\n'
                    tableInterfaceString += 'mask = mask >> 8;\n'
                    tableInterfaceString += '}\n'
                    tableInterfaceString += '}\n'
                elif colType == 'OctetString':
                    tableInterfaceString += 'var->type = ' + self.netsnmpTypes[self.getObjTypeString(col)] + ';\n'
                    tableInterfaceString += 'rc = ' + col['name'] + '_get(rowreq_ctx, (char **)&var->val.string, &var->val_len);\n'
                    tableInterfaceString += '}\n'
                elif colType == 'ObjectIdentifier':
                    tableInterfaceString += 'var->type = ' + self.netsnmpTypes[self.getObjTypeString(col)] + ';\n'
                    tableInterfaceString += 'rc = ' + col['name'] + '_get(rowreq_ctx, (oid **)&var->val.string, &var->val_len);\n'
                    tableInterfaceString += '}\n'
                else:
                    tableInterfaceString += 'var->type = ' + self.netsnmpTypes[self.getObjTypeString(col)] + ';\n'
                    tableInterfaceString += 'var->val_len = sizeof(' + self.ctypeClasses[colType] + ');\n'
                    tableInterfaceString += 'rc = ' + col['name'] + '_get(rowreq_ctx, (' + self.ctypeClasses[colType] + '*)var->val.string);\n'
                    tableInterfaceString += '}\n'
                tableInterfaceString += 'break;\n'
            tableInterfaceString += 'default:\n'
            tableInterfaceString += 'if(' + tableName.upper() + '_MIN_COL <= column && column <= ' + tableName.upper() + '_MAX_COL) {\n'
            tableInterfaceString += 'DEBUGMSGTL(("internal:' + tableName + ':_mfd_' + tableName + '_get_column","assume column %d is reserved\\n",column));\n'
            tableInterfaceString  += 'rc = MFD_SKIP;\n'
            tableInterfaceString += '} else {\n'
            tableInterfaceString += 'snmp_log(LOG_ERR, "unknown column %d in _' + tableName + '_get_column\\n",column);\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += 'break;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'return rc;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'int _mfd_' + tableName + '_get_values(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *agtreq_info, netsnmp_request_info *requests) {\n'
            tableInterfaceString += tableName + '_rowreq_ctx *rowreq_ctx = (' + tableName + '_rowreq_ctx*)netsnmp_container_table_row_extract(requests);\n'
            tableInterfaceString += 'netsnmp_table_request_info *tri;\n'
            tableInterfaceString += 'u_char *old_string;\n'
            tableInterfaceString += 'void (*dataFreeHook)(void*);\n'
            tableInterfaceString += 'int rc;\n\n'
            tableInterfaceString += 'DEBUGMSGTL(("internal:' + tableName + ':_mfd_' + tableName + '_get_values","called\\n"));\n\n'
            tableInterfaceString += 'netsnmp_assert(NULL != rowreq_ctx);\n\n'
            tableInterfaceString += 'for(;requests;requests = requests->next) {\n'
            tableInterfaceString += 'old_string = requests->requestvb->val.string;\n'
            tableInterfaceString += 'dataFreeHook = requests->requestvb->dataFreeHook;\n'
            tableInterfaceString += 'if (NULL == requests->requestvb->val.string) {\n'
            tableInterfaceString += 'requests->requestvb->val.string =requests->requestvb->buf;\n'
            tableInterfaceString += 'requests->requestvb->val_len = sizeof(requests->requestvb->buf);\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += 'else if (requests->requestvb->buf == requests->requestvb->val.string) {\n'
            tableInterfaceString += 'if(requests->requestvb->val_len != sizeof(requests->requestvb->buf)){\n'
            tableInterfaceString += 'requests->requestvb->val_len = sizeof(requests->requestvb->buf);\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'tri = netsnmp_extract_table_info(requests);\n'
            tableInterfaceString += 'if(NULL == tri) {\n'
            tableInterfaceString += 'continue;\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += 'rc = _' + tableName + '_get_column(rowreq_ctx, requests->requestvb, tri->colnum);\n'
            tableInterfaceString += 'if(rc) {\n'
            tableInterfaceString += 'if(MFD_SKIP == rc) {\n'
            tableInterfaceString += 'requests->requestvb->type = SNMP_NOSUCHINSTANCE;\n'
            tableInterfaceString += 'rc = SNMP_ERR_NOERROR;\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += 'else if (NULL == requests->requestvb->val.string) {\n'
            tableInterfaceString += 'snmp_log(LOG_ERR, "NULL varbind data pointer!\\n");\n'
            tableInterfaceString += 'rc = SNMP_ERR_GENERR;\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += 'if(rc) {\n'
            tableInterfaceString += 'netsnmp_request_set_error(requests, SNMP_VALIDATE_ERR(rc));\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'if(old_string && (old_string != requests->requestvb->buf) && (requests->requestvb->val.string != old_string )) {\n'
            tableInterfaceString += 'if(dataFreeHook) {\n'
            tableInterfaceString += '(*dataFreeHook)(old_string);\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += 'else {\n'
            tableInterfaceString += 'free(old_string);\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'return SNMP_ERR_NOERROR;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'static void _container_free(netsnmp_container *container);\n\n'
            tableInterfaceString += 'static int _cache_load(netsnmp_cache *cache, void *vmagic) {\n'
            tableInterfaceString += 'DEBUGMSGTL(("internal:' + tableName + ':_cache_load","called\\n"));\n\n'
            tableInterfaceString += 'if((NULL == cache) || (NULL == cache->magic)) {\n'
            tableInterfaceString += 'snmp_log(LOG_ERR, "invalid cache for ' + tableName + '_cache_load\\n");\n'
            tableInterfaceString += 'return -1;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'netsnmp_assert((0 == cache->valid) || (1 == cache->expired));\n\n'
            tableInterfaceString += 'return ' + tableName + '_container_load((netsnmp_container*)cache->magic);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'static void _cache_free(netsnmp_cache *cache, void *magic) {\n'
            tableInterfaceString += 'netsnmp_container *container;\n'
            tableInterfaceString += 'DEBUGMSGTL(("internal:' + tableName + ':_cache_free","called\\n"));\n\n'
            tableInterfaceString += 'if((NULL == cache) || (NULL == cache->magic)) {\n'
            tableInterfaceString += 'snmp_log(LOG_ERR,"invalid cache in ' + tableName + '_cache_free\\n");\n'
            tableInterfaceString += 'return;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'container = (netsnmp_container*)cache->magic;\n'
            tableInterfaceString += '_container_free(container);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'static void _container_item_free(' + tableName + '_rowreq_ctx *rowreq_ctx, void *context) {\n'
            tableInterfaceString += 'DEBUGMSGTL(("internal:' + tableName + ':_container_item_free","called\\n"));\n\n'
            tableInterfaceString += 'if(NULL == rowreq_ctx) {\n'
            tableInterfaceString += 'return ;\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += tableName + '_release_rowreq_ctx(rowreq_ctx);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'static void _container_free(netsnmp_container *container) {\n'
            tableInterfaceString += 'DEBUGMSGTL(("internal:' + tableName + ':_container_free","called\\n"));\n\n'
            tableInterfaceString += 'if(NULL == container) {\n'
            tableInterfaceString += 'snmp_log(LOG_ERR, "invalid container in ' + tableName + '_container_free\\n");\n'
            tableInterfaceString += 'return ;\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += tableName + '_container_free(container);\n'
            tableInterfaceString += 'CONTAINER_CLEAR(container, (netsnmp_container_obj_func *)_container_item_free, NULL);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'void _' + tableName + '_container_init(' + tableName + '_interface_ctx *if_ctx) {\n'
            tableInterfaceString += 'DEBUGMSGTL(("internal:' + tableName + ':_' + tableName + '_container_init","called\\n"));\n\n'
            tableInterfaceString += 'if_ctx->cache = netsnmp_cache_create(30, _cache_load, _cache_free, ' + tableName + '_oid, ' + tableName + '_oid_size);\n\n'
            tableInterfaceString += 'if(NULL == if_ctx->cache) {\n'
            tableInterfaceString += 'snmp_log(LOG_ERR,"error creating cache for ' + tableName + '\\n");\n'
            tableInterfaceString += 'return;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'if_ctx->cache->flags = NETSNMP_CACHE_DONT_INVALIDATE_ON_SET;\n'
            tableInterfaceString += tableName + '_container_init(&if_ctx->container, if_ctx->cache);\n'
            tableInterfaceString += 'if(NULL == if_ctx->container) {\n'
            tableInterfaceString += 'if_ctx->container = netsnmp_container_find("' + tableName + ':table_container");\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += 'if(NULL == if_ctx->container) {\n'
            tableInterfaceString += 'snmp_log(LOG_ERR,"error creating container in ' + tableName + '_container_init\\n");\n'
            tableInterfaceString += 'return;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'if(NULL != if_ctx->cache) {\n'
            tableInterfaceString += 'if_ctx->cache->magic = (void*)if_ctx->container;\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'void _' + tableName + '_container_shutdown(' + tableName + '_interface_ctx *if_ctx) {\n'
            tableInterfaceString += 'DEBUGMSGTL(("internal:' + tableName + ':_' + tableName + '_container_shutdown","called\\n"));\n\n'
            tableInterfaceString += tableName + '_container_shutdown(if_ctx->container);\n'
            tableInterfaceString += '_container_free(if_ctx->container);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += tableName + '_rowreq_ctx *' + tableName + '_row_find_by_mib_index(' + tableName + '_mib_index *mib_idx) {\n'
            tableInterfaceString += tableName + '_rowreq_ctx *rowreq_ctx;\n'
            tableInterfaceString += 'oid oid_tmp[MAX_OID_LEN];\n'
            tableInterfaceString += 'netsnmp_index oid_idx;\n'
            tableInterfaceString += 'int rc;\n\n'
            tableInterfaceString += 'oid_idx.oids = oid_tmp;\n'
            tableInterfaceString += 'oid_idx.len = sizeof(oid_tmp)/sizeof(oid);\n\n'
            tableInterfaceString += 'rc = ' + tableName + '_index_to_oid(&oid_idx, mib_idx);\n'
            tableInterfaceString += 'if(MFD_SUCCESS != rc) {\n'
            tableInterfaceString += 'return NULL;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'rowreq_ctx = (' + tableName + '_rowreq_ctx *)CONTAINER_FIND(' + tableName + '_if_ctx.container, &oid_idx);\n\n'
            tableInterfaceString += 'return rowreq_ctx;\n'
            tableInterfaceString += '}\n'
            self.fileWrite(fileName=tableName + '_interface.c',data=tableInterfaceString)

            tableInterfaceHeaderString = '#ifndef ' + tableName.upper() + '_INTERFACE_H\n'
            tableInterfaceHeaderString += '#define ' + tableName.upper() + '_INTERFACE_H\n'
            tableInterfaceHeaderString += '#include "' + tableName + '.h"\n\n'
            tableInterfaceHeaderString += 'void _' + tableName + '_initialize_interface(' + tableName + '_registration *user_ctx, u_long flags);\n'
            tableInterfaceHeaderString += 'void _' + tableName + '_shutdown_interface(' + tableName + '_registration *user_ctx);\n'
            tableInterfaceHeaderString += tableName + '_registration *' + tableName + '_registration_get(void);\n'
            tableInterfaceHeaderString += tableName + '_registration *' + tableName + '_registration_set(' + tableName + '_registration *newreg);\n'
            tableInterfaceHeaderString += 'netsnmp_container *' + tableName + '_container_get(void);\n'
            tableInterfaceHeaderString += 'int ' + tableName + '_container_size(void);\n'
            tableInterfaceHeaderString += tableName + '_rowreq_ctx *' + tableName + '_allocate_rowreq_ctx(void*);\n'
            tableInterfaceHeaderString += 'void ' + tableName + '_release_rowreq_ctx(' + tableName + '_rowreq_ctx *rowreq_ctx);\n'
            tableInterfaceHeaderString += 'int ' + tableName + '_index_to_oid(netsnmp_index *oid_idx, ' + tableName + '_mib_index *mib_idx);\n'
            tableInterfaceHeaderString += 'int ' + tableName + '_index_from_oid(netsnmp_index *oid_idx, ' + tableName + '_mib_index *mib_idx);\n'
            tableInterfaceHeaderString += 'void ' + tableName + '_valid_columns_set(netsnmp_column_info *vc);\n'
            tableInterfaceHeaderString += '#endif'
            self.fileWrite(fileName=tableName + '_interface.h',data=tableInterfaceHeaderString)
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
