import sys
import ast
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
      'SNMPv2-TC': ('DisplayString', 'TEXTUAL-CONVENTION',), # XXX
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
      'IPADDRESS': 'IpAddress',
      'NETWORKADDRESS': 'IpAddress',
      'OBJECT IDENTIFIER': 'ObjectIdentifier',
      'OCTET STRING': 'OctetString',
      'OPAQUE': 'Opaque',
      'TIMETICKS': 'TimeTicks',
      'UNSIGNED32': 'Unsigned32',
      'Counter': 'Counter32',
      'Gauge': 'Gauge32',
      'NetworkAddress': 'IpAddress', # RFC1065-SMI, RFC1155-SMI -> SNMPv2-SMI
      'nullSpecific': 'zeroDotZero', # RFC1158-MIB -> SNMPv2-SMI
      'ipRoutingTable': 'ipRouteTable', # RFC1158-MIB -> RFC1213-MIB
      'snmpEnableAuthTraps': 'snmpEnableAuthenTraps'  # RFC1158-MIB -> SNMPv2-MIB
    }
    
    ctypeClasses = {
        'Integer32': 'long',
        'TimeTicks': 'long',
        'OctetString': 'char *',
        'DisplayString': 'char *',
        'ObjectIdentifier':'oid',
        'ZeroBaseCounter32':'u_long',
        'Counter32': 'u_long'
    }

    netsnmpTypes = { 'Integer32':'ASN_INTEGER',
                    'TimeTicks':'ASN_TIMETICKS',
                    'OctetString':'ASN_OCTET_STR',
                    'DisplayString':'ASN_OCTET_STR',
                    'ObjectIdentifier':'ASN_OBJECT_ID',
                    'ZeroBasedCounter32':'u_long',
                    'Counter32':'u_long'
                    }

    smiv1IdxTypes = ['INTEGER', 'OCTET STRING', 'IPADDRESS', 'NETWORKADDRESS']

    ifTextStr = 'if mibBuilder.loadTexts: '
    indent = ' ' * 4
    fakeidx = 1000 # starting index for fake symbols

    def __init__(self, fileWriter):
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
        self.codeSymbols = []
        self.tables = {}
        self.tableRows = {}
        self.fileWriter = fileWriter
        self.customTypes = {}

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
            symbols = ()
            for symbol in set(imports[module]):
                symbols += self.symTrans(symbol)
            if symbols:
                self._presentedSyms = self._presentedSyms.union([self.transOpers(s) for s in symbols])
                self._importMap.update([(self.transOpers(s), module) for s in symbols])
                # outStr += '( %s, ) = mibBuilder.importSymbols("%s")\n' % \
                #   (', '.join([self.transOpers(s) for s in symbols]),
                #     '", "'.join((module,) + symbols))
        return outStr, tuple(sorted(imports))

    def genExports(self,):
        exports = list(self._exports)
        exportsNum = len(exports)
        chunkNum = exportsNum / 254
        outStr = ''
        for i in range(int(chunkNum + 1)):
            outStr += 'mibBuilder.exportSymbols("' + self.moduleName[0] + '", '
            outStr += ', '.join(exports[254 * i:254 * (i + 1)]) + ')\n'
        return self._exports and outStr or ''

    def genLabel(self, symbol, classmode=0):
        if symbol.find('-') != -1 or iskeyword(symbol):
            return classmode and 'label = "' + symbol + '"\n' or \
                                 '.setLabel("' + symbol + '")'
        return ''

    def addToExports(self, symbol, moduleIdentity=0):
        if moduleIdentity:
            self._exports.add('PYSNMP_MODULE_ID=%s' % symbol)
        self._exports.add('%s=%s' % (symbol, symbol))
        self._presentedSyms.add(symbol)

    def regSym(self, symbol, outStr, parentOid=None, moduleIdentity=0):
        if symbol in self._presentedSyms and symbol not in self._importMap:
            raise error.PySmiSemanticError('Duplicate symbol found: %s' % symbol)
        self.addToExports(symbol, moduleIdentity)
        self._out[symbol] = outStr

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
        outStr = name + ' = ModuleIdentity(' + oidStr + ')' + label + revisions + '\n'
        if self.genRules['text']:
            outStr += self.ifTextStr + name + lastUpdated + '\n'
            outStr += self.ifTextStr + name + organization + '\n'
            outStr += self.ifTextStr + name + contactInfo + '\n'
            outStr += self.ifTextStr + name + description + '\n'
        outStr = '//' + name + ' genModuleIdentity\n'
        self.regSym(name, outStr, parentOid, moduleIdentity=1)
        return outStr

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
        name, objects, description, oid = data
        label = self.genLabel(name)
        name = self.transOpers(name)
        oidStr, parentOid = oid
        objStr = ''
        if objects:
            objects = ['("' + self.moduleName[0] + '", "' + self.transOpers(obj) + '"),' for obj in objects]
        objStr = ' '.join(objects)
        outStr = name + ' = NotificationType(' + oidStr + ')' + label
        outStr += '.setObjects(*(' + objStr + '))\n'
        if self.genRules['text']:
            outStr += self.ifTextStr + name + description + '\n'
        outStr = '//' + name + ' genNotificationType'
        self.regSym(name, outStr, parentOid)
        return outStr

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

    def genObjectType(self, data, classmode=0):
        name, syntax, units, maxaccess, description, augmention, index, defval, oid = data
        label = self.genLabel(name)
        name = self.transOpers(name)
        oidStr, parentOid = oid
        indexStr, fakeStrlist, fakeSyms = index and index or ('', '', [])
        subtype = syntax[0] == 'Bits' and 'Bits()' + syntax[1] or \
                                          syntax[1] # Bits hack #1
        classtype = self.typeClasses.get(syntax[0], syntax[0])
        classtype = self.transOpers(classtype)
        classtype = syntax[0] == 'Bits' and 'MibScalar' or classtype # Bits hack #2
        classtype = name in self.symbolTable[self.moduleName[0]]['_symtable_cols'] and 'MibTableColumn' or classtype
        defval = self.genDefVal(defval, objname=name)
        outStr = ''
        #outStr = name + ' = ' + classtype + '(' + oidStr + ', ' + subtype + \
        #         (defval and defval or '') + ')' + label
        #outStr += (units and units) or ''
        #outStr += (maxaccess and maxaccess) or ''
        #outStr += (indexStr and indexStr) or ''
        #outStr += '\n'
        #if augmention:
        #    augmention = self.transOpers(augmention)
        #    outStr += augmention + '.registerAugmentions(("' +
        #    self.moduleName[0] + \
        #              '", "' + name + '"))\n'
        #    outStr += name + '.setIndexNames(*' + augmention +
        #    '.getIndexNames())\n'
        #if self.genRules['text'] and description:
        #    outStr += self.ifTextStr + name + description + '\n'
        outStr = self.codeGenClassTable[classtype](self, name,syntax, units,maxaccess, description, augmention, index, defval, oid, subtype)
        self.regSym(name, outStr, parentOid)
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
        name, declaration = data
        if declaration:
            parentType, attrs = declaration
            if parentType: # skipping SEQUENCE case
                name = self.transOpers(name)
                outStr = 'class ' + name + '(' + parentType + '):\n' + attrs + '\n'
                baseType = parentType[:parentType.find(',')]
                self.customTypes[name] = {'baseType':baseType}
                self.regSym(name, outStr)
        outStr = '//' + name + ' genTypeDeclaration'
        return outStr

    def genValueDeclaration(self, data, classmode=0):
        name, oid = data
        label = self.genLabel(name)
        name = self.transOpers(name)
        oidStr, parentOid = oid
        outStr = name + ' = MibIdentifier(' + oidStr + ')' + label + '\n'
        outStr = '//' + name + ' genValueDeclaration\n'
        self.regSym(name, outStr, parentOid)
        return outStr

### Subparts generation functions
    def genBitNames(self, data, classmode=0):
        names = data[0]
        return names

    def genBits(self, data, classmode=0):
        bits = data[0]
        namedval = ['("' + bit[0] + '", ' + str(bit[1]) + '),' for bit in bits]
        numFuncCalls = len(namedval) / 255 + 1
        funcCalls = ''
        for i in range(int(numFuncCalls)):
            funcCalls += 'NamedValues(' + ' '.join(namedval[255 * i:255 * (i + 1)]) + ') + '
        funcCalls = funcCalls[:-3]
        outStr = classmode and \
          self.indent + 'namedValues = ' + funcCalls + '\n' or \
          '.clone(namedValues=' + funcCalls + ')'
        return 'Bits', outStr

    def genCompliances(self, data, classmode=0):
        complStr = ''
        compliances = []
        for complianceModule in data[0]:
            name = complianceModule[0] or self.moduleName[0]
            compliances += ['("' + name + '", "' + self.transOpers(compl) + '"),' for compl in complianceModule[1]]
        complStr = ' '.join(compliances)
        return '.setObjects(*(' + complStr + '))'

    def genConceptualTable(self, data, classmode=0):
        row = data[0]
        if row[1] and row[1][-2:] == '()':
            row = row[1][:-2]
            self._rows.add(row)
        return 'MibTable', ''

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
                return self.genBits([defvalBits])[1]
            else:
                raise error.PySmiSemanticError('unknown type "%s" for defval "%s" of symbol "%s"' % (defvalType, defval, objname))
        return '.clone(' + val + ')'

    def genDescription(self, data, classmode=0):
        text = data[0]
        return '.setDescription(' + dorepr(text) + ')'

    def genEnumSpec(self, data, classmode=0):
        items = data[0]
        singleval = [str(item[1]) + ',' for item in items]
        outStr = classmode and self.indent + 'subtypeSpec = %s.subtypeSpec+' or '.subtype(subtypeSpec='
        numFuncCalls = len(singleval) / 255 + 1
        singleCall = numFuncCalls == 1 or False
        funcCalls = ''
        outStr += not singleCall and 'ConstraintsUnion(' or ''
        for i in range(int(numFuncCalls)):
            funcCalls += 'SingleValueConstraint(' + \
                              ' '.join(singleval[255 * i:255 * (i + 1)]) + '), '
        funcCalls = funcCalls[:-2]
        outStr += funcCalls
        outStr += not singleCall and \
                  (classmode and ')\n' or '))') or \
                  (not classmode and ')' or '\n')
        outStr += self.genBits(data, classmode=classmode)[1]
        return outStr

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
        singleRange = len(data[0]) == 1 or False
        outStr = classmode and self.indent + 'subtypeSpec = %s.subtypeSpec+' or \
                               '.subtype(subtypeSpec='
        outStr += not singleRange and 'ConstraintsUnion(' or ''
        for rng in data[0]:
            vmin, vmax = len(rng) == 1 and (rng[0], rng[0]) or rng
            vmin, vmax = str(self.str2int(vmin)), str(self.str2int(vmax))
            outStr += 'ValueRangeConstraint(' + vmin + ',' + vmax + ')' + \
                      (not singleRange and ',' or '')
        outStr += not singleRange and \
                  (classmode and ')' or '))') or \
                  (not classmode and ')' or '\n')
        return outStr

    def genMaxAccess(self, data, classmode=0):
        access = data[0].replace('-', '')
        return access != 'notaccessible' and '.setMaxAccess("' + access + '")' or ''

    def genOctetStringSubType(self, data, classmode=0):
        out = {}
        singleRange = len(data[0]) == 1 or False
        outStr = classmode and self.indent + 'subtypeSpec = %s.subtypeSpec+' or \
                               '.subtype(subtypeSpec='
        outStr += not singleRange and 'ConstraintsUnion(' or ''
        for rng in data[0]:
            vmin, vmax = len(rng) == 1 and (rng[0], rng[0]) or rng
            vmin, vmax = str(self.str2int(vmin)), str(self.str2int(vmax))
            out['ValueSizeConstraint'] = (vmin, vmax)
            outStr += 'ValueSizeConstraint(' + vmin + ',' + vmax + ')' + \
                      (not singleRange and ',' or '')
        outStr += not singleRange and \
                  (classmode and ')' or '))') or \
                  (not classmode and ')' or '\n')
        outStr += singleRange and vmin == vmax and \
                  (classmode and self.indent + 'fixedLength = ' + vmin + '\n' or '.setFixedLength(' + vmin + ')') or ''
        return outStr

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
        return row in self.symbolTable[self.moduleName[0]]['_symtable_rows'] and ('MibTableRow', '') or self.genSimpleSyntax(data, classmode=classmode)

    def genSequence(self, data, classmode=0):
        cols = data[0]
        self._cols.update(cols)
        return '', ''

    def genSimpleSyntax(self, data, classmode=0):
        objType = data[0]
        objType = self.typeClasses.get(objType, objType)
        objType = self.transOpers(objType)
        subtype = len(data) == 2 and data[1] or ''
        if classmode:
            subtype = '%s' in subtype and subtype % objType or subtype # XXX hack?
            return objType, subtype
        out = [objType, subtype]
        return 'MibScalar', out

    def genTypeDeclarationRHS(self, data, classmode=0):
        if len(data) == 1:
            parentType, attrs = data[0] # just syntax
        else:
            # Textual convention
            display, syntax = data
            parentType, attrs = syntax
            parentType = parentType + ', TextualConvention'
            attrs = (display and display or '') + attrs
        attrs = attrs or self.indent + 'pass\n'
        return parentType, attrs

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
    
    def genRegisterUnregister(self, moduleName):
        outStr = 'void register_' + moduleName + '(void) {\n'
        for codeSym in self.codeSymbols:
            outStr += 'register_' + codeSym + '();\n'
        outStr += '}\n'
        outStr += 'void unregister_' + moduleName + '(void) {\n'
        for codeSym in self.codeSymbols:
            outStr += 'unregister_' + codeSym + '();\n'
        outStr += '}\n'
        return outStr

    def genIntCode(self, name, syntax, units, maxaccess, description, augmention, index, defval, oid, subtype):
        outStr = 'static int netsnmp_' + name + ' = 42;\n'
        outStr += 'int handler_' + name + '(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests);\n\n'
        outStr += 'void register_' + name + '(void) {\n'
        outStr += 'const oid ' + name + '_oid[] = ' + str(oid).replace('[','{').replace(']','}') + ';\n'
        outStr += 'netsnmp_register_scalar(\n netsnmp_create_handler_registration("' + name + '", handler_' + name + ',' + name + '_oid, OID_LENGTH(' + name + '_oid), HANDLER_CAN_RWRITE));\n'
        outStr += '}\n\n'
        outStr += 'int handler_' + name + '(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {\n'
        outStr += 'if(reqinfo->mode == MODE_GET) {\n'
        outStr += 'snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER, &netsnmp_' + name + ', sizeof(netsnmp_' + name + '));\n'
        outStr += '}\n'
        outStr += 'return SNMP_ERR_NOERROR;\n'
        outStr += '}\n\n'
        return outStr

    def genTimeTicksCode(self, name, syntax, units, maxaccess,description, augmention, index, defval,oid, subtype):
        outStr = 'static unsigned long netsnmp_' + name + ' = 42;\n'
        outStr += 'int handler_' + name + '(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests);\n\n'
        outStr += 'void register_' + name + '(void) {\n'
        outStr += 'const oid ' + name + '_oid[] = ' + str(oid).replace('[','{').replace(']','}') + ';\n'
        outStr += 'netsnmp_register_scalar(\n netsnmp_create_handler_registration("' + name + '", handler_' + name + ',' + name + '_oid, OID_LENGTH(' + name + '_oid), HANDLER_CAN_RWRITE));\n'
        outStr += '}\n\n'
        outStr += 'int handler_' + name + '(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {\n'
        outStr += 'if(reqinfo->mode == MODE_GET) {\n'
        outStr += 'snmp_set_var_typed_value(requests->requestvb, ASN_TIMETICKS, &netsnmp_' + name + ', sizeof(netsnmp_' + name + '));\n'
        outStr += '}\n'
        outStr += 'return SNMP_ERR_NOERROR;\n'
        outStr += '}\n\n'
        return outStr

    def genStringCode(self, name, syntax, units, maxaccess, description, augmention, index, defval,oid, subtype):
        minConstraint, maxConstraint = subtype[1].get('ValueSizeConstraint',(0,0))
        if maxConstraint == 0:
            stringLength = 256
        else:
            if minConstraint == 0:
                stringLength = maxConstraint + 1
            else:
                stringLength = maxConstraint
        outStr = 'static char netsnmp_' + name + '[' + str(stringLength) + '] = "Avinash";\n'
        outStr += 'int handler_' + name + '(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests);\n\n'
        outStr += 'void register_' + name + '(void) {\n'
        outStr += 'const oid ' + name + '_oid[] = ' + str(oid).replace('[','{').replace(']','}') + ';\n'
        outStr += 'netsnmp_register_scalar(\n netsnmp_create_handler_registration("' + name + '", handler_' + name + ',' + name + '_oid, OID_LENGTH(' + name + '_oid), HANDLER_CAN_RWRITE));\n'
        outStr += '}\n\n'
        outStr += 'int handler_' + name + '(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {\n'
        outStr += 'if(reqinfo->mode == MODE_GET) {\n'
        outStr += 'snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, netsnmp_' + name + ', strlen(netsnmp_' + name + '));\n'
        outStr += '}\n'
        outStr += 'return SNMP_ERR_NOERROR;\n'
        outStr += '}\n\n'
        return outStr

    def genOidCode(self, name, syntax, units, maxaccess, description, augmention, index, defval, oid, subtype):
        outStr = 'static oid netsnmp_' + name + '[MAX_OID_LEN] = { 0 };\n'
        outStr += 'static int netsnmp_' + name + '_byte_length = 1;\n'
        outStr += 'int handler_' + name + '(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests);\n\n'
        outStr += 'void register_' + name + '(void) {\n'
        outStr += 'const oid ' + name + '_oid[] = ' + str(oid).replace('[','{').replace(']','}') + ';\n'
        outStr += 'netsnmp_register_scalar(\n netsnmp_create_handler_registration("' + name + '", handler_' + name + ',' + name + '_oid, OID_LENGTH(' + name + '_oid), HANDLER_CAN_RWRITE));\n'
        outStr += '}\n\n'
        outStr += 'int handler_' + name + '(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {\n'
        outStr += 'if(reqinfo->mode == MODE_GET) {\n'
        outStr += 'snmp_set_var_typed_value(requests->requestvb, ASN_OBJECT_ID, netsnmp_' + name + ', netsnmp_' + name + '_byte_length);\n'
        outStr += '}\n'
        outStr += 'return SNMP_ERR_NOERROR;\n'
        outStr += '}\n\n'
        return outStr

    def genZeroCounterCode(self, name, syntax, units, maxaccess, description, augmention, index, defval, oid, subtype):
        outStr = 'static u_long netsnmp_' + name + ' = 0 ;\n'
        outStr += 'int handler_' + name + '(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests);\n\n'
        outStr += 'void register_' + name + '(void) {\n'
        outStr += 'const oid ' + name + '_oid[] = ' + str(oid).replace('[','{').replace(']','}') + ';\n'
        outStr += 'netsnmp_register_scalar(\n netsnmp_create_handler_registration("' + name + '", handler_' + name + ',' + name + '_oid, OID_LENGTH(' + name + '_oid), HANDLER_CAN_RWRITE));\n'
        outStr += '}\n\n'
        outStr += 'int handler_' + name + '(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {\n'
        outStr += 'if(reqinfo->mode == MODE_GET) {\n'
        outStr += 'snmp_set_var_typed_value(requests->requestvb, ASN_GAUGE, netsnmp_' + name + ', netsnmp_' + name + '_byte_length);\n'
        outStr += '}\n'
        outStr += 'return SNMP_ERR_NOERROR;\n'
        outStr += '}\n\n'
        return outStr

    def genCounterCode(self, name, syntax, units, maxaccess, description, augmention, index, defval, oid, subtype):
        outStr = 'static u_long netsnmp_' + name + ' = 0;\n'
        outStr += 'int handler_' + name + '(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests);\n\n'
        outStr += 'void register_' + name + '(void) {\n'
        outStr += 'const oid ' + name + '_oid[] = ' + str(oid).replace('[','{').replace(']','}') + ';\n'
        outStr += 'netsnmp_register_scalar(\n netsnmp_create_handler_registration("' + name + '", handler_' + name + ',' + name + '_oid, OID_LENGTH(' + name + '_oid), HANDLER_CAN_RWRITE));\n'
        outStr += '}\n\n'
        outStr += 'int handler_' + name + '(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {\n'
        outStr += 'if(reqinfo->mode == MODE_GET) {\n'
        outStr += 'snmp_set_var_typed_value(requests->requestvb, ASN_COUNTER, netsnmp_' + name + ', netsnmp_' + name + '_byte_length);\n'
        outStr += '}\n'
        outStr += 'return SNMP_ERR_NOERROR;\n'
        outStr += '}\n\n'
        return outStr

    codeGenTable = { 'Integer32':genIntCode,
                   'TimeTicks': genTimeTicksCode,
                   'OctetString':genStringCode,
                   'DisplayString':genStringCode,
                   'ObjectIdentifier': genOidCode,
                   'ZeroBasedCounter32':genZeroCounterCode,
                   'Counter32':genCounterCode }

    def getSubTypeString(self, subtype):
        ret = ''
        if type(subtype) is str:
            return 'Integer32'
        if subtype[0] in self.customTypes:
            ret = self.customTypes[subtype[0]]['baseType']
        else:
            ret = subtype[0] 
        if 'SnmpAdminString' in ret:
            return 'OctetString'
        if 'Bits' in ret:
            return 'Integer32'
        if 'TimeFilter' in ret:
            return 'Integer32'
        if 'TruthValue' in ret:
            return 'Integer32'
        if ret.encode('ascii','ignore') is 'B':
            return 'Integer32'
        return ret
        
    def genScalarCode(self, name, syntax, units, maxaccess, description, augmention, index, defval, oid, subtype):
        self.codeSymbols.append(name)
        oidStr, parendOid = oid
        try:
            if subtype[0] in self.customTypes:
                baseType = self.customTypes[subtype[0]]['baseType']
                outStr = self.codeGenTable[baseType](self, name,syntax,units,maxaccess,description,augmention,index,defval,oid,['',''])
            else:
                outStr = self.codeGenTable[subtype[0]](self,name, syntax, units, maxaccess, description, augmention, index, defval, oidStr,subtype)
        except Exception as ex:
            print ex.message
            outStr = ''
        return outStr
        
    def genTableCode(self, name, syntax, units, maxaccess, description, augmention, index, defval, oid, subtype):
        tempDict = self.getDictionary(name, syntax, units, maxaccess,description, augmention,index, defval,oid, subtype)
        self.tables[name] = {'data': tempDict}
        return ''
        
    def genTableRowCode(self, name, syntax, units, maxaccess, description, augmention, index, defval, oid, subtype):
        oidStr, parentOid = oid
        self.tables[parentOid]['row'] = name
        tempDict = self.getDictionary(name, syntax,units,maxaccess, description, augmention, index, defval,oid, subtype)
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
        elif augmention is not None:
            indexColumn = augmention
            self.tableRows[name]['index'].append(indexColumn)
        self.tableRows[name]['columns'] = []
        return ''
        
    def genTableColumnCode(self, name, syntax, units, maxaccess, description, augmention, index, defval, oid, subtype):
        oidStr, parentOid = oid
        tempDict = self.getDictionary(name, syntax, units, maxaccess, description, augmention, index, defval, oid, subtype)
        self.tableRows[parentOid]['columns'].append(tempDict)
        return ''
        
    def getDictionary(self, name, syntax, units, maxaccess, description, augmention, index,defval,oid,subtype):
        return {'name':name,
                'syntax':syntax,
                'units':units,
                'maxaccess':maxaccess,
                'description':description,
                'augmention':augmention,
                'index':index,
                'defval':defval,
                'oid':oid,
                'subtype':subtype}

    codeGenClassTable = { 'MibScalar':genScalarCode,
                         'MibTable':genTableCode,
                         'MibTableRow':genTableRowCode,
                         'MibTableColumn':genTableColumnCode}
    
    def genCode(self, ast, symbolTable, **kwargs):
        self.genRules['text'] = kwargs.get('genTexts', False)
        self.symbolTable = symbolTable
        out = ''
        importedModules = ()
        self._rows.clear()
        self._cols.clear()
        self._exports.clear()
        self._presentedSyms.clear()
        self._importMap.clear()
        self._out.clear()
        self.moduleName[0], moduleOid, imports, declarations = ast
        out, importedModules = self.genImports(imports and imports or {})
        for declr in declarations and declarations or []:
            if declr:
                clausetype = declr[0]
                classmode = clausetype == 'typeDeclaration'
                self.handlersTable[declr[0]](self, self.prepData(declr[1:], classmode), classmode)
        for sym in self.symbolTable[self.moduleName[0]]['_symtable_order']:
            # if sym not in self._out:
            #     raise error.PySmiCodegenError('No generated code for symbol
            #     %s' % sym)
            if sym in self.codeSymbols:
                out += self._out[sym]
        # out += self.genExports()
        out += self.genRegisterUnregister(self.moduleName[0].replace('-','_'))
        out = self.headers + '#include "' + self.moduleName[0].replace('-','_') + '.h"\n' + out
        if 'comments' in kwargs:
            out = ''.join(['// %s\n' % x for x in kwargs['comments']]) + '//\n' + out
            out = '//\n// Net-SNMP MIB module %s (http://pysnmp.sf.net)\n' % self.moduleName[0] + out
        debug.logger & debug.flagCodegen and debug.logger('canonical MIB name %s (%s), imported MIB(s) %s, C code size %s bytes' % (self.moduleName[0], moduleOid, ','.join(importedModules) or '<none>', len(out)))
        self.genCFile(self.moduleName[0].replace('-','_'),out)
        self.genCTableFiles(self.moduleName[0].replace('-','_'))
        self.genHeaderFile(self.moduleName[0].replace('-','_'))
        return MibInfo(oid=None, name=self.moduleName[0], imported=tuple([ x for x in importedModules if x not in fakeMibs])), out

    def genCFile(self, moduleName, data):
        self.fileWriter.fileWrite(fileName=moduleName + '.c',data=data)

    def genCTableFiles(self, moduleName):
        for key in self.tables.keys():
            tableName = key
            indexes = []
            for col in self.tableRows[self.tables[tableName]['row']]['columns']:
                if col['name'] in self.tableRows[self.tables[tableName]['row']]['index']:
                    indexes.append(col)
            if len(indexes) is 0:
                continue
            tableFileString = """#include <net-snmp/net-snmp-config.h>
    #include <net-snmp/net-snmp-features.h>
    #include <net-snmp/net-snmp-includes.h>
    #include <net-snmp/agent/net-snmp-agent-includes.h>
    #include <net-snmp/agent/mib-modules.h>
    """
            tableFileString += '#include "' + tableName + '".h\n'
            tableFileString += '#include "' + tableName + '"_interface.h\n\n'
            tableFileString += 'const oid ' + tableName + '_oid[] = {' + tableName.upper() + '_OID };\n'
            tableFileString += 'const int ' + tableName + '_oid_size = OID_LENGTH(' + tableName + '_oid);\n'
            tableFileString += tableName + '_registration ' + tableName + '_user_context;\n'
            tableFileString += 'void initialize_table_' + tableName + '(void);\n'
            tableFileString += 'void shutdown_table_' + tableName + '(void);\n'
            tableFileString += 'void init_' + tableName + '(void) {\n'
            tableFileString += tableName + '_registration * user_context;\n'
            tableFileString += 'u_long flags;\n'
            tableFileString += 'user_context = netsnmp_create_data_list("' + tableName + '",NULL,NULL);\n'
            tableFileString += 'flags = 0;\n'
            tableFileString += '_' + tableName + '_initialize_interface(user_context,flags);\n'
            tableFileString += '}\n\n'
            tableFileString += 'shutdown_' + tableName + '(void) {\n'
            tableFileString += '_' + tableName + '_shutdown_interface(&' + tableName + '_user_context);\n'
            tableFileString += '}\n\n'
            tableFileString += 'int ' + tableName + '_rowreq_ctx_init(' + tableName + '_rowreq_ctx *rowreq_ctx, void *user_init_ctx) {\n'
            tableFileString += 'return MFD_SUCCESS;\n'
            tableFileString += '}\n\n'
            tableFileString += 'void ' + tableName + '_rowreq_ctx_cleanup(' + tableName + '_rowreq_ctx *rowreq_ctx) {\n'
            tableFileString += '}\n\n'
            tableFileString += 'int ' + tableName + '_pre_request(' + tableName + '_registration *user_context) {\n'
            tableFileString += 'return MFD_SUCCESS;\n'
            tableFileString += '}\n\n'
            tableFileString += 'int ' + tableName + '_post_request(' + tableName + '_registration *user_context) {\n'
            tableFileString += 'return MFD_SUCCESS;\n'
            tableFileString += '}\n'
            self.fileWriter.fileWrite(fileName=tableName + '.c',data=tableFileString)

            tableFileHeaderString = '#ifndef ' + tableName.upper() + '_H\n'
            tableFileHeaderString += '#define ' + tableName.upper() + '_H\n'
            tableFileHeaderString += '#include <net-snmp/library/asn1.h>\n'
            tableFileHeaderString += '#include "' + tableName + '_oids.h"'
            tableFileHeaderString += '#include "' + tableName + '_enums.h"'
            #tableFileHeaderString +=
            #tableFileHeaderString += 'config_add_mib('+moduleName+')\n'
            #tableFileHeaderString +=
            #'config_require('+moduleName+')/'+tableName+'/'+tableName+'_interface)\n'
            #tableFileHeaderString +=
            #'config_require('+moduleName+')/'+tableName+'/'+tableName+'_data_access)\n'
            #tableFileHeaderString +=
            #'config_require('+moduleName+')/'+tableName+'/'+tableName+'_data_get)\n'
            #tableFileHeaderString +=
            #'config_require('+moduleName+')/'+tableName+'/'+tableName+'_data_set)\n'
            tableFileHeaderString += 'void init_' + tableName + '(void);\n'
            tableFileHeaderString += 'void shutdown_' + tableName + '(void);\n\n'
            tableFileHeaderString += 'typedef netsnmp_data_list ' + tableName + '_registration;\n\n'
            tableFileHeaderString += 'typedef struct ' + tableName + '_data_s {\n'
            for col in self.tableRows[self.tables[tableName]['row']]['columns']:
                if col['name'] not in self.tableRows[self.tables[tableName]['row']]['index']:
                    tableFileHeaderString += self.ctypeClasses[self.getSubTypeString(col['subtype'])] + ' ' + col['name'] + ';\n'
                else:
                    indexes.append(col)
            tableFileHeaderString += '} ' + tableName + '_data;\n\n'
            tableFileHeaderString += 'typedef struct ' + tableName + '_mib_index_s {\n'
            for idx in indexes:
                tableFileHeaderString += self.ctypeClasses[self.getSubTypeString(idx['subtype'])] + ' ' + idx['name'] + ';\n'
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
            tableFileHeaderString += tableName + 'rowreq_ctx* ' + tableName + '_row_find_by_mib_index(' + tableName + '_mib_index *mib_idx);\n'
            tableFileHeaderString += 'extern const oid ' + tableName + '_oid[];\n'
            tableFileHeaderString += 'extern const int ' + tableName + '_oid_size;\n'
            tableFileHeaderString += '#include "' + tableName + '_interface.h"\n'
            tableFileHeaderString += '#include "' + tableName + '_data_access.h"\n'
            tableFileHeaderString += '#include "' + tableName + '_data_get.h"\n'
            tableFileHeaderString += '#include "' + tableName + '_data_set.h"\n\n'
            tableFileHeaderString += '#endif'
            self.fileWriter.fileWrite(fileName= tableName + '.h',data=tableFileHeaderString)

            tableOidsHeaderString = '#ifndef ' + tableName.upper() + '_OIDS_H\n'
            tableOidsHeaderString += '#define ' + tableName.upper() + '_OIDS_H\n'
            oidStr,parentOid = self.tables[tableName]['data']['oid']
            oidStr = oidStr.replace('[','').replace(']','')
            tableOidsHeaderString += '#define ' + tableName.upper() + ' ' + oidStr + '\n'
            for col in self.tableRows[self.tables[tableName]['row']]['columns']:
                tempOid, tempParentOid = col['oid']
                tempOid = tempOid[tempOid.rfind(',') + 1:tempOid.rfind(']')]
                tableOidsHeaderString += '#define COLUMN_' + col['name'] + ' ' + tempOid + '\n'
            tableOidsHeaderString += '#endif'
            self.fileWriter.fileWrite(fileName=tableName + '_oids.h',data=tableOidsHeaderString)

            tableDataGetString = """#include <net-snmp/net-snmp-config.h>
    #include <net-snmp/net-snmp-features.h>
    #include <net-snmp/net-snmp-includes.h>
    #include <net-snmp/agent/net-snmp-agent-includes.h>
    """
            tableDataGetString += '#include ' + tableName + '.h\n\n'
            tableDataGetString += 'int ' + tableName + '_indexes_set_tbl_idx(' + tableName + '_mib_index *tbl_idx'
            for idx in indexes:
               tableDataGetString += ', ' + self.ctypeClasses[self.getSubTypeString(idx['subtype'])] + ' ' + idx['name'] + '_val'
            tableDataGetString += ') {\n'
            for idx in indexes:
                tableDataGetString += 'tbl_idx->' + idx['name'] + ' = ' + idx['name'] + '_val;\n'
            tableDataGetString += 'return MFD_SUCCESS;\n'
            tableDataGetString += '}\n\n'
            tableDataGetString += 'int ' + tableName + '_indexes_set(' + tableName + '_rowreq_ctx *rowreq_ctx'
            for idx in indexes:
               tableDataGetString += ', ' + self.ctypeClasses[self.getSubTypeString(idx['subtype'])] + ' ' + idx['name'] + '_val'
            tableDataGetString += ') {\n'
            tableDataGetString += 'if (MFD_SUCCESS != ' + tableName + '_indexes_set_tbl_idx(&rowreq_ctx->tbl_idx'
            for idx in indexes:
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
            for col in self.tableRows[self.tables[tableName]['row']]['columns']:
                tableDataGetString += 'int ' + col['name'] + '_get(' + tableName + '_rowreq_ctx *rowreq_ctx,' + self.ctypeClasses[self.getSubTypeString(col['subtype'])] + ' *' + col['name'] + '_val_ptr) {\n'
                tableDataGetString += '(*' + col['name'] + '_val_ptr) = rowreq_ctx->data.' + col['name'] + ';\n'
                tableDataGetString += 'return MFD_SUCCESS;\n'
                tableDataGetString += '}\n\n'
            self.fileWriter.fileWrite(fileName=tableName + '_data_get.c',data=tableDataGetString)

            tableDataGetHeaderString = '#ifndef ' + tableName.upper() + '_DATA_GET_H\n'
            tableDataGetHeaderString += '#define ' + tableName.upper() + '_DATA_GET_H\n'
            for col in self.tableRows[self.tables[tableName]['row']]['columns']:
                tableDataGetHeaderString += 'int ' + col['name'] + '_get(' + tableName + '_rowreq_ctx,' + self.ctypeClasses[self.getSubTypeString(col['subtype'])] + ' *' + col['name'] + '_val_ptr);\n'
            tableDataGetHeaderString += 'int ' + tableName + '_indexes_set_tbl_idx(' + tableName + '_mib_index *tbl_idx'
            for idx in indexes:
                tableDataGetHeaderString += ', ' + self.ctypeClasses[self.getSubTypeString(idx['subtype'])] + ' ' + idx['name'] + '_val'
            tableDataGetHeaderString += ');\n'
            tableDataGetHeaderString += 'int ' + tableName + '_indexes_set(' + tableName + '_rowreq_ctx *rowreq_ctx'
            tableDataGetHeaderString += ', ' + self.ctypeClasses[self.getSubTypeString(idx['subtype'])] + ' ' + idx['name'] + '_val'
            tableDataGetHeaderString += ');\n'
            tableDataGetHeaderString += '#endif\n'
            self.fileWriter.fileWrite(fileName=tableName + '_data_get.h',data=tableDataGetHeaderString)

            tableDataSetString = """#include <net-snmp/net-snmp-config.h>
    #include <net-snmp/net-snmp-features.h>
    #include <net-snmp/net-snmp-includes.h>
    #include <net-snmp/net-snmp-agent-includes.h>
    """
            tableDataSetString += '#include "' + tableName + '.h"\n'
            self.fileWriter.fileWrite(fileName=tableName + '_data_set.c',data=tableDataSetString)

            tableDataSetHeaderString = '#ifndef ' + tableName.upper() + '_DATA_SET_H\n'
            tableDataSetHeaderString += '#define ' + tableName.upper() + '_DATA_SET_H\n'
            tableDataSetHeaderString += '#endif\n'
            self.fileWriter.fileWrite(fileName=tableName + '_data_set.h',data=tableDataSetHeaderString)

            tableDataAccessString = """#include <net-snmp/net-snmp-config.h>
    #include <net-snmp/net-snmp-features.h>
    #include <net-snmp/net-snmp-includes.h>
    #include <net-snmp/agent/net-snmp-agent-includes.h>
    """
            tableDataAccessString += '#include "' + tableName + '.h"\n'
            tableDataAccessString += '#include "' + tableName + '_data_access.h"\n'
            tableDataAccessString += 'int ' + tableName + '_init_data(' + tableName + '_registration *' + tableName + '_reg) {\n'
            tableDataAccessString += 'return MFD_SUCCESS;\n'
            tableDataAccessString += '}\n\n'
            tableDataAccessString += 'void ' + tableName + '_container_init(netsnmp_container **container_ptr_ptr, netsnmp_cache *cache) {\n'
            tableDataAccessString += 'if (NULL == container_ptr_ptr) {\n'
            tableDataAccessString += 'return;\n'
            tableDataAccessString += '}\n'
            tableDataAccessString += '*container_ptr_ptr = NULL;\n'
            tableDataAccessString += 'if (NULL == cache) {\n'
            tableDataAccessString += 'return;\n'
            tableDataAccessString += '}\n'
            tableDataAccessString += 'cache->timeout = ' + tableName.upper() + '_CACHE_TIMEOUT;\n'
            tableDataAccessString += '}\n\n'
            tableDataAccessString += 'void ' + tableName + '_container_shutdown(netsnmp_container *container_ptr) {\n'
            tableDataAccessString += 'if (NULL == container_ptr) {\n'
            tableDataAccessString += 'return;\n'
            tableDataAccessString += '}\n'
            tableDataAccessString += '}\n\n'
            tableDataAccessString += 'int ' + tableName + '_container_load(netsnmp_container *container) {\n'
            tableDataAccessString += tableName + '_rowreq_ctx *rowreq_ctx;\n'
            tableDataAccessString += 'size_t count = 0;\n'
            for idx in indexes:
                tableDataAccessString += self.ctypeClasses[self.getSubTypeString(idx['subtype'])] + ' ' + idx['name'] + ';\n'
            tableDataAccessString += 'return MFD_SUCCESS;\n'
            tableDataAccessString += '}\n\n'
            tableDataAccessString += 'void ' + tableName + '_container_free(netsnmp_container *container) {\n'
            tableDataAccessString += '}\n\n'
            tableDataAccessString += 'int ' + tableName + '_row_prep(' + tableName + '_rowreq_ctx *rowreq_ctx) {\n'
            tableDataAccessString += 'return MFD_SUCCESS;\n'
            tableDataAccessString += '}\n'
            self.fileWriter.fileWrite(fileName=tableName + '_data_access.c',data=tableDataAccessString)

            tableDataAccessHeaderString = '#ifndef ' + tableName.upper() + '_DATA_ACCESS_H\n'
            tableDataAccessHeaderString += '#define ' + tableName.upper() + '_DATA_ACCESS_H\n'
            tableDataAccessHeaderString += 'int ' + tableName + '_init_data(' + tableName + '_registration *' + tableName + '_reg);\n'
            tableDataAccessHeaderString += '#define ' + tableName.upper() + '_CACHE_TIMEOUT 60\n'
            tableDataAccessHeaderString += 'void ' + tableName + '_container_init(netsnmp_container ** container_ptr_ptr, netsnmp_cache *cache);\n'
            tableDataAccessHeaderString += 'void ' + tableName + '_container_shutdown(netsnmp_container *container_ptr);\n'
            tableDataAccessHeaderString += 'int ' + tableName + '_container_load(netsnmp_container *container);\n'
            tableDataAccessHeaderString += 'void ' + tableName + '_container_free(netsnmp_container *container);\n'
            tableDataAccessHeaderString += 'int ' + tableName + '_cache_load(netsnmp_container *container);\n'
            tableDataAccessHeaderString += 'void ' + tableName + '_cache_free(netsnmp_container *container);\n'
            tableDataAccessHeaderString += 'int ' + tableName + '_row_prep(' + tableName + '_rowreq_ctx *rowreq_ctx);\n'
            tableDataAccessHeaderString += '#endif'
            self.fileWriter.fileWrite(fileName=tableName + '_data_access.h',data=tableDataAccessHeaderString)

            tableEnumsHeaderString = '#ifndef ' + tableName.upper() + '_ENUMS_H\n'
            tableEnumsHeaderString += '#define ' + tableName.upper() + '_ENUMS_H\n'
            tableEnumsHeaderString += '#endif\n'
            self.fileWriter.fileWrite(fileName=tableName + '_enums.h',data=tableEnumsHeaderString)

            tableInterfaceString = """#include <net-snmp/net-snmp-config.h>
    #include <net-snmp/net-snmp-features.h>
    #include <net-snmp/net-snmp-includes.h>
    #include <net-snmp/agent/net-snmp-agent-includes.h>
    #include <net-snmp/agent/table_container.h>
    #include <net-snmp/library/container.h>
    """
            tableInterfaceString += '#include "' + tableName + '.h"\n'
            tableInterfaceString += '#include "' + tableName + '_interface.h"\n'
            tableInterfaceString += 'netsnmp_feature_require(baby_steps)\n'
            tableInterfaceString += 'netsnmp_feature_require(row_merge)\n'
            tableInterfaceString += 'netsnmp_feature_require(check_all_requests_error)\n'
            tableInterfaceString += '#include <ctype.h>\n\n'
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
            tableInterfaceString += 'void +' + tableName + '_initialize_interface(' + tableName + '_registration *reg_ptr, u_long flags) {\n'
            tableInterfaceString += 'netsnmp_baby_steps_access_methods *access_multiplexer = &' + tableName + '_if_ctx.access_multiplexer;\n'
            tableInterfaceString += 'netsnmp_table_registration_info *tbl_info = &' + tableName + '_if_ctx.tbl_info;\n'
            tableInterfaceString += 'netsnmp_handler_registration *reginfo;\n'
            tableInterfaceString += 'netsnmp_mib_handler *handler;\n'
            tableInterfaceString += 'int mfd_modes = 0;\n\n'
            tableInterfaceString += 'netsnmp_table_helper_add_indexes(tbl_info'
            for idx in indexes:
                tableInterfaceString += ', ' + self.netsnmpTypes[self.getSubTypeString(idx['subtype'])]
            tableInterfaceString += ', 0);\n'
            tableInterfaceString += tableName + '_if_ctx.user_ctx = reg_ptr;\n'
            tableInterfaceString += tableName + '_init_data(reg_ptr);\n'
            tableInterfaceString += '_' + tableName + '_container_init(&' + tableName + '_if_ctx);\n'
            tableInterfaceString += 'if ( NULL == ' + tableName + '_if_ctx.container) {\n'
            tableInterfaceString += 'return;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'access_multiplexer->object_lookup = _mfd_' + tableName + '_object_lookup;\n'
            tableInterfaceString += 'access_multiplexer->get_values = _mfd_' + tableName + '_get_values;\n\n'
            tableInterfaceString += 'access_multiplexer->pre_request = _mfd_' + tableName + '_pre_request;\n'
            tableInterfaceString += 'access_multiplexer->post_request = _mfd_' + tableName + '_post_request;\n\n'
            tableInterfaceString += 'handler = netsnmp_baby_steps_access_multiplexer_get(access_multiplexer);\n'
            tableInterfaceString += 'reginfo = netsnmp_handler_registration_create("' + tableName + '", handler, ' + tableName + '_oid, ' + tableName + '_oid_size, HANDLER_CAN_BABY_STEP | HANDLER_CAN_RONLY);\n\n'
            tableInterfaceString += 'if (NULL == reginfo) {\n'
            tableInterfaceString += 'return;\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += 'reginfo->my_reg_void = &' + tableName + '_if_ctx;\n\n'
            tableInterfaceString += 'if (access_multiplexer->object_lookup)\n'
            tableInterfaceString += 'mfd_modes |= BABY_STEP_OBJECT_LOOKUP;\n'
            tableInterfaceString += 'if (access_multiplexer->pre_request)\n'
            tableInterfaceString += 'mfd_modes |= BABY_STEP_PRE_REQUEST;\n'
            tableInterfaceString += 'if (access_multiplexer->post_request)\n'
            tableInterfaceString += 'mfd_modes |= BABY_STEP_POST_REQUEST;\n\n'
            tableInterfaceString += 'if (access_multiplexer->set_values)\n'
            tableInterfaceString += 'mfd_modes |= BABY_STEP_SET_VALUES;\n'
            tableInterfaceString += 'if (access_multiplexer->irreversible_commit)\n'
            tableInterfaceString += 'mfd_modes |= BABY_STEP_IRREVERSIBLE_COMMIT;\n'
            tableInterfaceString += 'if (access_multiplexer->object_syntax_checks)\n'
            tableInterfaceString += 'mfd_modes |= BABY_STEP_CHECK_OBJECT;\n'
            tableInterfaceString += 'if (access_multiplexer->undo_setup)\n'
            tableInterfaceString += 'mfd_modes |= BABY_STEP_UNDO_SETUP;\n'
            tableInterfaceString += 'if (access_multiplexer->undo_cleanup)\n'
            tableInterfaceString += 'mfd_modes |= BABY_STEP_UNDO_CLEANUP;\n'
            tableInterfaceString += 'if (access_multiplexer->undo_sets)\n'
            tableInterfaceString += 'mfd_modes |= BABY_STEP_UNDO_SETS;\n'
            tableInterfaceString += 'if(access_multiplexer->row_creation)\n'
            tableInterfaceString += 'mfd_modes |= BABY_STEP_ROW_CREATE;\n'
            tableInterfaceString += 'if(access_multiplexer->consistency_checks)\n'
            tableInterfaceString += 'mfd_modes |= BABY_STEP_CHECK_CONSISTENCY;\n'
            tableInterfaceString += 'if(access_multiplexer->commit)\n'
            tableInterfaceString += 'mfd_modes |= BABY_STEP_COMMIT;\n'
            tableInterfaceString += 'if(access_multiplexer->undo_commit)\n'
            tableInterfaceString += 'mfd_modes |= BABY_STEP_UNDO_COMMIT;\n\n'
            tableInterfaceString += 'handler = netsnmp_baby_steps_handler_get(mfd_modes);\n'
            tableInterfaceString += 'netsnmp_inject_handler(reginfo, hanlder);\n\n'
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
            tableInterfaceString += 'int ' + tableName + '_valid_columns_set(netsnmp_column_info *vc) {\n'
            tableInterfaceString += tableName + '_if_ctx.tbl_info.valid_columns = vc;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'int ' + tableName + '_index_to_oid(netsnmp_index *oid_idx, ' + tableName + '_mib_index *mib_idx) {\n'
            tableInterfaceString += 'int err = SNMP_ERR_NOERROR;\n'
            for idx in indexes:
                tableInterfaceString += 'netsnmp_variable_list var_' + idx['name'] + ';\n'
            for index, idx in enumerate(indexes):
                tableInterfaceString += 'memset( &var_' + idx['name'] + ', 0x00, sizeof(var_' + idx['name'] + '));\n'
                tableInterfaceString += 'var_' + idx['name'] + '.type = ' + self.netsnmpTypes[self.getSubTypeString(idx['subtype'])] + ';\n'
                if index is not len(indexes) -1:
                    tableInterfaceString += 'var_' + idx['name'] + '.next_variable = &' + indexes[index + 1]['name'] + ';\n'
                else:
                    tableInterfaceString += 'var_' + idx['name'] + '.next_variable = NULL;\n'
            for idx in indexes:
                tableInterfaceString += 'snmp_set_var_value(&var_' + idx['name'] + ', &mib_idx->' + idx['name'] + ', sizeof(mib_idx->' + idx['name'] + '));\n'
            tableInterfaceString += 'err = build_oid_noalloc(oid_idx->oids, oid_idx->len, &oid_idx->len, NULL, 0, &var_' + indexes[0]['name'] + ');\n'
            tableInterfaceString += 'if(err) {\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'snmp_reset_var_buffers(&var_' + indexes[0]['name'] + ';\n'
            tableInterfaceString += 'return err;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'int ' + tableName + '_index_from_oid(netsnmp_index *oid_idx, ' + tableName + '_mi_index *mib_idx) {\n'
            tableInterfaceString += 'int err = SNMP_ERR_NOERROR;\n'
            for idx in indexes:
                tableInterfaceString += 'netsnmp_variable_list var_' + idx['name'] + ';\n'
            for index, idx in enumerate(indexes):
                tableInterfaceString += 'memset(&var_' + idx['name'] + ', 0x00, sizeof(var_' + idx['name'] + '));\n'
                tableInterfaceString += 'var_' + idx['name'] + '.type = ' + self.netsnmpTypes[self.getSubTypeString(idx['subtype'])] + ';\n'
                if index is not len(indexes)-1:
                    tableInterfaceString += 'var_' + idx['name'] + '.next_variable = &' + indexes[index + 1]['name'] + ';\n'
                else:
                    tableInterfaceString += 'var_' + idx['name'] + '.next_variable = NULL;\n'
            tableInterfaceString += 'err = parse_oid_indexes( oid_idx->oids, oid_idx->len, &var_' + indexes[0]['name'] + ');\n'
            tableInterfaceString += 'if (err == SNMP_ERR_NOERROR) {\n'
            for idx in indexes:
                tableInterfaceString += 'mib_idx->' + idx['name'] + '*((' + self.ctypeClasses[self.getSubTypeString(idx['subtype'])] + '*)var_' + idx['name'] + '.val.string);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'snmp_reset_var_buffers(&var_' + indexes[0]['name'] + ';\n'
            tableInterfaceString += 'return err;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += tableName + '_rowreq_ctx *' + tableName + '_allocate_rowreq_ctx(void *user_init_ctx) {\n'
            tableInterfaceString += tableName + '_rowreq_ctx *rowreq_ctx = SNMP_MALLOC_TYPEDEF(' + tableName + '_rowreq_ctx);\n'
            tableInterfaceString += 'if(NULL == rowreq_ctx) {\n'
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
            tableInterfaceString += 'void ' + tableName + '_relase_rowreq_ctx(' + tableName + '_rowreq_ctx *rowreq_ctx) {\n'
            tableInterfaceString += tableName + '_rowreq_ctx_cleanup(rowreq_ctx);\n'
            tableInterfaceString += 'if (rowreq_ctx->oid_idx.oids != rowreq_ctx->oid_tmp) {\n'
            tableInterfaceString += 'free(rowreq_ctx->oid_idx.oids);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'SNMP_FREE(rowreq_ctx);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'static int _mfd_' + tableName + '_pre_request(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *agtreq_info, netsnmp_request_info *requests) {\n'
            tableInterfaceString += 'int rc;\n'
            tableInterfaceString += 'if (1 != netsnmp_row_merge_status_first(reginfo, agtreq_info)) {\n'
            tableInterfaceString += 'return SNMP_ERR_NOERROR;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'rc = ' + tableName + '_pre_request(' + tableName + '_if_ctx.user_ctx);\n'
            tableInterfaceString += 'if(MFD_SUCCESS != rc) {\n'
            tableInterfaceString += 'netsnmp_request_set_error_all(requests, SNMP_VALIDATE_ERR(rc));\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'return SNMP_ERR_NOERROR;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'static int _mfd_' + tableName + '_post_request(netsnmp_mib_handler *handler, netsnmp_handle_registration *reginfo, netsnmp_agent_request_info *agtreq_info, netsnmp_request_info *requests) {\n'
            tableInterfaceString += tableName + '_rowreq_ctx *rowreq_ctx = (' + tableName + '_rowreq_ctx *)(netsnmp_container_table_row_extract(requests);\n'
            tableInterfaceString += 'int rc, packet_rc;\n'
            tableInterfaceString += 'if(rowreq_ctx && (rowreq_ctx->rowreq_flags & MFD_ROW_DELETED)) {\n'
            tableInterfaceString += tableName + '_release_rowreq_ctx(rowreq_ctx);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'if (1 != netsnmp_row_merge_status_last(reginfo, agtreq_info)) {\n'
            tableInterfaceString += 'return SNMP_ERR_NOERROR;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'packet rc = netsnmp_check_all_requests_error(agtreq_info->asp, 0);\n'
            tableInterfaceString += 'rc = ' + tableName + '+post_request(' + tableName + '_if_ctx.user_ctx, packet_rc);\n'
            tableInterfaceString += 'if(MFD_SUCCESS != rc) {\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += 'return SNMP_ERR_NOERROR;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'static int _mfd_' + tableName + '_object_lookup(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *agtreq_info, netsnmp_request_info *requests) {\n'
            tableInterfaceString += 'int rc = SNMP_ERR_NOERROR;\n'
            tableInterfaceString += tableName + '_rowreq_ctx *rowreq_ctx = (' + tableName + '_rowreq_ctx*)(netsnmp_container_table_row_extract(requests);\n'
            tableInterfaceString += 'if(NULL == rowreq_ctx) {\n'
            tableInterfaceString += 'rc = SNMP_ERR_NOCREATION;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'if(MFD_SUCCESS != rc) {\n'
            tableInterfaceString += 'netsnmp_request_set_error_all(requests, rc);\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += 'else {\n'
            tableInterfaceString += tableName + '_row_prep(rowreq_ctx);\n'
            tableInterfaceString += 'return SNMP_VALIDATE_ERR(rc);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'NETSNMP_STATIC_INLINE int _' + tableName + '_get_column(' + tableName + '_rowreq_ctx *rowreq_ctx, netsnmp_variable_list *var, int column) {\n'
            tableInterfaceString += 'int rc = SNMPERR_SUCCESS;\n'
            tableInterfaceString += 'switch(column) {\n'
            for col in self.tableRows[self.tables[tableName]['row']]['columns']:
                tableInterfaceString += 'case COLUMN_' + col['name'].upper() + ':\n'
                tableInterfaceString += 'var->val_len = sizeof(' + self.ctypeClasses[self.getSubTypeString(col['subtype'])] + ');\n'
                tableInterfaceString += 'var->type = ' + self.netsnmpTypes[self.getSubTypeString(col['subtype'])] + ';\n'
                tableInterfaceString += 'rc = ' + col['name'] + '_get(rowreq_ctx, (' + self.ctypeClasses[self.getSubTypeString(col['subtype'])] + '*)var->val.string);\n'
                tableInterfaceString += 'break;\n'
            tableInterfaceString += 'default:\n'
            tableInterfaceString += 'break;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'return rc;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'int _mfd_' + tableName + '_get_values(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *agtreq_info, netsnmp_request_info *requests) {\n'
            tableInterfaceString += tableName + '_rowreq_ctx *rowreq_ctx = (' + tableName + '_rowreq_ctx*)(netsnmp_container_table_row_extract(requests);\n'
            tableInterfaceString += 'netsnmp_table_request_info *tri;\n'
            tableInterfaceString += 'u_char *old_string;\n'
            tableInterfaceString += 'void (*dataFreeHook)(void*);\n'
            tableInterfaceString += 'int rc;\n'
            tableInterfaceString += 'for(;requets;requests = requests->next) {\n'
            tableInterfaceString += 'old_string = requests->requestvb->val.string;\n'
            tableInterfaceString += 'dataFreeHook = requests->requestvb->dataFreeHook;\n'
            tableInterfaceString += 'if (NULL == requests->requestvb->val.string) {\n'
            tableInterfaceString += 'requests->requestvb->val.string =requests->requestvb->buf;\n'
            tableInterfaceString += 'requests->requestvb->val_len = sizeof(requests->requestvb->buf);\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += 'else if (requests->requestvb->buf == requests->requestvb->val.String) {\n'
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
            tableInterfaceString += 'rc = SNMP_ERR_GENERR;\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += 'if(rc) {\n'
            tableInterfaceString += 'netsnmp_request_set_error(requests, SNMP_VALIDATE_ERR(rc));\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += 'if(old_string && (old_string != requests->requestvb->buf) && (requests->requestvb->val.string != old_string )) {\n'
            tableInterfaceString += 'if(dataFreeHook) {\n'
            tableInterfaceString += '(*dataFreHook)(old_string);\n'
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
            tableInterfaceString += 'if((NULL == cache) || (NULL == cache->magic)) {\n'
            tableInterfaceString += 'return -1;\n'
            tableInterfaceString += 'return ' + tableName + '_container_load((netsnmp_container*)cache->magic);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'static void _cache_free(netsnmp_cache *cache, void *magic) {\n'
            tableInterfaceString += 'netsnmp_container *container;\n'
            tableInterfaceString += 'if((NULL == cache) || (NULL == cache->magic)) {\n'
            tableInterfaceString += 'return;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'container = (netsnmp_container*)cache->magic;\n'
            tableInterfaceString += '_container_free(container);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'static void _container_item_free(' + tableName + '_rowreq_ctx *rowreq_ctx, void *context) {\n'
            tableInterfaceString += 'if(NULL == rowreq_ctx) {\n'
            tableInterfaceString += 'return ;\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += tableName + '_release_rowreq_ctx(rowreq_ctx);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'static void _container_free(netsnmp_container *container) {\n'
            tableInterfaceString += 'if(NULL == container) {\n'
            tableInterfaceString += 'return ;\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += tableName + '_container_free(container);\n'
            tableInterfaceString += 'CONTAINER_CLEAR(container, (netsnmp_container_obj_func *)_container_item_free, NULL);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'void _' + tableName + '_container_init(' + tableName + '_interface_ctx *if_ctx) {\n'
            tableInterfaceString += 'if_ctx->cache = netsnmp_cache_create(30, _cache_load, _cache_free, ' + tableName + '_oid, ' + tableName + '_oid_size);\n'
            tableInterfaceString += 'if(NULL == if_ctx->cache) {\n'
            tableInterfaceString += 'return;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'if_ctx->cache->flags = NETSNMP_CACHE_DONT_INVALIDATE_ON_SET;\n'
            tableInterfaceString += tableName + '_container_init(&if_ctx->container, if_ctx->cache);\n'
            tableInterfaceString += 'if(NULL == if_ctx->container) {\n'
            tableInterfaceString += 'if_ctx->container = netsnmp_container_find("' + tableName + ':table_container");\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += 'if(NULL == if_ctx->container) {\n'
            tableInterfaceString += 'return;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'if(NULL != if_ctx->cache) {\n'
            tableInterfaceString += 'if_ctx->cache->magic = (void*)if_ctx->container;\n'
            tableInterfaceString += '}\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'void _' + tableName + '_container_shutdown(' + tableName + '_interface_ctx *if_ctx) {\n'
            tableInterfaceString += tableName + '_container_shutdown(if_ctx->container);\n'
            tableInterfaceString += '_container_free(if_ctx->container);\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += tableName + '_rowreq_ctx *' + tableName + '_row_find_by_mib_index(' + tableName + '_mib_index *mib_idx) {\n'
            tableInterfaceString += tableName + '_rowreq_ctx *rowreq_ctx;\n'
            tableInterfaceString += 'oid oid_tmp[MAX_OID_LEN];\n'
            tableInterfaceString += 'netsnmp_index oid_idx;\n'
            tableInterfaceString += 'int rc;\n\n'
            tableInterfaceString += 'oid_idx.oids = oid_tmp;\n'
            tableInterfaceString += 'oid_idx.len = sizeof(oid_tmp)/sizeof(oid);\n'
            tableInterfaceString += 'rc = ' + tableName + '_index_to_oid(&oid_idx, mib_idx);\n'
            tableInterfaceString += 'if(MFD_SUCCESS != rc) {\n'
            tableInterfaceString += 'return NULL;\n'
            tableInterfaceString += '}\n\n'
            tableInterfaceString += 'rowreq_ctx = (' + tableName + '_rowreq_ctx *)CONTAINER_FIND(' + tableName + '_if_ctx.container, &oid_idx);\n'
            tableInterfaceString += 'return rowreq_ctx;\n'
            tableInterfaceString += '}\n'
            self.fileWriter.fileWrite(fileName=tableName + '_interface.c',data=tableInterfaceString)

            tableInterfaceHeaderString = '#ifndef ' + tableName.upper() + '_INTERFACE_H\n'
            tableInterfaceHeaderString += '#define ' + tableName.upper() + '_INTERFACE_H\n'
            tableInterfaceHeaderString += '#include "' + tableName + '.h"\n\n'
            tableInterfaceHeaderString += 'void _' + tableName + '_initialize_interface(' + tableName + '_registration *user_ctx, u_long flags);\n'
            tableInterfaceHeaderString += 'void _' + tableName + '_shutdown_interfce(' + tableName + '_registration *user_ctx);\n'
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
            self.fileWriter.fileWrite(fileName=tableName + '_interface.h',data=tableInterfaceHeaderString)
        return

    def genHeaderFile(self, moduleName):
        headerString = '#ifndef ' + moduleName + '_H\n'
        headerString += '#define ' + moduleName + '_H\n'
        headerString += 'void register_' + moduleName + '(void);\n'
        headerString += 'void unregister_' + moduleName + '(void);\n'
        headerString += '#endif'
        self.fileWriter.fileWrite(fileName=moduleName + '.h',data=headerString)

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
