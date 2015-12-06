#
# PySNMP MIB module INET-ADDRESS-MIB (http://pysnmp.sf.net)
# ASN.1 source http://mibs.snmplabs.com:80/asn1/INET-ADDRESS-MIB
# Produced by pysmi-0.0.6 at Sun Dec  6 17:40:54 2015
# On host ? platform ? version ? by user ?
# Using Python version 3.4.3 (v3.4.3:9b73f1c3e601, Feb 24 2015, 22:43:06) [MSC v.1600 32 bit (Intel)]
#
( OctetString, ObjectIdentifier, Integer, ) = mibBuilder.importSymbols("ASN1", "OctetString", "ObjectIdentifier", "Integer")
( NamedValues, ) = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
( ValueRangeConstraint, ValueSizeConstraint, ConstraintsUnion, ConstraintsIntersection, SingleValueConstraint, ) = mibBuilder.importSymbols("ASN1-REFINEMENT", "ValueRangeConstraint", "ValueSizeConstraint", "ConstraintsUnion", "ConstraintsIntersection", "SingleValueConstraint")
( NotificationGroup, ModuleCompliance, ) = mibBuilder.importSymbols("SNMPv2-CONF", "NotificationGroup", "ModuleCompliance")
( Unsigned32, MibScalar, MibTable, MibTableRow, MibTableColumn, mib_2, IpAddress, ObjectIdentity, ModuleIdentity, iso, Gauge32, NotificationType, TimeTicks, MibIdentifier, Counter32, Integer32, Counter64, Bits, ) = mibBuilder.importSymbols("SNMPv2-SMI", "Unsigned32", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "mib-2", "IpAddress", "ObjectIdentity", "ModuleIdentity", "iso", "Gauge32", "NotificationType", "TimeTicks", "MibIdentifier", "Counter32", "Integer32", "Counter64", "Bits")
( TextualConvention, DisplayString, ) = mibBuilder.importSymbols("SNMPv2-TC", "TextualConvention", "DisplayString")
inetAddressMIB = ModuleIdentity((1, 3, 6, 1, 2, 1, 76)).setRevisions(("2005-02-04 00:00", "2002-05-09 00:00", "2000-06-08 00:00",))
class InetAddressType(Integer32, TextualConvention):
    subtypeSpec = Integer32.subtypeSpec+ConstraintsUnion(SingleValueConstraint(0, 1, 2, 3, 4, 16,))
    namedValues = NamedValues(("unknown", 0), ("ipv4", 1), ("ipv6", 2), ("ipv4z", 3), ("ipv6z", 4), ("dns", 16),)

class InetAddress(OctetString, TextualConvention):
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(0,255)

class InetAddressIPv4(OctetString, TextualConvention):
    displayHint = '1d.1d.1d.1d'
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(4,4)
    fixedLength = 4

class InetAddressIPv6(OctetString, TextualConvention):
    displayHint = '2x:2x:2x:2x:2x:2x:2x:2x'
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(16,16)
    fixedLength = 16

class InetAddressIPv4z(OctetString, TextualConvention):
    displayHint = '1d.1d.1d.1d%4d'
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(8,8)
    fixedLength = 8

class InetAddressIPv6z(OctetString, TextualConvention):
    displayHint = '2x:2x:2x:2x:2x:2x:2x:2x%4d'
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(20,20)
    fixedLength = 20

class InetAddressDNS(OctetString, TextualConvention):
    displayHint = '255a'
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(1,255)

class InetAddressPrefixLength(Unsigned32, TextualConvention):
    displayHint = 'd'
    subtypeSpec = Unsigned32.subtypeSpec+ValueRangeConstraint(0,2040)

class InetPortNumber(Unsigned32, TextualConvention):
    displayHint = 'd'
    subtypeSpec = Unsigned32.subtypeSpec+ValueRangeConstraint(0,65535)

class InetAutonomousSystemNumber(Unsigned32, TextualConvention):
    displayHint = 'd'

class InetScopeType(Integer32, TextualConvention):
    subtypeSpec = Integer32.subtypeSpec+ConstraintsUnion(SingleValueConstraint(1, 2, 3, 4, 5, 8, 14,))
    namedValues = NamedValues(("interfaceLocal", 1), ("linkLocal", 2), ("subnetLocal", 3), ("adminLocal", 4), ("siteLocal", 5), ("organizationLocal", 8), ("global", 14),)

class InetZoneIndex(Unsigned32, TextualConvention):
    displayHint = 'd'

class InetVersion(Integer32, TextualConvention):
    subtypeSpec = Integer32.subtypeSpec+ConstraintsUnion(SingleValueConstraint(0, 1, 2,))
    namedValues = NamedValues(("unknown", 0), ("ipv4", 1), ("ipv6", 2),)

mibBuilder.exportSymbols("INET-ADDRESS-MIB", InetAddressPrefixLength=InetAddressPrefixLength, InetAddressIPv4z=InetAddressIPv4z, InetZoneIndex=InetZoneIndex, InetAddressIPv4=InetAddressIPv4, inetAddressMIB=inetAddressMIB, InetVersion=InetVersion, InetAddressIPv6=InetAddressIPv6, InetAddress=InetAddress, InetPortNumber=InetPortNumber, InetScopeType=InetScopeType, InetAddressType=InetAddressType, InetAddressDNS=InetAddressDNS, PYSNMP_MODULE_ID=inetAddressMIB, InetAutonomousSystemNumber=InetAutonomousSystemNumber, InetAddressIPv6z=InetAddressIPv6z)
