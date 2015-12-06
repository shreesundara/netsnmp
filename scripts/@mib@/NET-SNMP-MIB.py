#
# PySNMP MIB module NET-SNMP-MIB (http://pysnmp.sf.net)
# ASN.1 source http://mibs.snmplabs.com:80/asn1/NET-SNMP-MIB
# Produced by pysmi-0.0.6 at Sun Dec  6 17:40:54 2015
# On host ? platform ? version ? by user ?
# Using Python version 3.4.3 (v3.4.3:9b73f1c3e601, Feb 24 2015, 22:43:06) [MSC v.1600 32 bit (Intel)]
#
( OctetString, ObjectIdentifier, Integer, ) = mibBuilder.importSymbols("ASN1", "OctetString", "ObjectIdentifier", "Integer")
( NamedValues, ) = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
( ValueRangeConstraint, ValueSizeConstraint, ConstraintsUnion, ConstraintsIntersection, SingleValueConstraint, ) = mibBuilder.importSymbols("ASN1-REFINEMENT", "ValueRangeConstraint", "ValueSizeConstraint", "ConstraintsUnion", "ConstraintsIntersection", "SingleValueConstraint")
( NotificationGroup, ModuleCompliance, ) = mibBuilder.importSymbols("SNMPv2-CONF", "NotificationGroup", "ModuleCompliance")
( Unsigned32, enterprises, MibScalar, MibTable, MibTableRow, MibTableColumn, IpAddress, ObjectIdentity, ModuleIdentity, iso, Gauge32, NotificationType, TimeTicks, MibIdentifier, Counter32, Integer32, Counter64, Bits, ) = mibBuilder.importSymbols("SNMPv2-SMI", "Unsigned32", "enterprises", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "IpAddress", "ObjectIdentity", "ModuleIdentity", "iso", "Gauge32", "NotificationType", "TimeTicks", "MibIdentifier", "Counter32", "Integer32", "Counter64", "Bits")
( DisplayString, TextualConvention, ) = mibBuilder.importSymbols("SNMPv2-TC", "DisplayString", "TextualConvention")
netSnmp = ModuleIdentity((1, 3, 6, 1, 4, 1, 8072)).setRevisions(("2002-01-30 00:00",))
netSnmpObjects = MibIdentifier((1, 3, 6, 1, 4, 1, 8072, 1))
netSnmpEnumerations = MibIdentifier((1, 3, 6, 1, 4, 1, 8072, 3))
netSnmpModuleIDs = MibIdentifier((1, 3, 6, 1, 4, 1, 8072, 3, 1))
netSnmpAgentOIDs = MibIdentifier((1, 3, 6, 1, 4, 1, 8072, 3, 2))
netSnmpDomains = MibIdentifier((1, 3, 6, 1, 4, 1, 8072, 3, 3))
netSnmpExperimental = MibIdentifier((1, 3, 6, 1, 4, 1, 8072, 9999))
netSnmpPlaypen = MibIdentifier((1, 3, 6, 1, 4, 1, 8072, 9999, 9999))
netSnmpNotificationPrefix = MibIdentifier((1, 3, 6, 1, 4, 1, 8072, 4))
netSnmpNotifications = MibIdentifier((1, 3, 6, 1, 4, 1, 8072, 4, 0))
netSnmpNotificationObjects = MibIdentifier((1, 3, 6, 1, 4, 1, 8072, 4, 1))
netSnmpConformance = MibIdentifier((1, 3, 6, 1, 4, 1, 8072, 5))
netSnmpCompliances = MibIdentifier((1, 3, 6, 1, 4, 1, 8072, 5, 1))
netSnmpGroups = MibIdentifier((1, 3, 6, 1, 4, 1, 8072, 5, 2))
mibBuilder.exportSymbols("NET-SNMP-MIB", netSnmpExperimental=netSnmpExperimental, netSnmpGroups=netSnmpGroups, netSnmpNotificationPrefix=netSnmpNotificationPrefix, netSnmpDomains=netSnmpDomains, netSnmpPlaypen=netSnmpPlaypen, netSnmpNotificationObjects=netSnmpNotificationObjects, netSnmpObjects=netSnmpObjects, netSnmp=netSnmp, netSnmpConformance=netSnmpConformance, netSnmpCompliances=netSnmpCompliances, netSnmpModuleIDs=netSnmpModuleIDs, netSnmpNotifications=netSnmpNotifications, netSnmpEnumerations=netSnmpEnumerations, PYSNMP_MODULE_ID=netSnmp, netSnmpAgentOIDs=netSnmpAgentOIDs)
