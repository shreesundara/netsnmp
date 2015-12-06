#
# PySNMP MIB module NET-SNMP-TUTORIAL-MIB (http://pysnmp.sf.net)
# ASN.1 source file://\Users\Avinash\Documents\pysmi-0.0.6\scripts\@mib@\NET-SNMP-TUTORIAL-MIB.txt
# Produced by pysmi-0.0.6 at Sun Dec  6 17:40:54 2015
# On host ? platform ? version ? by user ?
# Using Python version 3.4.3 (v3.4.3:9b73f1c3e601, Feb 24 2015, 22:43:06) [MSC v.1600 32 bit (Intel)]
#
( OctetString, ObjectIdentifier, Integer, ) = mibBuilder.importSymbols("ASN1", "OctetString", "ObjectIdentifier", "Integer")
( NamedValues, ) = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
( ValueRangeConstraint, ValueSizeConstraint, ConstraintsUnion, ConstraintsIntersection, SingleValueConstraint, ) = mibBuilder.importSymbols("ASN1-REFINEMENT", "ValueRangeConstraint", "ValueSizeConstraint", "ConstraintsUnion", "ConstraintsIntersection", "SingleValueConstraint")
( netSnmpExamples, ) = mibBuilder.importSymbols("NET-SNMP-EXAMPLES-MIB", "netSnmpExamples")
( NotificationGroup, ObjectGroup, ModuleCompliance, ) = mibBuilder.importSymbols("SNMPv2-CONF", "NotificationGroup", "ObjectGroup", "ModuleCompliance")
( Unsigned32, MibScalar, MibTable, MibTableRow, MibTableColumn, IpAddress, ObjectIdentity, ModuleIdentity, iso, Gauge32, NotificationType, TimeTicks, MibIdentifier, Counter32, Integer32, Counter64, Bits, ) = mibBuilder.importSymbols("SNMPv2-SMI", "Unsigned32", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "IpAddress", "ObjectIdentity", "ModuleIdentity", "iso", "Gauge32", "NotificationType", "TimeTicks", "MibIdentifier", "Counter32", "Integer32", "Counter64", "Bits")
( DisplayString, TextualConvention, ) = mibBuilder.importSymbols("SNMPv2-TC", "DisplayString", "TextualConvention")
netSnmpTutorialMIB = ModuleIdentity((1, 3, 6, 1, 4, 1, 8072, 2, 4))
nstMIBObjects = MibIdentifier((1, 3, 6, 1, 4, 1, 8072, 2, 4, 1))
nstMIBConformance = MibIdentifier((1, 3, 6, 1, 4, 1, 8072, 2, 4, 2))
nstAgentModules = MibIdentifier((1, 3, 6, 1, 4, 1, 8072, 2, 4, 1, 1))
nstAgentModuleObject = MibScalar((1, 3, 6, 1, 4, 1, 8072, 2, 4, 1, 1, 1), Integer32().clone(1)).setMaxAccess("readwrite")
nstAgentSubagentObject = MibScalar((1, 3, 6, 1, 4, 1, 8072, 2, 4, 1, 1, 2), Integer32().clone(2)).setMaxAccess("readwrite")
nstAgentPluginObject = MibScalar((1, 3, 6, 1, 4, 1, 8072, 2, 4, 1, 1, 3), Integer32().clone(3)).setMaxAccess("readwrite")
mibBuilder.exportSymbols("NET-SNMP-TUTORIAL-MIB", netSnmpTutorialMIB=netSnmpTutorialMIB, nstAgentSubagentObject=nstAgentSubagentObject, nstAgentModuleObject=nstAgentModuleObject, nstMIBConformance=nstMIBConformance, nstAgentPluginObject=nstAgentPluginObject, nstMIBObjects=nstMIBObjects, PYSNMP_MODULE_ID=netSnmpTutorialMIB, nstAgentModules=nstAgentModules)
