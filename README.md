# docsis-cm-rfc2786
Test DOCSIS Cable Modem SNMPv3

This project is based on snmp4j.

Reference DOCSIS OSSI spec and RFC2786 for detail.

Steps：

1. run the app.
2. copy the public number to public number field in cable modem configuration.
3. make cable modem online using the new configuration file again.
4. the app will get device information using SNMPv3.
