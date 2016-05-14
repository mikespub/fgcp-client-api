# Client API library for the Fujitsu Global Cloud Platform (FGCP) #
using XML-RPC API Version 2015-01-30

---

## Using this library ##
If you already have access to the Fujitsu Global Cloud Platform (FGCP), have a look at the demo script:

> `Usage: fgcp_demo.py [pem_file] [region]`

If not, register on one of the Service Portals from the list below. Afterwards, you can access your resources via command-line scripts, web interfaces etc. as you prefer.

```
# Connect with your client certificate to region 'uk'
from fgcp.resource import FGCPVDataCenter
vdc = FGCPVDataCenter('client.pem', 'uk')

# Do typical actions on resources
vsystem = vdc.get_vsystem('Demo System')
vsystem.show_status()
#for vserver in vsystem.vservers:
#    result = vserver.backup(wait=True)
#...
# See tests/test_resource.py for more examples
```

Note: this client API library provides higher-level [Client Methods](https://github.com/mikespub/fgcp-client-api/wiki/ClientMethods), intermediate [Resource Actions](https://github.com/mikespub/fgcp-client-api/wiki/ResourceActions) and lower-level [API Commands](https://github.com/mikespub/fgcp-client-api/wiki/APICommands).


---

## Fujitsu Global Cloud Platform (FGCP) ##

![http://mikespub.net/fgcp_client_api.png](http://mikespub.net/fgcp_client_api.png)

Service Portal
  * for Australia and New Zealand: http://globalcloud.fujitsu.com.au/
  * for Central Europe (CEMEA&I): http://globalcloud.de.fujitsu.com/
  * for Japan: http://oviss.jp.fujitsu.com/
  * for Singapore, Malaysia, Indonesia, Thailand and Vietnam: http://globalcloud.sg.fujitsu.com/
  * for the UK and Ireland: http://globalcloud.uk.fujitsu.com/
  * for the Americas: http://globalcloud.us.fujitsu.com/


---

## Requirements ##
This module uses tlslite.utils or gdata.tlslite.utils to create the key signature, see https://pypi.python.org/pypi/tlslite-ng or https://pypi.python.org/pypi/tlslite for download and installation

Note: to convert your .p12 or .pfx file to unencrypted PEM format, you can use
the following 'openssl' command:
```
openssl pkcs12 -in UserCert.p12 -out client.pem -nodes
```
