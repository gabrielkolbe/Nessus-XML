#!C:/Users/Gabriel/AppData/Local/Programs/Python/Python37-32/python.exe
# on windows machine
print ("Content-Type: text/html\n")
# to run in browser on xampp

from sys import argv
import xml.etree.ElementTree as ET

f = open('nessus.xml', 'r')
xml_content = f.read()
f.close()

tree = ET.fromstring(xml_content)
#tree = ET.parse(xml_content)

# XML structure:
# 
# <NessusClientData_v2>
# <Report name="Win NT 4.0" xmlns:cm="http://www.nessus.org/cm">
# <ReportHost name="myscan">
# ......
# <ReportItem port="139" svc_name="smb" protocol="tcp" severity="4" pluginID="34477" pluginName="MS08-067: Microsoft Windows Server Service Crafted RPC Request Handling Remote Code Execution (958644) (ECLIPSEDWING) (uncredentialed check)" pluginFamily="Windows">
# ......
# <plugin_name>MS08-067: Microsoft Windows Server Service Crafted RPC Request Handling Remote Code Execution (958644) (ECLIPSEDWING) (uncredentialed check)</plugin_name>
# <plugin_publication_date>2008/10/23</plugin_publication_date>
# <plugin_type>local</plugin_type>
# <risk_factor>Critical</risk_factor>
# ......
# <xref>CWE:94</xref>
# </ReportItem>
# <ReportItem port="139" svc_name="smb" protocol="tcp" severity="0" pluginID="106716" pluginName="Microsoft Windows SMB2 Dialects Supported (remote check)" pluginFamily="Windows">
# ......
# </ReportHost>
# </Report>
# </NessusClientData_v2>

for host in tree.findall('Report/ReportHost'):
  ipaddr = host.find("HostProperties/tag/[@name='host-ip']").text

  for item in host.findall('ReportItem'):
    risk_factor = item.find('risk_factor').text
    pluginID = item.get('pluginID')
    pluginName = item.get('pluginName')
    port = item.get('port')
    protocol = item.get('protocol')
  
    print(
      ipaddr + ',' + \
      risk_factor + ',' + \
      port + '/' + protocol + ',' + \
      pluginID + ',' + \
      '"' + pluginName + '"'
    )

