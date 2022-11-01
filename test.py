from urllib.request import urlopen
from xml.etree.ElementTree import ElementTree, parse
import sys
import ssl

def xml_from_url(url:str)->ElementTree:
    ssl._create_default_https_context = ssl._create_unverified_context
    try:
        return xml_parse(urlopen(url))
    except Exception as e:
        print(e)
        print("error while opening url: "+url)
        sys.exit(1)
    

def xml_parse(target)->ElementTree:
    try:
        return parse(target)
    except:
        print("error while parsing xml from: "+target)
        sys.exit(2)

tree = xml_from_url(sys.argv[1])
for child in list(tree.getroot()):
    print(child.tag)