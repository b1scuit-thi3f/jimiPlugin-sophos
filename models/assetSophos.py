import re
import datetime

from plugins.sophos.includes import sophos
from core.models import trigger, webui
from core import settings, logging, auth

certSettings = settings.config["sophos"]

class _assetSophos(trigger._trigger):  
    filters = list()
    XOrganizationID = str()
    client_id = str()
    client_secret = str()
    tenants = list()

    def check(self):
        if not hasattr(self,"client_secret_plain"):
            self.client_secret_plain = auth.getPasswordFromENC(self.client_secret)
        sophosAPI = sophos.sophos(certSettings["ca"],self.client_id,self.client_secret_plain,self.XOrganizationID)
        self.filters.append("view=full")
        for tenant in self.tenants:
            computers = []
            if sophosAPI.setTenant(tenant):
                computers = sophosAPI.getEndpoints(filters=self.filters)
            if computers["result"]:
                for computer in computers["data"]:
                    result = {}

                    # Name
                    if "hostname" in computer:
                        result["name"] = computer["hostname"].lower()

                        # LastSeen converted to epoch
                        if "lastSeenAt" in computer:
                            result["lastSeen"] = int(datetime.datetime.strptime(computer["lastSeenAt"],"%Y-%m-%dT%H:%M:%S.%fZ").timestamp()*1000)

                            # OS
                            if "os" in computer:
                                if "platform" in computer["os"]:
                                    result["platform"] = computer["os"]["platform"].lower()
                                    if result["platform"] == "windows":
                                        if "name" in computer["os"]:
                                            os = re.search('(.*) ((pro|enterprise|standard|datacenter))', computer["os"]["name"], re.IGNORECASE)
                                            if os:
                                                result["operatingSystem"] = os.group(1).lower()
                                                result["operatingSystemEdition"] = os.group(2).lower()
                                        if "build" in computer["os"]:
                                            result["operatingSystemBuild"] =  computer["os"]["build"]
                                        if "majorVersion" in computer["os"] and "minorVersion" in computer["os"]:
                                            result["operatingSystemVersion"] =  "{0}.{1}".format(computer["os"]["majorVersion"],computer["os"]["minorVersion"])
                                    elif result["platform"] == "linux":
                                        if "name" in computer["os"]:
                                            os = re.search('(.*) ((pro|enterprise|standard|datacenter)).*([0-9]\.[0-9]*)', computer["os"]["name"], re.IGNORECASE)
                                            if os:
                                                result["operatingSystem"] = os.group(1).lower()
                                                result["operatingSystemEdition"] = os.group(2).lower()
                                                result["operatingSystemVersion"] = os.group(2)
                                    elif result["platform"] == "macOS":
                                        result["operatingSystem"] = result["platform"]
                                        if "majorVersion" in computer["os"] and "minorVersion" in computer["os"]:
                                            result["operatingSystemVersion"] =  "{0}.{1}".format(computer["os"]["majorVersion"],computer["os"]["minorVersion"])
                                        if "build" in computer["os"]:
                                            result["operatingSystemBuild"] =  computer["os"]["build"]

                            # IP
                            if "ipv4Addresses" in computer:
                                if type(computer["ipv4Addresses"]) is list:
                                    result["src_ip"] = computer["ipv4Addresses"][0]
                        
                            # User
                            if "associatedPerson" in computer:
                                if "viaLogin" in computer["associatedPerson"]:
                                    if "\\" in computer["associatedPerson"]["viaLogin"]:
                                        userInfo = re.search('(.*)\\\\(.*)', computer["associatedPerson"]["viaLogin"], re.IGNORECASE)
                                        if userInfo:
                                            user = userInfo.group(2)
                                            domain = userInfo.group(1)
                                    else:
                                        user = computer["associatedPerson"]["viaLogin"]
                                    result["user"] = user.lower()
                                    result["domain"] = domain.lower()

                            # Estate
                            result["estate"] = tenant

                            # Other Sophos Values
                            if "tamperProtectionEnabled" in computer:
                                result["tamperProtection"] = computer["tamperProtectionEnabled"]
                            versions = {}
                            if "assignedProducts" in computer:
                                for product in computer["assignedProducts"]:
                                    if product["status"] == "installed":
                                        versions[product["code"]] = product["version"]
                            result["versions"] = versions
                            if "health" in computer:
                                result["health"] = computer["health"]["overall"]

                            result["sophos_id"] = computer["id"]
                        
                            self.result["events"].append(result)
        

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "client_secret" and not value.startswith("ENC "):
            self.client_secret = "ENC {0}".format(auth.getENCFromPassword(value))
            return True
        return super(_assetSophos, self).setAttribute(attr,value,sessionData)