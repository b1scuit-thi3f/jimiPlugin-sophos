from plugins.sophos.includes import sophos as sophosApi
from core.models import action
from core import auth, settings, logging, helpers
import array

class _sophosEndpoint(action._action):
    endpointID = str()
    XOrganizationID = str()
    client_id = str()
    client_secret = str()
    tenant = str()

    def run(self,data,persistentData,actionResult):
        endpointID = helpers.evalString(self.endpointID,{"data" : data})
        tenant = helpers.evalString(self.tenant,{"data" : data})
        client_secret = auth.getPasswordFromENC(self.client_secret)
        actionResult["data"] = "Not yet implemented"
        actionResult["result"] = False
        actionResult["rc"] = 0
        return actionResult

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "client_secret" and not value.startswith("ENC "):
            self.client_secret = "ENC {0}".format(auth.getENCFromPassword(value))
            return True
        return super(_sophosEndpoint, self).setAttribute(attr,value,sessionData=sessionData)

class _sophosScan(action._action):
    endpointID = str()
    XOrganizationID = str()
    client_id = str()
    client_secret = str()
    tenant = str()

    def run(self,data,persistentData,actionResult):
        endpointID = helpers.evalString(self.endpointID,{"data" : data})
        tenant = helpers.evalString(self.tenant,{"data" : data})
        client_secret = auth.getPasswordFromENC(self.client_secret)
            
        sophos = sophosApi.sophos(None, self.client_id, client_secret, self.XOrganizationID)
        sophos.setTenant(tenant)
        res = sophos.postScan(endpointID)
        if res["result"]:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["data"] = res["data"]
        return actionResult

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "client_secret" and not value.startswith("ENC "):
            self.client_secret = "ENC {0}".format(auth.getENCFromPassword(value))
            return True
        return super(_sophosScan, self).setAttribute(attr,value,sessionData=sessionData)

class _sophosGetTamperProtection(action._action):
    endpointID = str()
    XOrganizationID = str()
    client_id = str()
    client_secret = str()
    tenant = str()
    invertID = bool()

    def run(self,data,persistentData,actionResult):
        endpointID = helpers.evalString(self.endpointID,{"data" : data})
        tenant = helpers.evalString(self.tenant,{"data" : data})
        client_secret = auth.getPasswordFromENC(self.client_secret)

        if self.invertID:
            byteArray = array.array("H",endpointID)
            byteArray.byteswap()
            endpointID = byteArray.tostring()

        sophos = sophosApi.sophos(None, self.client_id, client_secret, self.XOrganizationID)
        sophos.setTenant(tenant)
        res = sophos.getTamperProtection(endpointID)
        if res["result"]:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["data"] = res["data"]
            actionResult["msg"] = "Tamper protection password found"
        else:
            actionResult["rc"] = 404
            actionResult["msg"] = res["data"]["message"]
        return actionResult
        
    def setAttribute(self,attr,value,sessionData=None):
        if attr == "client_secret" and not value.startswith("ENC "):
            self.client_secret = "ENC {0}".format(auth.getENCFromPassword(value))
            return True
        return super(_sophosGetTamperProtection, self).setAttribute(attr,value,sessionData=sessionData)

class _sophosSetTamperProtection(action._action):
    endpointID = str()
    XOrganizationID = str()
    client_id = str()
    client_secret = str()
    tenant = str()
    enable_protection = True
    regenerate_password = True

    def run(self,data,persistentData,actionResult):
        endpointID = helpers.evalString(self.endpointID,{"data" : data})
        tenant = helpers.evalString(self.tenant,{"data" : data})
        client_secret = auth.getPasswordFromENC(self.client_secret)

        sophos = sophosApi.sophos(None, self.client_id, client_secret, self.XOrganizationID)
        sophos.setTenant(tenant)
        res = sophos.postTamperProtection(endpointID, {"enabled": self.enable_protection, "regeneratePassword": self.regenerate_password})
        if res["result"]:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["data"] = res["data"]
        return actionResult
                    
    def setAttribute(self,attr,value,sessionData=None):
        if attr == "client_secret" and not value.startswith("ENC "):
            self.client_secret = "ENC {0}".format(auth.getENCFromPassword(value))
            return True
        return super(_sophosSetTamperProtection, self).setAttribute(attr,value,sessionData=sessionData)