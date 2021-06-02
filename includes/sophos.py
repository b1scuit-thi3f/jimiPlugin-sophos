import requests
import time
from datetime import datetime, timedelta
from pathlib import Path

class sophos():
    def __init__(self,ca,client_id,client_secret,XOrganizationID):
        if ca:
            self.ca = Path(ca)
        else:
            self.ca = None
        self.url = "https://api.central.sophos.com/"
        self.jwtToken = requests.post("https://id.sophos.com/api/v2/oauth2/token", headers={"Content-Type":"application/x-www-form-urlencoded"}, data={"grant_type":"client_credentials","client_id":client_id,"client_secret":client_secret,"scope":"token"})
        if self.jwtToken.status_code == 200:
            self.jwtToken = self.jwtToken.json()['access_token']
        self.standardHeaders = {"Authorization" : f"Bearer {self.jwtToken}", "X-Organization-ID" : XOrganizationID}
        self.tenants = self.getData("organization","tenants")["data"]
        if "items" in self.tenants:
            self.tenants = self.tenants['items']
        else:
            self.tenants = []
        self.standardHeaders.pop("X-Organization-ID")

    def setTenant(self,tenant):
        if tenant.lower() in [x['name'].lower() for x in self.tenants]:
            selectedTenant = [x for x in self.tenants if x['name'].lower() == tenant.lower()][0]
            self.url = selectedTenant['apiHost']
            self.standardHeaders['X-Tenant-ID'] = selectedTenant['id']
            return True
        return False

    def getData(self,api,request,params=[]):
        request = requests.get("{}/{}/v1/{}?{}".format(self.url,api,request,'&'.join(params)),headers=self.standardHeaders)
        if request.status_code != 200:
            return {"result":False,"data":request.json()}
        else:
            return {"result":True,"data":request.json()}

    def deleteData(self,api,request,params=[]):
        request = requests.delete("{}/{}/v1/{}?{}".format(self.url,api,request,'&'.join(params)),headers=self.standardHeaders)
        if request.status_code != 200:
            return {"result":False,"data":request.json()}
        else:
            return {"result":True,"data":request.json()}

    def postJson(self,api,request,json={}):
        request = requests.post("{}/{}/v1/{}".format(self.url,api,request), json=json, headers=self.standardHeaders)
        if request.status_code != 201:
            return {"result":False,"data":request.json()}
        else:
            return {"result":True,"data":request.json()}

    def getPagedData(self,api,request,pageSize,params=[]):
        items = []
        params.append("pageTotal=True")
        response = requests.get("{}/{}/v1/{}?{}".format(self.url,api,request,'&'.join(params+["pageSize=1"])),headers=self.standardHeaders)
        if response.status_code == 200:
            response = response.json()
            if 'items' in response:
                items = response['items']
                if 'nextKey' in response['pages']:
                    nextKey = response['pages']['nextKey']
                    params.append("pageSize={}".format(pageSize))
                    while len(items) < response['pages']['total']:
                        nextRequest = requests.get("{}/{}/v1/{}?{}".format(self.url,api,request,'&'.join(["pageFromKey={}".format(nextKey)]+params)),headers=self.standardHeaders)
                        if nextRequest.status_code != 200:
                            return {"result":True,"data":items}
                        nextResponse = nextRequest.json()
                        if 'items' in nextResponse:
                            items.extend(nextResponse['items'])
                            if 'nextKey' in nextResponse['pages']:
                                nextKey = nextResponse['pages']['nextKey']
                            else:
                                break
                        else:
                            break
                        time.sleep(1)
            return {"result":True,"data":items}
        else:
            return {"result":False,"data":request.json()}

    def getAlerts(self,filters=[],startTime=24):
        startDate = "{}.000Z".format((datetime.now() - timedelta(hours=startTime)).strftime("%Y-%m-%dT%H:%M:%S"))
        filters.append(startDate)
        alerts = self.getPagedData("common","alerts",100,filters)
        return alerts

    def getEndpoints(self,filters=[]):
        endpoints = self.getPagedData("endpoint","endpoints",500,filters)
        return endpoints

    def getEndpoint(self,endpointID):
        return self.getData("endpoint","endpoints/{}".format(endpointID))

    def deleteEndpoint(self,endpointID):
        return self.deleteData("endpoint","endpoints/{}".format(endpointID))

    def postScan(self, endpointID):
        return self.postJson("endpoint", "endpoints/" + endpointID + "/scans", {})

    def getTamperProtection(self, endpointID):
        return self.getData("endpoint", "endpoints/" + endpointID + "/tamper-protection")

    def postTamperProtection(self, endpointID, params={'enabled': True, 'regeneratePassword': True}):
        return self.postJson("endpoint", "endpoints/" + endpointID + "/tamper-protection", params)