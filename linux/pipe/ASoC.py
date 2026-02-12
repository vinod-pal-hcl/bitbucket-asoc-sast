import requests
import urllib3
import time
import subprocess
import datetime
import io
import sys
import os
import json

# Disable SSL warnings when bypassing certificate verification
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ASoC:
    def __init__(self, apikey, datacenter="NA", allow_untrusted=False):
        self.apikey = apikey
        self.token = ""
        self.allow_untrusted = allow_untrusted
        if datacenter == "EU":
            self.base_url = "https://eu.cloud.appscan.com"
        elif datacenter == "NA":
            self.base_url = "https://cloud.appscan.com"
        else:
            self.base_url = datacenter
    
    def getDataCenterURL(self):
        return self.base_url
    
    def login(self):
        if self.allow_untrusted:
            resp = requests.post(f"{self.base_url}/api/v4/Account/ApiKeyLogin", json=self.apikey, verify=False)
        else:
            resp = requests.post(f"{self.base_url}/api/v4/Account/ApiKeyLogin", json=self.apikey)
        if(resp.status_code == 200):
            jsonObj = resp.json()
            self.token = jsonObj["Token"]
            return True
        else:
            return False
        
    def logout(self):
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        if self.allow_untrusted:
            resp = requests.get(f"{self.base_url}/api/v4/Account/Logout", headers=headers, verify=False)
        else:
            resp = requests.get(f"{self.base_url}/api/v4/Account/Logout", headers=headers)
        if(resp.status_code == 200):
            self.token = ""
            return True
        else:
            return False
        
    def checkAuth(self):
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        if self.allow_untrusted:
            resp = requests.get(f"{self.base_url}/api/v4/Account/TenantInfo", headers=headers, verify=False)
        else:
            resp = requests.get(f"{self.base_url}/api/v4/Account/TenantInfo", headers=headers)
        return resp.status_code == 200
    
    def generateIRX(self, scanName, scan_flag, appscanBin, stdoutFilePath = "", configFile=None, secret_scanning=None, printio=True, scan_speed=""):
        #Build scan arguments
        args = [appscanBin, "prepare", "-n", scanName]
        if configFile:
            args.extend(["-c", configFile])
        if secret_scanning is not None:
            if secret_scanning == False:
                args.append("--noSecrets")
            elif secret_scanning == True:
                args.append("--enableSecrets")
        if scan_flag is not None:
            args.append(scan_flag)
        if scan_speed != "":
            args.extend(["-s", scan_speed])
        
        stdoutFile = os.path.join(stdoutFilePath, scanName+'_stdout.txt')
        
        with io.open(stdoutFile, 'wb') as writer:
            process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1)
            for line in iter(process.stdout.readline, b''):
                writer.write(line)
                if printio:
                    sys.stdout.write(line.decode('ascii'))
                    sys.stdout.flush()
            process.wait()
        if(printio):
            print()
        irxPath = scanName + ".irx"
        if(os.path.exists(irxPath)):
            return irxPath
        else:
            return None
            
    def uploadFile(self, filePath):
        #files = {'name': (<filename>, <file object>, <content type>, <per-part headers>)}
        fileName = os.path.basename(filePath)
        files = {
            "uploadedFile": (fileName, open(filePath, 'rb'), 'application/octet-stream'),
            "fileName": (None, fileName)
        }
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        if self.allow_untrusted:
            resp = requests.post(f"{self.base_url}/api/v4/FileUpload", headers=headers, files=files, verify=False)
        else:
            resp = requests.post(f"{self.base_url}/api/v4/FileUpload", headers=headers, files=files)
        if(resp.status_code == 200):
            fileId = resp.json()["FileId"]
            return fileId
        return None
    
    def createSastScan(self, scanName, appId, irxFileId, comment="", personal=False):
        data = {
            "ScanName": scanName,
            "AppId": appId,
            "Comment": comment,
            "ApplicationFileId": irxFileId,
            "Personal": personal
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        if self.allow_untrusted:
            resp = requests.post(f"{self.base_url}/api/v4/Scans/Sast/", headers=headers, json=data, verify=False)
        else:
            resp = requests.post(f"{self.base_url}/api/v4/Scans/Sast/", headers=headers, json=data)
        if(resp.status_code != 201):
            print(f"Error submitting scan")
            print(resp.json())
        if(resp.status_code == 201):
            scanId = resp.json()["Id"]
            return scanId
            
        return None

    def createScaScan(self, scanName, appId, irxFileId, comment="", personal=False):
        data = {
            "ScanName": scanName,
            "AppId": appId,
            "Comment": comment,
            "ApplicationFileId": irxFileId,
            "Personal": personal
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        if self.allow_untrusted:
            resp = requests.post(f"{self.base_url}/api/v4/Scans/Sca/", headers=headers, json=data, verify=False)
        else:
            resp = requests.post(f"{self.base_url}/api/v4/Scans/Sca/", headers=headers, json=data)
        if(resp.status_code != 201):
            print(f"Error submitting scan")
            print(resp.json())
        if(resp.status_code == 201):
            scanId = resp.json()["Id"]
            return scanId
            
        return None
    
    def getScanStatus(self, scanId):
        """Get scan execution status and details using the Executions endpoint.
        
        Returns the latest execution object which includes:
        - Status: The scan status (Running, Ready, Abort, etc.)
        - All summary data (NIssuesFound, NCriticalIssues, NHighIssues, etc.)
        
        Returns None on error.
        """
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        url = f"{self.base_url}/api/v4/Scans/{scanId}/Executions?%24top=1&%24count=false"
        if self.allow_untrusted:
            resp = requests.get(url, headers=headers, verify=False)
        else:
            resp = requests.get(url, headers=headers)
        if(resp.status_code == 200):
            executions = resp.json()
            if executions and len(executions) > 0:
                return executions[0]
            return None
        else:
            print(f"ASoC Report Status")
            print(resp)
            return None
            
    def getApplication(self, id):
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        if self.allow_untrusted:
            resp = requests.get(f"{self.base_url}/api/v4/Apps/", headers=headers, verify=False)
        else:
            resp = requests.get(f"{self.base_url}/api/v4/Apps/", headers=headers)
        if(resp.status_code == 200):
            app_info = self.checkAppExists(resp.json(), id)
            return app_info
        else:
            print(f"ASoC App Summary Error Response")
            return None

    def checkAppExists(self, response, id):
        for item in response['Items']:
            if item['Id'] == id:
                return item  
        return None  

    def SastScanSummary(self, id, is_execution=False):
        if(is_execution):
            asoc_url = f"{self.base_url}/api/v4/Scans/SastExecution/"
        else:
            asoc_url = f"{self.base_url}/api/v4/Scans/Sast/"
        
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        
        if self.allow_untrusted:
            resp = requests.get(asoc_url+id, headers=headers, verify=False)
        else:
            resp = requests.get(asoc_url+id, headers=headers)
        
        if(resp.status_code == 200):
            return resp.json()
        else:
            print(resp.status_code)
            print(resp.text)
            return None
        
    def ScaScanSummary(self, id, is_execution=False):
        if(is_execution):
            asoc_url = f"{self.base_url}/api/v4/Scans/ScaExecution/"
        else:
            asoc_url = f"{self.base_url}/api/v4/Scans/Sca/"
        
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        
        if self.allow_untrusted:
            resp = requests.get(asoc_url+id, headers=headers, verify=False)
        else:
            resp = requests.get(asoc_url+id, headers=headers)
        
        if(resp.status_code == 200):
            return resp.json()
        else:
            print(resp.status_code)
            print(resp.text)
            return None
        
    def startReport(self, id, reportConfig):
        url = f"{self.base_url}/api/v4/Reports/Security/Scan/"+id
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        if self.allow_untrusted:
            resp = requests.post(url, headers=headers, json=reportConfig, verify=False)
        else:
            resp = requests.post(url, headers=headers, json=reportConfig)
        if(resp.status_code == 200):
            return resp.json()["Id"]
        else:
            return None
        
    def reportStatus(self, reportId):
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        if self.allow_untrusted:
            resp = requests.get(f"{self.base_url}/api/v4/Reports?filter=Id%20eq%20"+reportId, headers=headers, verify=False)
        else:
            resp = requests.get(f"{self.base_url}/api/v4/Reports?filter=Id%20eq%20"+reportId, headers=headers)
        if(resp.status_code == 200):
            return resp.json()
        else:
            return {"Status": "Abort", "Progress": 0}
            
    def waitForReport(self, reportId, intervalSecs=3, timeoutSecs=60):
        status = None
        elapsed = 0
        while status not in ["Abort","Ready"] or elapsed >= timeoutSecs:
            status = self.reportStatus(reportId)
            elapsed += intervalSecs
            time.sleep(intervalSecs)   
        return status == "Ready"
        
    def downloadReport(self, reportId, fullPath):
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        if self.allow_untrusted:
            resp = requests.get(f"{self.base_url}/api/v4/Reports/"+reportId+"/Download", headers=headers, verify=False)
        else:
            resp = requests.get(f"{self.base_url}/api/v4/Reports/"+reportId+"/Download", headers=headers)
        if(resp.status_code==200):
            report_bytes = resp.content
            with open(fullPath, "wb") as f:
                f.write(report_bytes)
            return True
        else:
            return False
    
    #Get current system timestamp
    def getTimeStamp(self):
        ts = time.time()
        return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d_%H-%M-%S')
    
        
    
    
        
        