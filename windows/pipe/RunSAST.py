from bitbucket_pipes_toolkit import Pipe, get_logger
from ASoC import ASoC
import requests
import urllib3
import socket
import os
import json
import time
import zipfile
import re
import datetime
import shutil

# Disable SSL warnings when bypassing certificate verification
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = get_logger()

schema = {
    'SCAN_NAME': {'type': 'string', 'required': False, 'default': "HCL_ASoC_SAST"},
    'DATACENTER': {'type': 'string', 'required': False, 'default': "NA"},
    'SECRET_SCANNING': {'type': 'boolean', 'required': False, 'default': None},
    'CONFIG_FILE_PATH': {'type': 'string', 'required': False, 'default': ""},
    'REPO': {'type': 'string', 'required': False, 'default': ""},
    'BUILD_NUM': {'type': 'number', 'required': False, 'default': 0},
    'API_KEY_ID': {'type': 'string', 'required': True},
    'API_KEY_SECRET': {'type': 'string', 'required': True},
    'APP_ID': {'type': 'string', 'required': True},
    'TARGET_DIR': {'type': 'string', 'required': True, 'default': './'},
    'DEBUG': {'type': 'boolean', 'required': False, 'default': False},
    'STATIC_ANALYSIS_ONLY': {'type': 'boolean', 'required': False, 'default': False},
    'OPEN_SOURCE_ONLY': {'type': 'boolean', 'required': False, 'default': False},
    'ALLOW_UNTRUSTED': {'type': 'boolean', 'required': False, 'default': False},
    'SCAN_SPEED': {'type': 'string', 'required': False, 'default': ""},
    'PERSONAL_SCAN': {'type': 'boolean', 'required': False, 'default': False},
    'WAIT_FOR_ANALYSIS': {'type': 'boolean', 'required': False, 'default': True},
    'FAIL_FOR_NONCOMPLIANCE': {'type': 'boolean', 'required': False, 'default': False},
    'FAILURE_THRESHOLD': {'type': 'string', 'required': False, 'default': 'Low'}
}

class AppScanOnCloudSAST(Pipe):
    asoc = None
    
    #Run SAST Scan Process
    def run(self):
        super().run()
        env = dict(os.environ)
        scanName = self.get_variable('SCAN_NAME')
        apikeyid = self.get_variable('API_KEY_ID')
        apikeysecret = self.get_variable('API_KEY_SECRET')
        self.appID = self.get_variable('APP_ID')
        self.datacenter = self.get_variable('DATACENTER')
        self.debug = self.get_variable('DEBUG')
        self.cloneDir = self.get_variable('TARGET_DIR')
        self.secret_scanning = self.get_variable('SECRET_SCANNING')
        buildNum = self.get_variable('BUILD_NUM')
        self.static_analysis_only = self.get_variable('STATIC_ANALYSIS_ONLY')
        self.open_source_only = self.get_variable('OPEN_SOURCE_ONLY')
        self.scan_speed = self.get_variable('SCAN_SPEED')
        self.personal_scan = self.get_variable('PERSONAL_SCAN')
        self.wait_for_analysis = self.get_variable('WAIT_FOR_ANALYSIS')
        self.fail_for_noncompliance = self.get_variable('FAIL_FOR_NONCOMPLIANCE')
        self.failure_threshold = self.get_variable('FAILURE_THRESHOLD')
        self.repo = env.get('BITBUCKET_REPO_SLUG', "")
        self.repo_full_name = env.get('BITBUCKET_REPO_FULL_NAME', "")
        branch = env.get('BITBUCKET_BRANCH', "")
        self.commit = env.get('BITBUCKET_COMMIT', "")
        self.repoOwner = env.get('BITBUCKET_REPO_OWNER', "")
        self.cwd = os.getcwd()

        if(self.static_analysis_only and self.open_source_only):
            logger.error("Cannot run IRGen with both 'Open Source Only' and 'Static Analysis Only' options")
            self.fail(message="Both OSO and SAO selected")
            return False

        scan_flag = None
        if(self.static_analysis_only):
            logger.info("Setting scan mode to SAO")
            scan_flag = '-sao'
        if(self.open_source_only):
            logger.info("Setting scan mode to OSO")
            scan_flag = '-oso'

        configFile = None
        if len(self.get_variable('CONFIG_FILE_PATH')) > 0:
            configFile = os.path.join(self.cwd, self.get_variable('CONFIG_FILE_PATH'))

        apikey = {
          "KeyId": apikeyid,
          "KeySecret": apikeysecret
        }
        
        allow_untrusted = self.get_variable('ALLOW_UNTRUSTED')

        self.asoc = ASoC(apikey, self.datacenter, allow_untrusted)
        logger.info("Executing Pipe: HCL AppScan on Cloud SAST")
        if(self.debug):
            logger.setLevel('DEBUG')
            logger.info("Debug logging enabled")

        scanName = re.sub('[^a-zA-Z0-9\s_\-\.]', '_', scanName)+"_"+self.getTimeStamp()
        comment = "This scan was created via BitBucket Pipeline"
        
        logger.info("========== Step 0: Preparation ====================")
        #Copy contents of the clone dir to the target dir
        targetDir = os.path.join(self.cwd, "target")
        logger.info(f"Copying [{self.cwd}] to [{targetDir}]")
        if(shutil.copytree(self.cloneDir, targetDir) is None):
            logger.error("Cannot copy build clone dir into target dir")
            self.fail(message="Error Running ASoC SAST Pipeline")
            return False
            
        #Create the saclient dir if it doesn not exist
        saclientPath = os.path.join(self.cwd, "saclient")
        if(not os.path.isdir(saclientPath)):
            logger.debug(f"SAClient Path [{saclientPath}] does not exist")
            try:
                os.mkdir(saclientPath)
                logger.info(f"Created dir [{saclientPath}]")
            except:
                logger.error(f"Error creating saclient path [{saclientPath}]")
                self.fail(message="Error Running ASoC SAST Pipeline")
                return False
            if(not os.path.isdir(saclientPath)):
                logger.error(f"Error creating saclient path [{saclientPath}]")
                self.fail(message="Error Running ASoC SAST Pipeline")
                return False
                
        #Create Reports Dir if it does not exist 
        reportsDir = os.path.join(self.cwd, "reports")
        if(not os.path.isdir(reportsDir)):
            logger.debug(f"Reports dir doesn't exists [{reportsDir}]")
            os.mkdir(reportsDir)
            if(not os.path.isdir(reportsDir)):
                logger.error(f"Cannot create reports dir! [{reportsDir}]")
                self.fail(message="Error Running ASoC SAST Pipeline")
                return False
            else:
                logger.info(f"Created dir [{reportsDir}]")
        #Make sure we have write permission on the reports dir
        logger.info("Setting permissions on reports dir")
        os.chmod(reportsDir, 755)
        logger.info("========== Step 0: Complete =======================\n")
        
        #Step 1: Download the SACLientUtil
        logger.info("========== Step 1: Download SAClientUtil ==========")
        appscanPath = self.getSAClient(saclientPath)
        if(appscanPath is None):
            logger.error("AppScan Path not found, something went wrong with SACLientUtil Download?")
            self.fail(message="Error Running ASoC SAST Pipeline")
            return False
        logger.info("========== Step 1: Complete =======================\n")

        #Step 2: Generate the IRX
        logger.info("========== Step 2: Generate IRX File ==============")
        irxPath = self.genIrx(scanName, appscanPath, targetDir, reportsDir, scan_flag, configFile, self.secret_scanning)
        if(irxPath is None):
            logger.error("IRX File Not Generated.")
            self.fail(message="Error Running ASoC SAST Pipeline")
            return False
        logger.info("========== Step 2: Complete =======================\n")

        #Step 3: Run the Scan
        logger.info("========== Step 3: Run the Scan on ASoC ===========")
        scanId = self.runScan(scanName, self.appID, irxPath, comment, True, self.personal_scan)
        if(scanId is None):
            logger.error("Error creating scan")
            self.fail(message="Error Running ASoC SAST Pipeline")
            return False
        logger.info("========== Step 3: Complete =======================\n")

        #Step 4: Get the Scan Summary
        logger.info("========== Step 4: Fetch Scan Summary =============")      
        summaryFileName = scanName+".json"
        summaryPath = os.path.join(reportsDir, summaryFileName)
        logger.debug("Fetching Scan Summary")
        summary = self.getScanSummary(scanId, summaryPath)
        if(summary is None):
            logger.error("Error getting scan summary")
        else:
            seconds = summary["duration_seconds"] % (24 * 3600)
            hour = seconds // 3600
            seconds %= 3600
            minutes = seconds // 60
            seconds %= 60
            durationStr = "%d:%02d:%02d" % (hour, minutes, seconds)
            logger.info("Scan Summary:")
            logger.info(f"\tDuration: {durationStr}")
            logger.info(f'\tTotal Issues: {summary["total_issues"]}')
            logger.info(f'\t\tHigh Issues: {summary["high_issues"]}')
            logger.info(f'\t\tMed Issues: {summary["medium_issues"]}')
            logger.info(f'\t\tLow Issues: {summary["low_issues"]}')
            logger.debug("Scan Summary:\n"+json.dumps(summary, indent=2))
            
            # Export scan results for use in subsequent pipeline steps
            self.exportScanResults(summary, scanId, reportsDir)
        logger.info("========== Step 4: Complete =======================\n")
        

        #Step 5: Download the Scan Report
        logger.info("========== Step 5: Download Scan Report ===========")
        notes = ""
        if(len(self.repo)>0):
            notes += f"Bitbucket Repo: {self.repo} "
        if(buildNum!=0):
            notes += f"Build: {buildNum}"
        reportFileName = scanName+".html"
        reportPath = os.path.join(reportsDir, reportFileName)
        report = self.getReport(scanId, reportPath, notes)
        if(report is None):
            logger.error("Error downloading report")
            self.fail(message="Error Running ASoC SAST Pipeline")
            return False
        logger.info(f"Report Downloaded [{reportPath}]")
        
        # Export report paths for downstream consumption
        self.exportReportPaths(reportPath, summaryPath, reportsDir)
        logger.info("========== Step 5: Complete =======================\n")
        
        # Step 6: Check for Non-Compliance (if enabled)
        if self.wait_for_analysis and self.fail_for_noncompliance and summary is not None:
            logger.info("========== Step 6: Compliance Check ===============")
            issues_at_threshold = self.getIssuesAtOrAboveThreshold(summary, self.failure_threshold)
            if issues_at_threshold > 0:
                logger.error(f"Non-compliance detected: {issues_at_threshold} issue(s) found at or above '{self.failure_threshold}' severity threshold")
                logger.error(f"  Threshold: {self.failure_threshold}")
                logger.error(f"  Critical Issues: {summary['critical_issues']}")
                logger.error(f"  High Issues: {summary['high_issues']}")
                logger.error(f"  Medium Issues: {summary['medium_issues']}")
                logger.error(f"  Low Issues: {summary['low_issues']}")
                logger.error(f"  Informational Issues: {summary['info_issues']}")
                logger.info("========== Step 6: FAILED =========================\n")
                self.fail(message=f"Security scan failed: {issues_at_threshold} issue(s) at or above {self.failure_threshold} severity")
                return False
            else:
                logger.info(f"No issues found at or above '{self.failure_threshold}' severity threshold")
                logger.info("========== Step 6: Complete =======================\n")
        
        self.success(message="ASoC SAST Pipeline Complete")
        
    def exportScanResults(self, summary, scanId, reportsDir):
        """
        Export scan results as environment variables and output files
        for use in subsequent Bitbucket Pipeline steps
        """
        # Create output files that can be sourced in bash or parsed
        outputFile = os.path.join(reportsDir, "scan_results.txt")
        envFile = os.path.join(reportsDir, "scan_env.sh")
        
        # Write human-readable output
        with open(outputFile, 'w') as f:
            f.write(f"SCAN_ID={scanId}\n")
            f.write(f"SCAN_NAME={summary['scan_name']}\n")
            f.write(f"TOTAL_ISSUES={summary['total_issues']}\n")
            f.write(f"CRITICAL_ISSUES={summary['critical_issues']}\n")
            f.write(f"HIGH_ISSUES={summary['high_issues']}\n")
            f.write(f"MEDIUM_ISSUES={summary['medium_issues']}\n")
            f.write(f"LOW_ISSUES={summary['low_issues']}\n")
            f.write(f"INFO_ISSUES={summary['info_issues']}\n")
            f.write(f"SCAN_DURATION_SECONDS={summary['duration_seconds']}\n")
            f.write(f"CREATED_AT={summary['createdAt']}\n")
        
        # Write shell-sourceable environment variables
        with open(envFile, 'w') as f:
            f.write(f"export ASOC_SCAN_ID='{scanId}'\n")
            f.write(f"export ASOC_SCAN_NAME='{summary['scan_name']}'\n")
            f.write(f"export ASOC_TOTAL_ISSUES={summary['total_issues']}\n")
            f.write(f"export ASOC_CRITICAL_ISSUES={summary['critical_issues']}\n")
            f.write(f"export ASOC_HIGH_ISSUES={summary['high_issues']}\n")
            f.write(f"export ASOC_MEDIUM_ISSUES={summary['medium_issues']}\n")
            f.write(f"export ASOC_LOW_ISSUES={summary['low_issues']}\n")
            f.write(f"export ASOC_INFO_ISSUES={summary['info_issues']}\n")
            f.write(f"export ASOC_SCAN_DURATION_SECONDS={summary['duration_seconds']}\n")
            f.write(f"export ASOC_SCAN_URL='{self.asoc.getDataCenterURL()}/main/myapps/{self.appID}/scans/{scanId}'\n")
        
        logger.info(f"Scan results exported to: {outputFile}")
        logger.info(f"Environment variables exported to: {envFile}")
        logger.info("To use in next pipeline step, add 'source reports/scan_env.sh' or parse scan_results.txt")

    def exportReportPaths(self, reportPath, summaryPath, reportsDir):
        """
        Export report file paths for artifact collection
        """
        pathsFile = os.path.join(reportsDir, "report_paths.txt")
        with open(pathsFile, 'w') as f:
            f.write(f"HTML_REPORT={reportPath}\n")
            f.write(f"JSON_SUMMARY={summaryPath}\n")
            f.write(f"REPORTS_DIR={reportsDir}\n")
        
        logger.info(f"Report paths exported to: {pathsFile}")
        logger.info("")
        logger.info("=" * 55)
        logger.info("PIPELINE OUTPUT SUMMARY")
        logger.info("=" * 55)
        logger.info(f"HTML Report: {reportPath}")
        logger.info(f"JSON Summary: {summaryPath}")
        logger.info(f"Scan Results: {os.path.join(reportsDir, 'scan_results.txt')}")
        logger.info(f"Environment File: {os.path.join(reportsDir, 'scan_env.sh')}")
        logger.info("")
        logger.info("To use these outputs in your bitbucket-pipelines.yml:")
        logger.info("1. Add artifacts section to preserve reports/")
        logger.info("2. Source the environment file: source reports/scan_env.sh")
        logger.info("3. Use variables like $ASOC_CRITICAL_ISSUES in next steps")
        logger.info("=" * 55)

    def getIssuesAtOrAboveThreshold(self, summary, threshold):
        """
        Calculate the number of issues at or above the specified severity threshold.
        
        Args:
            summary: The scan summary dictionary containing issue counts
            threshold: Severity threshold string (Critical, High, Medium, Low, Informational)
        
        Returns:
            int: Total count of issues at or above the threshold
        """
        threshold_lower = threshold.lower() if threshold else 'low'
        
        critical = summary.get('critical_issues', 0)
        high = summary.get('high_issues', 0)
        medium = summary.get('medium_issues', 0)
        low = summary.get('low_issues', 0)
        info = summary.get('info_issues', 0)
        
        if threshold_lower == 'critical':
            return critical
        elif threshold_lower == 'high':
            return critical + high
        elif threshold_lower == 'medium':
            return critical + high + medium
        elif threshold_lower == 'low':
            return critical + high + medium + low
        elif threshold_lower in ['informational', 'info']:
            return critical + high + medium + low + info
        else:
            # Default to Low if invalid threshold
            logger.warning(f"Invalid threshold '{threshold}', defaulting to 'Low'")
            return critical + high + medium + low

    #download and unzip SAClientUtil to {cwd}/saclient
    def getSAClient(self, saclientPath="saclient"):
        #Downloading SAClientUtil
        url = self.asoc.getDataCenterURL() + "/api/v4/Tools/SAClientUtil?os=win"
        logger.info("Downloading SAClientUtil Zip")
        try:
            if self.asoc.allow_untrusted:
                r = requests.get(url, stream=True, verify=False)
            else:
                r = requests.get(url, stream=True)
        except socket.gaierror as e:
            print(f"DNS resolution failed: {e}")
            return None
        except requests.exceptions.RequestException as e:
            print(f"HTTP request failed: {e}")
            return None

        if(r.status_code != 200):
            logger.error("Invalid HTTP code downloading SAClient Util")
            return None

        file_size = int(r.headers.get("content-length", 0))
        disposition = r.headers.get("content-disposition")
        if disposition is None:
            logger.warning("'content-disposition' header missing in response")
        chunk_size = 4096
        xfered = 0
        percent = 0
        start = time.time()
        save_path = os.path.join(self.cwd, "saclient.zip")
        with open(save_path, 'wb') as fd:
            for chunk in r.iter_content(chunk_size=chunk_size):
                fd.write(chunk)
                xfered += len(chunk)
                if file_size:
                    percent = round((xfered/file_size)*100)
                else:
                    percent = 0
                if(time.time()-start > 3):
                    logger.info(f"SAClientUtil Download: {percent}%")
                    start = time.time()
        logger.info(f"SAClientUtil Download: {percent}%")

        # Check if the downloaded file is a valid zip
        if r.headers.get('content-type', '').lower() != 'application/zip':
            logger.error(f"Unexpected content-type: {r.headers.get('content-type')}")
            with open(save_path, 'rb') as f:
                sample = f.read(20000)
                logger.error(f"First 20000 bytes of file: {sample}")
            logger.error("Downloaded file is not a zip. Aborting extraction.")
            return None

        #Extract the downloaded file
        logger.info("Extracting SAClientUtil Zip")
        try:
            with zipfile.ZipFile(save_path, 'r') as zip_ref:
                zip_ref.extractall(saclientPath)
        except zipfile.BadZipFile:
            logger.error("Downloaded file is not a valid zip file. Aborting.")
            with open(save_path, 'rb') as f:
                sample = f.read(200)
                logger.error(f"First 200 bytes of file: {sample}")
            return None

        #Make sure all the SAClientUtil Files can be read and executed
        logger.info("Setting permissions on SACLientUtil Files")
        for root, dirs, files in os.walk(saclientPath):
            for d in dirs:
                os.chmod(os.path.join(root, d), 755)
            for f in files:
                os.chmod(os.path.join(root, f), 755)

        #Find the appscan executable
        logger.debug("Finding appscan bin path")
        appscanPath = None
        dirs = os.listdir(saclientPath)
        for file in dirs:
            appscanPath = os.path.join(self.cwd, saclientPath, file, "bin", "appscan.bat")

        if(os.path.exists(appscanPath)):
            logger.debug(f"AppScan Bin Path [{appscanPath}]")
        else:
            logger.error("Something went wrong setting up the SAClientUtil")
            logger.error(f"AppScan Bin [{appscanPath}] not found!")
            return None

        #Return the appscan executable path
        return appscanPath
        
    #generate IRX file for target directory
    def genIrx(self, scanName, appscanPath, targetPath, reportsDir, scan_flag, configFile=None, secret_scanning=False, scan_speed=""):
        #Change Working Dir to the target directory
        logger.debug(f"Changing dir to target: [{targetPath}]")
        os.chdir(targetPath)
        logger.info("IRX Gen stdout will be saved to [reports]")
        logger.info("Running AppScan Prepare")
        irxFile = self.asoc.generateIRX(scanName, scan_flag, appscanPath, reportsDir, configFile, secret_scanning, self.debug, scan_speed)
        if(irxFile is None):
            logger.error("IRX Not Generated")
            return None
            
        irxPath = os.path.join(targetPath, irxFile)
        logPath = os.path.join(targetPath, scanName+"_logs.zip")
        
        #Change working dir back to the previous current working dir
        logger.debug(f"Changing dir to previous working dir: [{self.cwd}]")
        os.chdir(self.cwd)
        
        #Check if logs dir exists, if it does copy to the reports dir to be saved
        if(os.path.exists(logPath)):
            logger.debug(f"Logs Found [{logPath}]")
            logger.debug("Copying logs to reports dir")
            newLogPath = os.path.join(reportsDir, scanName+"_logs.zip")
            res = shutil.copyfile(logPath, newLogPath)
            if(res):
                logger.info(f"Logs Saved: [{res}]")
                
        #Verify the IRX File Exists
        if(os.path.exists(irxPath)):
            logger.debug(f"IRX Path [{irxPath}]")
            return irxPath
        
        logger.error(f"IRX File does not exist [{irxPath}]")
        return None
    
    #Create the SAST scan based on an IRX File
    #If Wait=True the function will sleep until the scan is complete
    def runScan(self, scanName, appId, irxPath, comment="", wait=True, personal_scan=False):
        #Verify that ASoC is logged in, if not then login
        logger.debug("Login to ASoC")
        if(not self.asoc.checkAuth()):
            if(self.asoc.login()):
                logger.info("Successfully logged into ASoC API")
            else:
                logger.error("Error logging into ASoC!")
                return None
               
        #Verify that appId exists
        logger.debug(f"Checking AppId [{appId}]")
        app = self.asoc.getApplication(appId)
        if(app):
            appName = app["Name"]
            logger.info("App Found:")
            logger.info(f"\t[{appName}] - [{appId}]")
        else:
            logger.error("Invalid AppId: App Not Found!")
            return None
        
        scanName = appName+"_"+scanName
        #Upload the IRX File and get a FileId
        logger.debug("Uploading IRX File")
        fileId = self.asoc.uploadFile(irxPath)
        if(fileId is None):
            logger.error("Error uploading IRX File")
        logger.debug(f"IRX FileId: [{fileId}]")
        
        #Run the Scan
        logger.debug("Running Scan")
        scanId = self.asoc.createSastScan(scanName, appId, fileId, comment, personal_scan)
        
        if(scanId):
            logger.info("Scan Created")
            logger.info(f"ScanId: [{scanId}]")
        else:
            logger.error("Scan not created!")
            return None
            
        #If Wait=False, return now with scanId
        if(wait == False):
            logger.info("Do not wait for scan to complete, return immediatly")
            return scanId
        
        logger.info("Waiting for scan to complete (status=Ready)")
        execution = self.asoc.getScanStatus(scanId)
        status = execution["Status"] if execution else "Abort"

        start = time.time()
        while(status not in ["Ready", "Abort"]):
            if(time.time()-start >= 120):
                logger.info(f"\tScan still running...(status={status})")
                start = time.time()
            time.sleep(15)
            execution = self.asoc.getScanStatus(scanId)
            status = execution["Status"] if execution else "Abort"
        
        if(status == "Ready"):
            logger.info(f"Scan [{scanId}] Complete")
            # Store the execution data for use in getScanSummary
            self.lastExecution = execution
        else:
            logger.error("ASoC returned an invalid status... check login?")
            logger.error("If script continues, the scan might not be complete")
            self.lastExecution = None
        return scanId
    
    #Download a report based on a scan
    def getReport(self, scanId, reportPath, note=""):
        reportConfig = {
            "Configuration": {
					"Summary": True,
					"Overview": True,
					"TableOfContent": True,
					"Advisories": True,
					"FixRecommendation": True,
					"MinimizeDetails": True,
					"ReportFileType": "Html",
					"Title": "HCL ASoC SAST Security Report",
                    "Notes": note
				}
        }
        reportId = self.asoc.startReport(scanId, reportConfig)
        if(reportId is None):
            logger.error("Error starting report")
            return None
        
        statusMsg = self.asoc.reportStatus(reportId)
        while(statusMsg["Items"][0].get("Status") not in ["Ready", "Abort"]):
            time.sleep(5)
            statusMsg = self.asoc.reportStatus(reportId)
            percent = statusMsg["Items"][0].get("Progress")
            logger.info(f"Report Progress: {percent}%")
        
        if(statusMsg["Items"][0].get("Status") != "Ready"):
            logger.error("Problem generating report")
            return None
        logger.info("Report Complete, downloading report")
        
        result = self.asoc.downloadReport(reportId, reportPath)
        if(not result):
            logger.error(f"Error Downloading Report")
        return os.path.exists(reportPath)
    
    def getScanSummary(self, scanId, summaryPath):
        """Get scan summary from the execution data obtained during status polling.
        
        Uses the execution data already retrieved by getScanStatus to avoid
        an additional API call.
        """
        # Use the execution data stored during scan status polling
        execution = getattr(self, 'lastExecution', None)
        if execution is None:
            logger.error("No execution data available from scan status")
            return None
        
        # Extract scan name from the filename (remove .irx extension)
        scan_name = execution.get("FileName", "Unknown")
        if scan_name.endswith(".irx"):
            scan_name = scan_name[:-4]
        
        summaryDict = {
            "scan_name": scan_name,
            "scan_id": execution["ScanId"],
            "execution_id": execution["Id"],
            "createdAt": execution["CreatedAt"],
            "duration_seconds": execution["ExecutionDurationSec"],
            "critical_issues": execution["NCriticalIssues"],
            "high_issues": execution["NHighIssues"],
            "medium_issues": execution["NMediumIssues"],
            "low_issues": execution["NLowIssues"],
            "info_issues": execution["NInfoIssues"],
            "total_issues": execution["NIssuesFound"],
            "opensource_licenses": execution["NOpenSourceLicenses"],
            "opensource_packages": execution["NOpenSourcePackages"]
        }
        logger.info(f"Scan summary saved [{summaryPath}]")
        with open(summaryPath, "w") as summaryFile:
            json.dump(execution, summaryFile, indent=4)
        return summaryDict
    
    #Get current system timestamp
    def getTimeStamp(self):
        ts = time.time()
        return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d_%H-%M-%S')
    
        
if __name__ == '__main__':
    pipe = AppScanOnCloudSAST(pipe_metadata='/pipe.yml', schema=schema)
    pipe.run()
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    