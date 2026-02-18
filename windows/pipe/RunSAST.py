#
# Copyright 2026 HCL America, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from bitbucket_pipes_toolkit import Pipe, get_logger, CodeInsights
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
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from constants import (
    VERSION,
    SACLIENT_DOWNLOAD_ENDPOINT, APPSCAN_BIN_NAME,
    CONTENT_TYPE_ZIP,
    SCAN_FLAG_SAO, SCAN_FLAG_OSO,
    SCAN_STATUS_READY, SCAN_STATUS_ABORT,
    SCAN_POLL_INTERVAL_SECS, SCAN_LOG_INTERVAL_SECS, SCAN_MAX_WAIT_SECS,
    REPORT_POLL_INTERVAL_SECS, DOWNLOAD_LOG_INTERVAL_SECS,
    DOWNLOAD_CHUNK_SIZE, BYTES_PER_MB, FILE_PERMISSION_MODE, SECONDS_PER_DAY,
    SACLIENT_DIR, TARGET_DIR, REPORTS_DIR,
    SACLIENT_ZIP_FILENAME, SCAN_RESULTS_FILENAME, SCAN_ENV_FILENAME, REPORT_PATHS_FILENAME,
    SCAN_NAME_VALID_CHARS_REGEX, SCAN_NAME_REPLACEMENT_CHAR,
    DEFAULT_REPORT_TITLE, DEFAULT_REPORT_FILE_TYPE,
    MSG_PIPE_NAME, MSG_PIPELINE_ERROR, MSG_PIPELINE_SUCCESS,
    MSG_BOTH_OSO_SAO, MSG_SCAN_COMMENT,
    TIMESTAMP_FORMAT,
    CODE_INSIGHTS_REPORT_ID, CODE_INSIGHTS_REPORT_TITLE, CODE_INSIGHTS_REPORTER,
    CODE_INSIGHTS_LOGO_URL, CODE_INSIGHTS_MAX_ANNOTATIONS,
    CODE_INSIGHTS_ANNOTATION_TYPE, CODE_INSIGHTS_REPORT_TYPE,
    SEVERITY_MAP_ASOC_TO_BB,
)

# Disable SSL warnings when bypassing certificate verification
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = get_logger()

schema = {
    'SCAN_NAME': {'type': 'string', 'required': False, 'default': ""},
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
    'FAILURE_THRESHOLD': {'type': 'string', 'required': False, 'default': 'Low'},
    'CODE_INSIGHTS': {'type': 'boolean', 'required': False, 'default': False},
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
        self.code_insights_enabled = self.get_variable('CODE_INSIGHTS')
        self.repo = env.get('BITBUCKET_REPO_SLUG', "") or env.get('REPO_SLUG', "")
        self.repo_full_name = env.get('BITBUCKET_REPO_FULL_NAME', "") or env.get('REPO', "")
        branch = env.get('BITBUCKET_BRANCH', "") or env.get('BRANCH', "")
        self.commit = env.get('BITBUCKET_COMMIT', "") or env.get('COMMIT', "")
        projectKey = env.get('BITBUCKET_PROJECT_KEY', "") or env.get('PROJECT_KEY', "")
        self.repoOwner = env.get('BITBUCKET_REPO_OWNER', "") or env.get('REPO_OWNER', "")
        self.cwd = os.getcwd()

        if(self.static_analysis_only and self.open_source_only):
            logger.error("Cannot run IRGen with both 'Open Source Only' and 'Static Analysis Only' options")
            self.fail(message=MSG_BOTH_OSO_SAO)
            return False

        scan_flag = None
        if(self.static_analysis_only):
            logger.info("Setting scan mode to SAO")
            scan_flag = SCAN_FLAG_SAO
        if(self.open_source_only):
            logger.info("Setting scan mode to OSO")
            scan_flag = SCAN_FLAG_OSO

        configFile = None
        if len(self.get_variable('CONFIG_FILE_PATH')) > 0:
            configFile = os.path.join(self.cwd, self.get_variable('CONFIG_FILE_PATH'))

        allow_untrusted = self.get_variable('ALLOW_UNTRUSTED')

        apikey = {
          "KeyId": apikeyid,
          "KeySecret": apikeysecret,
        }
        self.asoc = ASoC(apikey, logger, self.datacenter, allow_untrusted)
        client_type = self.asoc.getClientType()
        self.asoc.apikey["ClientType"] = client_type
        logger.info(f"Client Version: {client_type}")
        logger.info(MSG_PIPE_NAME)
        if(self.debug):
            logger.setLevel('DEBUG')
            logger.info("Debug logging enabled")

        # Use Bitbucket repo name if scan name not provided
        if not scanName:
            scanName = self.repo
        
        #valid chars for a scan name: alphanumeric + [.-_ ]
        scanName = re.sub(SCAN_NAME_VALID_CHARS_REGEX, SCAN_NAME_REPLACEMENT_CHAR, scanName)
        comment = MSG_SCAN_COMMENT
        
        logger.info("========== Step 0: Preparation ====================")
        #Copy contents of the clone dir to the target dir
        logger.info(f"SCAN_NAME: {scanName}")
        logger.info(f"APP_ID: {self.appID}")
        logger.info(f"BUILD_NUM: {buildNum}")
        logger.info(f"TARGET_DIR: {self.cloneDir}")
        if configFile is not None:
            logger.info(f"CONFIG_FILE_PATH: {configFile}")
        else:
            logger.info(f"CONFIG_FILE_PATH: Not Specified")
        logger.info(f"DATACENTER: {self.datacenter}")
        logger.info(f"SECRET_SCANNING: {self.secret_scanning}")
        logger.info(f"SCAN_SPEED: {self.scan_speed}")
        logger.info(f"DEBUG: {self.debug}")
        logger.info(f"CODE_INSIGHTS: {self.code_insights_enabled}")
        logger.debug(f"REPO: {self.repo}")
        logger.debug(f"REPO_FULL: {self.repo_full_name}")
        logger.debug(f"BRANCH: {branch}")
        logger.debug(f"COMMIT: {self.commit}")
        logger.debug(f"PROJECT_KEY: {projectKey}")
        logger.debug(f"REPO_OWNER: {self.repoOwner}")
        logger.debug(f"Current Working Dir: {self.cwd}")
        targetDir = os.path.join(self.cwd, TARGET_DIR)
        logger.debug(f"SCAN TARGET: {targetDir}")

        cwd_dir_list = os.listdir(self.cwd)
        logger.debug(cwd_dir_list)
        clone_dir_list = os.listdir(self.cloneDir)
        logger.debug(clone_dir_list)

        # Check if config file actually exists
        if configFile is not None:
            if not os.path.exists(configFile):
                logger.error(f"Config Path Does Not Exist: {configFile}")
                logger.error(f"Using Defaults")
                configFile = None


        logger.info(f"Copying [{self.cwd}] to [{targetDir}]")
        if(shutil.copytree(self.cloneDir, targetDir) is None):
            logger.error("Cannot copy build clone dir into target dir")
            self.fail(message=MSG_PIPELINE_ERROR)
            return False
            
        #Create the saclient dir if it doesn not exist
        saclientPath = os.path.join(self.cwd, SACLIENT_DIR)
        if(not os.path.isdir(saclientPath)):
            logger.debug(f"SAClient Path [{saclientPath}] does not exist")
            try:
                os.mkdir(saclientPath)
                logger.info(f"Created dir [{saclientPath}]")
            except:
                logger.error(f"Error creating saclient path [{saclientPath}]")
                self.fail(message=MSG_PIPELINE_ERROR)
                return False
            if(not os.path.isdir(saclientPath)):
                logger.error(f"Error creating saclient path [{saclientPath}]")
                self.fail(message=MSG_PIPELINE_ERROR)
                return False
                
        #Create Reports Dir if it does not exist
        # Write reports to the parent of TARGET_DIR so they land inside
        # the mounted volume (critical for Windows docker run where cwd
        # may be outside the mount). For Linux pipes this resolves to
        # the same workspace-relative path as before.
        cloneParent = os.path.dirname(os.path.abspath(self.cloneDir))
        reportsDir = os.path.join(cloneParent, REPORTS_DIR)
        logger.info(f"Reports directory: {reportsDir}")
        if(not os.path.isdir(reportsDir)):
            logger.debug(f"Reports dir doesn't exists [{reportsDir}]")
            os.mkdir(reportsDir)
            if(not os.path.isdir(reportsDir)):
                logger.error(f"Cannot create reports dir! [{reportsDir}]")
                self.fail(message=MSG_PIPELINE_ERROR)
                return False
            else:
                logger.info(f"Created dir [{reportsDir}]")
        #Make sure we have write permission on the reports dir
        logger.info("Setting permissions on reports dir")
        os.chmod(reportsDir, FILE_PERMISSION_MODE)
        logger.info("========== Step 0: Complete =======================\n")
        
        #Step 1: Download the SACLientUtil
        logger.info("========== Step 1: Download SAClientUtil ==========")
        appscanPath = self.getSAClient(saclientPath)
        if(appscanPath is None):
            logger.error("AppScan Path not found, something went wrong with SACLientUtil Download?")
            self.fail(message=MSG_PIPELINE_ERROR)
            return False
        logger.info("========== Step 1: Complete =======================\n")

        #Step 2: Generate the IRX
        logger.info("========== Step 2: Generate IRX File ==============")
        if configFile is None:
            logger.info("Config file not specified. Using defaults.")
            
        irxPath = self.genIrx(scanName, appscanPath, targetDir, reportsDir, scan_flag, configFile, self.secret_scanning, self.scan_speed)
        if(irxPath is None):
            logger.error("IRX File Not Generated.")
            self.fail(message=MSG_PIPELINE_ERROR)
            return False
        logger.info("========== Step 2: Complete =======================\n")

        #Step 3: Run the Scan(s)
        logger.info("========== Step 3: Run the Scan on ASoC ===========")
        scan_result = self.runScan(scanName, self.appID, irxPath, comment, True, self.personal_scan)
        if(scan_result is None):
            logger.error("Error creating scan(s)")
            self.fail(message=MSG_PIPELINE_ERROR)
            return False
        sast_scan_id = scan_result.get('sast_scan_id')
        sca_scan_id = scan_result.get('sca_scan_id')
        # For backward compatibility
        self.scanID = sast_scan_id or sca_scan_id
        logger.info("========== Step 3: Complete =======================\n")

        #Step 4: Get the Scan Summary
        logger.info("========== Step 4: Fetch Scan Summary =============")      
        summaries = {}
        summary_paths = {}
        for scan_type, scan_id in [('SAST', sast_scan_id), ('SCA', sca_scan_id)]:
            if scan_id is None:
                continue
            summaryFileName = scanName + f"_{scan_type.lower()}.json"
            sSummaryPath = os.path.join(reportsDir, summaryFileName)
            summary_paths[scan_type] = sSummaryPath
            logger.debug(f"Fetching {scan_type} Scan Summary")
            scan_summary = self.getScanSummary(scan_id, sSummaryPath)
            if scan_summary is None:
                logger.error(f"Error getting {scan_type} scan summary")
            else:
                summaries[scan_type] = scan_summary
                self._logScanSummary(scan_type, scan_summary)
        
        combined_summary = self._combineSummaries(summaries) if summaries else None
        if combined_summary:
            if len(summaries) > 1:
                logger.info("Combined Summary (SAST + SCA):")
                self._logScanSummary("Combined", combined_summary)
            # Export scan results for use in subsequent pipeline steps
            self.exportScanResults(combined_summary, scan_result, reportsDir)
        else:
            logger.error("No scan summaries available")
        logger.info("========== Step 4: Complete =======================\n")
        

        #Step 5: Download the Scan Report
        logger.info("========== Step 5: Download Scan Report ===========")
        notes = ""
        if(len(self.repo)>0):
            notes += f"Bitbucket Repo: {self.repo} "
        if(buildNum!=0):
            notes += f"Build: {buildNum}"
        report_paths = {}
        for scan_type, scan_id in [('SAST', sast_scan_id), ('SCA', sca_scan_id)]:
            if scan_id is None:
                continue
            reportFileName = scanName + f"_{scan_type.lower()}.html"
            reportPath = os.path.join(reportsDir, reportFileName)
            logger.info(f"Downloading {scan_type} report...")
            report = self.getReport(scan_id, reportPath, notes)
            if(report is None):
                logger.error(f"Error downloading {scan_type} report")
                self.fail(message=MSG_PIPELINE_ERROR)
                return False
            logger.info(f"{scan_type} Report Downloaded [{reportPath}]")
            report_paths[scan_type] = reportPath
        
        # Export report paths for downstream consumption
        self.exportReportPaths(report_paths, summary_paths, reportsDir)
        logger.info("========== Step 5: Complete =======================\n")
        
        # Step 6: Check for Non-Compliance (if enabled)
        if self.wait_for_analysis and self.fail_for_noncompliance and combined_summary is not None:
            logger.info("========== Step 6: Compliance Check ===============")
            issues_at_threshold = self.getIssuesAtOrAboveThreshold(combined_summary, self.failure_threshold)
            if issues_at_threshold > 0:
                logger.error(f"Non-compliance detected: {issues_at_threshold} issue(s) found at or above '{self.failure_threshold}' severity threshold")
                logger.error(f"  Threshold: {self.failure_threshold}")
                logger.error(f"  Critical Issues: {combined_summary['critical_issues']}")
                logger.error(f"  High Issues: {combined_summary['high_issues']}")
                logger.error(f"  Medium Issues: {combined_summary['medium_issues']}")
                logger.error(f"  Low Issues: {combined_summary['low_issues']}")
                logger.error(f"  Informational Issues: {combined_summary['info_issues']}")
                logger.info("========== Step 6: FAILED =========================\n")
                self.fail(message=f"Security scan failed: {issues_at_threshold} issue(s) at or above {self.failure_threshold} severity")
                return False
            else:
                logger.info(f"No issues found at or above '{self.failure_threshold}' severity threshold")
                logger.info("========== Step 6: Complete =======================\n")
        
        # Step 7: Code Insights (if enabled)
        if self.code_insights_enabled:
            logger.info("========== Step 7: Bitbucket Code Insights ========")
            try:
                self.publishCodeInsights(combined_summary, scan_result)
                logger.info("========== Step 7: Complete =======================\n")
            except Exception as e:
                logger.error(f"Code Insights failed: {e}")
                logger.warning("Continuing despite Code Insights failure - scan results are still valid")
                logger.info("========== Step 7: FAILED (non-blocking) ==========\n")
        
        self.success(message=MSG_PIPELINE_SUCCESS)

    def publishCodeInsights(self, combined_summary, scan_result):
        """
        Publish scan results to Bitbucket Code Insights, including a
        summary report and per-issue annotations.
        
        Args:
            combined_summary: Aggregated scan summary dict with issue counts.
            scan_result: Dict with 'sast_scan_id' and/or 'sca_scan_id' keys.
        """
        logger.info("[CODE INSIGHTS] Starting publishCodeInsights function")
        logger.info(f"[CODE INSIGHTS] Input parameters - combined_summary: {combined_summary}")
        logger.info(f"[CODE INSIGHTS] Input parameters - scan_result: {scan_result}")
        
        logger.info(f"[CODE INSIGHTS] Validating commit: {self.commit}")
        if not self.commit:
            logger.warning("[CODE INSIGHTS] VALIDATION FAILED: No BITBUCKET_COMMIT available - skipping Code Insights")
            return
        logger.info(f"[CODE INSIGHTS] Commit validated successfully: {self.commit}")
        
        logger.info(f"[CODE INSIGHTS] Validating repo owner: {self.repoOwner}, repo: {self.repo}")
        if not self.repoOwner or not self.repo:
            logger.warning(f"[CODE INSIGHTS] VALIDATION FAILED: No BITBUCKET_REPO_OWNER ({self.repoOwner}) or BITBUCKET_REPO_SLUG ({self.repo}) available - skipping Code Insights")
            return
        logger.info(f"[CODE INSIGHTS] Repo info validated successfully - Owner: {self.repoOwner}, Repo: {self.repo}")
        
        logger.info("[CODE INSIGHTS] Initializing CodeInsights object with OIDC auth")
        try:
            code_insights = CodeInsights(
                repo=self.repo,
                username=self.repoOwner,
                auth_type="oidc",
            )
            logger.info("[CODE INSIGHTS] CodeInsights object initialized successfully")
        except Exception as e:
            logger.error(f"[CODE INSIGHTS] FAILED to initialize CodeInsights object: {e}")
            raise
        
        # Step 7a: Create the Code Insights report
        logger.info("[CODE INSIGHTS] ========== Step 7a: Creating Code Insights Report ==========")
        try:
            report_uuid = self._createCodeInsightsReport(code_insights, combined_summary, scan_result)
            logger.info(f"[CODE INSIGHTS] Step 7a completed successfully. Report UUID: {report_uuid}")
        except Exception as e:
            logger.error(f"[CODE INSIGHTS] Step 7a FAILED: {e}")
            raise
        
        # Step 7b: Create annotations from scan issues
        logger.info("[CODE INSIGHTS] ========== Step 7b: Creating Code Insights Annotations ==========")
        try:
            self._createCodeInsightsAnnotations(code_insights, scan_result, report_uuid)
            logger.info("[CODE INSIGHTS] Step 7b completed successfully")
        except Exception as e:
            logger.error(f"[CODE INSIGHTS] Step 7b FAILED: {e}")
            raise
        
        logger.info("[CODE INSIGHTS] publishCodeInsights completed successfully")
    
    def _createCodeInsightsReport(self, code_insights, summary, scan_result):
        """
        Create a Code Insights report with scan summary data attached to the commit.
        
        Args:
            code_insights: CodeInsights instance.
            summary: Scan summary dict with issue counts.
            scan_result: Dict with scan IDs.
        
        Returns:
            str: The report UUID assigned by Bitbucket, or CODE_INSIGHTS_REPORT_ID as fallback.
        """
        logger.info("[CODE INSIGHTS REPORT] Starting _createCodeInsightsReport")
        logger.debug(f"[CODE INSIGHTS REPORT] Summary input: {json.dumps(summary, indent=2) if summary else 'None'}")
        logger.debug(f"[CODE INSIGHTS REPORT] Scan result input: {json.dumps(scan_result, indent=2)}")
        
        total_issues = summary.get('total_issues', 0) if summary else 0
        logger.info(f"[CODE INSIGHTS REPORT] Total issues extracted: {total_issues}")
        
        # Determine result based on compliance check settings
        logger.info(f"[CODE INSIGHTS REPORT] Determining report result - fail_for_noncompliance: {self.fail_for_noncompliance}, failure_threshold: {self.failure_threshold}")
        if self.fail_for_noncompliance and summary:
            issues_at_threshold = self.getIssuesAtOrAboveThreshold(summary, self.failure_threshold)
            report_result = "FAILED" if issues_at_threshold > 0 else "PASSED"
            logger.info(f"[CODE INSIGHTS REPORT] Compliance mode: Issues at/above threshold: {issues_at_threshold}, Result: {report_result}")
        else:
            report_result = "PASSED" if total_issues == 0 else "FAILED"
            logger.info(f"[CODE INSIGHTS REPORT] Standard mode: Result: {report_result}")
        
        # Build the scan URL for linking
        logger.info("[CODE INSIGHTS REPORT] Building scan URL")
        sast_scan_id = scan_result.get('sast_scan_id')
        sca_scan_id = scan_result.get('sca_scan_id')
        logger.info(f"[CODE INSIGHTS REPORT] Scan IDs - SAST: {sast_scan_id}, SCA: {sca_scan_id}")
        primary_scan_id = sast_scan_id or sca_scan_id
        scan_link = f"{self.asoc.getDataCenterURL()}/main/myapps/{self.appID}/scans/{primary_scan_id}" if primary_scan_id else self.asoc.getDataCenterURL()
        logger.info(f"[CODE INSIGHTS REPORT] Scan link generated: {scan_link}")
        
        # Build report data items
        logger.info("[CODE INSIGHTS REPORT] Building report data items")
        data_items = []
        if summary:
            data_items = [
                {"title": "Total Issues", "type": "NUMBER", "value": summary.get('total_issues', 0)},
                {"title": "Critical Issues", "type": "NUMBER", "value": summary.get('critical_issues', 0)},
                {"title": "High Issues", "type": "NUMBER", "value": summary.get('high_issues', 0)},
                {"title": "Medium Issues", "type": "NUMBER", "value": summary.get('medium_issues', 0)},
                {"title": "Low Issues", "type": "NUMBER", "value": summary.get('low_issues', 0)},
                {"title": "Informational Issues", "type": "NUMBER", "value": summary.get('info_issues', 0)},
            ]
            logger.info(f"[CODE INSIGHTS REPORT] Added issue count data items")
            # Add duration if available
            duration = summary.get('duration_seconds', 0)
            if duration:
                minutes = duration // 60
                data_items.append({"title": "Scan Duration (min)", "type": "NUMBER", "value": minutes})
                logger.info(f"[CODE INSIGHTS REPORT] Added scan duration: {minutes} minutes")
            # Add scan type info
            scan_types = []
            if sast_scan_id:
                scan_types.append("SAST")
            if sca_scan_id:
                scan_types.append("SCA")
            if scan_types:
                data_items.append({"title": "Scan Types", "type": "TEXT", "value": " + ".join(scan_types)})
                logger.info(f"[CODE INSIGHTS REPORT] Added scan types: {' + '.join(scan_types)}")
        logger.info(f"[CODE INSIGHTS REPORT] Total data items created: {len(data_items)}")
        
        # Build the details string
        logger.info("[CODE INSIGHTS REPORT] Building details string")
        details_parts = []
        if summary:
            details_parts.append(f"Found {total_issues} issue(s)")
            if self.fail_for_noncompliance:
                details_parts.append(f"Threshold: {self.failure_threshold}")
        details = " | ".join(details_parts) if details_parts else "Security scan completed"
        logger.info(f"[CODE INSIGHTS REPORT] Details: {details}")
        
        # Generate a deterministic UUID from the external_id for consistent report identification
        logger.info(f"[CODE INSIGHTS REPORT] Generating report UUID from external_id: {CODE_INSIGHTS_REPORT_ID}")
        report_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, CODE_INSIGHTS_REPORT_ID))
        logger.info(f"[CODE INSIGHTS REPORT] Generated report UUID: {report_uuid}")
        
        report_data = {
            "title": CODE_INSIGHTS_REPORT_TITLE,
            "details": details,
            "report_type": CODE_INSIGHTS_REPORT_TYPE,
            "reporter": CODE_INSIGHTS_REPORTER,
            "result": report_result,
            "uuid": report_uuid,
            "external_id": CODE_INSIGHTS_REPORT_ID,
            "logo_url": CODE_INSIGHTS_LOGO_URL,
            "link": scan_link,
            "data": data_items,
        }
        
        logger.info("[CODE INSIGHTS REPORT] Final report data structure:")
        logger.debug(f"[CODE INSIGHTS REPORT] {json.dumps(report_data, indent=2)}")
        logger.info(f"[CODE INSIGHTS REPORT] Calling code_insights.create_report() for commit: {self.commit}")
        
        try:
            result = code_insights.create_report(self.commit, report_data)
            logger.info(f"[CODE INSIGHTS REPORT] Report created successfully (result={report_result})")
            logger.debug(f"[CODE INSIGHTS REPORT] Report response: {json.dumps(result, indent=2) if result else 'None'}")
            # Extract the Bitbucket-assigned UUID to use for annotations
            report_uuid = result.get('uuid', CODE_INSIGHTS_REPORT_ID) if result else CODE_INSIGHTS_REPORT_ID
            logger.info(f"[CODE INSIGHTS REPORT] Final report UUID from Bitbucket: {report_uuid}")
            return report_uuid
        except Exception as e:
            logger.error(f"[CODE INSIGHTS REPORT] FAILED to create Code Insights report: {e}")
            logger.error(f"[CODE INSIGHTS REPORT] Exception type: {type(e).__name__}")
            import traceback
            logger.error(f"[CODE INSIGHTS REPORT] Full traceback: {traceback.format_exc()}")
            raise
    
    def _createCodeInsightsAnnotations(self, code_insights, scan_result, report_id):
        """
        Create Code Insights annotations from individual scan issues.
        Fetches issues from ASoC and maps them to file-level annotations.
        
        Args:
            code_insights: CodeInsights instance.
            scan_result: Dict with 'sast_scan_id' and/or 'sca_scan_id' keys.
            report_id: The report UUID or external_id to attach annotations to.
        """
        logger.info("[CODE INSIGHTS ANNOTATIONS] Starting _createCodeInsightsAnnotations")
        logger.info(f"[CODE INSIGHTS ANNOTATIONS] Report ID: {report_id}")
        logger.info(f"[CODE INSIGHTS ANNOTATIONS] Scan result: {scan_result}")
        logger.info(f"[CODE INSIGHTS ANNOTATIONS] Max annotations limit: {CODE_INSIGHTS_MAX_ANNOTATIONS}")
        
        all_issues = []
        for scan_type, scan_id in [('SAST', scan_result.get('sast_scan_id')),
                                    ('SCA', scan_result.get('sca_scan_id'))]:
            logger.info(f"[CODE INSIGHTS ANNOTATIONS] Processing {scan_type} scan - ID: {scan_id}")
            if scan_id is None:
                logger.info(f"[CODE INSIGHTS ANNOTATIONS] Skipping {scan_type} - no scan ID")
                continue
            logger.info(f"[CODE INSIGHTS ANNOTATIONS] Fetching {scan_type} issues from ASoC (limit: {CODE_INSIGHTS_MAX_ANNOTATIONS})...")
            try:
                issues = self.asoc.getScanIssues(scan_id, top=CODE_INSIGHTS_MAX_ANNOTATIONS)
                logger.info(f"[CODE INSIGHTS ANNOTATIONS] Successfully retrieved {len(issues)} {scan_type} issues")
                logger.debug(f"[CODE INSIGHTS ANNOTATIONS] Sample of first issue: {json.dumps(issues[0], indent=2) if issues else 'No issues'}")
            except Exception as e:
                logger.error(f"[CODE INSIGHTS ANNOTATIONS] FAILED to fetch {scan_type} issues: {e}")
                raise
            
            for issue in issues:
                issue['_scan_type'] = scan_type
                issue['_scan_id'] = scan_id
            all_issues.extend(issues)
            logger.info(f"[CODE INSIGHTS ANNOTATIONS] Added {len(issues)} {scan_type} issues to total")
        
        logger.info(f"[CODE INSIGHTS ANNOTATIONS] Total issues collected from all scans: {len(all_issues)}")
        
        if not all_issues:
            logger.info("[CODE INSIGHTS ANNOTATIONS] No issues to annotate - returning")
            return
        
        # Limit total annotations to max allowed
        if len(all_issues) > CODE_INSIGHTS_MAX_ANNOTATIONS:
            logger.warning(f"[CODE INSIGHTS ANNOTATIONS] Truncating {len(all_issues)} issues to {CODE_INSIGHTS_MAX_ANNOTATIONS} annotations (Bitbucket limit)")
            all_issues = all_issues[:CODE_INSIGHTS_MAX_ANNOTATIONS]
        else:
            logger.info(f"[CODE INSIGHTS ANNOTATIONS] Processing all {len(all_issues)} issues (within limit)")
        
        logger.info("[CODE INSIGHTS ANNOTATIONS] Building annotations from issues...")
        annotations = []
        annotations_skipped = 0
        
        for idx, issue in enumerate(all_issues):
            logger.debug(f"[CODE INSIGHTS ANNOTATIONS] Building annotation {idx + 1}/{len(all_issues)}")
            try:
                annotation = self._buildAnnotation(issue, idx)
                if annotation is None:
                    annotations_skipped += 1
                    logger.debug(f"[CODE INSIGHTS ANNOTATIONS] Annotation {idx} skipped (returned None)")
                    continue
                annotations.append(annotation)
                logger.debug(f"[CODE INSIGHTS ANNOTATIONS] Annotation {idx} built successfully")
            except Exception as e:
                logger.error(f"[CODE INSIGHTS ANNOTATIONS] Error building annotation {idx}: {e}")
                annotations_skipped += 1
        
        logger.info(f"[CODE INSIGHTS ANNOTATIONS] Built {len(annotations)} valid annotations, {annotations_skipped} skipped")
        
        if not annotations:
            logger.info(f"[CODE INSIGHTS ANNOTATIONS] No valid annotations to create ({annotations_skipped} total skipped) - returning")
            return
        
        logger.debug(f"[CODE INSIGHTS ANNOTATIONS] Sample annotation data: {json.dumps(annotations[0], indent=2) if annotations else 'None'}")
        
        # Use bulk annotations API for efficiency and to avoid per-annotation lookup issues
        logger.info(f"[CODE INSIGHTS ANNOTATIONS] Attempting to create {len(annotations)} annotations via bulk API")
        logger.info(f"[CODE INSIGHTS ANNOTATIONS] Calling create_bulk_annotations for commit: {self.commit}, report: {report_id}")
        try:
            code_insights.create_bulk_annotations(
                self.commit,
                report_id,
                annotations
            )
            logger.info(f"[CODE INSIGHTS ANNOTATIONS] SUCCESS: {len(annotations)} annotations created via bulk API, {annotations_skipped} skipped")
        except Exception as e:
            logger.warning(f"[CODE INSIGHTS ANNOTATIONS] Bulk annotations FAILED: {e}")
            logger.warning(f"[CODE INSIGHTS ANNOTATIONS] Exception type: {type(e).__name__}")
            import traceback
            logger.debug(f"[CODE INSIGHTS ANNOTATIONS] Full traceback: {traceback.format_exc()}")
            logger.info("[CODE INSIGHTS ANNOTATIONS] Falling back to individual annotation creation...")
            annotations_created = 0
            annotations_failed = 0
            for idx, annotation in enumerate(annotations):
                logger.debug(f"[CODE INSIGHTS ANNOTATIONS] Creating individual annotation {idx + 1}/{len(annotations)}")
                try:
                    code_insights.create_annotation(
                        self.commit,
                        report_id,
                        annotation
                    )
                    annotations_created += 1
                    logger.debug(f"[CODE INSIGHTS ANNOTATIONS] Individual annotation {idx} created successfully")
                except Exception as ann_e:
                    logger.debug(f"[CODE INSIGHTS ANNOTATIONS] Failed to create individual annotation {idx}: {ann_e}")
                    annotations_failed += 1
            logger.info(f"[CODE INSIGHTS ANNOTATIONS] Fallback complete: {annotations_created} created, {annotations_failed} failed, {annotations_skipped} skipped")
    
    def _buildAnnotation(self, issue, index):
        """
        Build a Code Insights annotation dict from an ASoC issue.
        
        Args:
            issue: ASoC issue dictionary.
            index: Index for unique external_id.
        
        Returns:
            dict: Annotation data, or None if the issue cannot be mapped.
        """
        logger.debug(f"[BUILD ANNOTATION] Starting _buildAnnotation for issue index {index}")
        logger.debug(f"[BUILD ANNOTATION] Issue data: {json.dumps(issue, indent=2)}")
        
        # Extract issue fields (ASoC issue structure)
        issue_id = issue.get("Id", str(index))
        severity = issue.get("Severity", "Informational")
        issue_type = issue.get("IssueType", "Security Issue")
        scan_type = issue.get("_scan_type", "")
        scan_id = issue.get("_scan_id", "")
        discovery_method = issue.get("DiscoveryMethod", scan_type)
        logger.debug(f"[BUILD ANNOTATION] Extracted fields - ID: {issue_id}, Severity: {severity}, Type: {issue_type}, Scan: {scan_type}")
        
        # Location info
        location = issue.get("Location", "")
        source_file = issue.get("SourceFile", "")
        line = issue.get("Line", None)
        logger.debug(f"[BUILD ANNOTATION] Location info - File: {source_file}, Line: {line}, Location: {location}")
        
        # Build summary: prefer ApiVulnName > Source > IssueType
        vuln_name = issue.get("ApiVulnName") or issue.get("Source") or issue_type
        summary = f"[{discovery_method}] {vuln_name}"
        logger.debug(f"[BUILD ANNOTATION] Built summary: {summary}")
        
        # Build details
        details_parts = []
        details_parts.append(f"Issue Type: {issue_type}")
        if location:
            details_parts.append(f"Location: {location}")
        if issue.get("Context"):
            details_parts.append(f"Context: {issue.get('Context')}")
        if issue.get("Cwe"):
            details_parts.append(f"CWE-{issue.get('Cwe')}")
        cve = issue.get("Cve")
        if cve and str(cve).strip():
            details_parts.append(f"CVE: {cve}")
        cvss = issue.get("Cvss")
        if cvss is not None:
            details_parts.append(f"CVSS: {cvss}")
        if issue.get("Scanner"):
            details_parts.append(f"Scanner: {issue.get('Scanner')}")
        details = " | ".join(details_parts) if details_parts else summary
        
        # Map severity
        bb_severity = SEVERITY_MAP_ASOC_TO_BB.get(severity, "LOW")
        logger.debug(f"[BUILD ANNOTATION] Mapped severity: ASoC '{severity}' -> BB '{bb_severity}'")
        
        # Build link to issue in ASoC
        link = f"{self.asoc.getDataCenterURL()}/main/myapps/{self.appID}/scans/{scan_id}/issues"
        logger.debug(f"[BUILD ANNOTATION] Issue link: {link}")
        
        annotation = {
            "external_id": f"asoc-{scan_type.lower()}-{issue_id}",
            "annotation_type": CODE_INSIGHTS_ANNOTATION_TYPE,
            "summary": summary[:450],  # Bitbucket limits summary length
            "details": details[:2000],  # Bitbucket limits details length
            "severity": bb_severity,
            "result": "FAILED",
            "link": link,
        }
        
        # Add file path and line if available
        if source_file:
            annotation["path"] = source_file
            logger.debug(f"[BUILD ANNOTATION] Added file path: {source_file}")
        if line is not None:
            try:
                annotation["line"] = int(line)
                logger.debug(f"[BUILD ANNOTATION] Added line number: {line}")
            except (ValueError, TypeError):
                logger.debug(f"[BUILD ANNOTATION] Could not parse line number: {line}")
        
        logger.debug(f"[BUILD ANNOTATION] Final annotation: {json.dumps(annotation, indent=2)}")
        return annotation

    def _logScanSummary(self, label, summary):
        """Log a scan summary with a label."""
        seconds = summary["duration_seconds"] % SECONDS_PER_DAY
        hour = seconds // 3600
        seconds %= 3600
        minutes = seconds // 60
        seconds %= 60
        durationStr = "%d:%02d:%02d" % (hour, minutes, seconds)
        logger.info(f"{label} Scan Summary:")
        logger.info(f"\tDuration: {durationStr}")
        logger.info(f'\tTotal Issues: {summary["total_issues"]}')
        logger.info(f'\t\tCritical Issues: {summary["critical_issues"]}')
        logger.info(f'\t\tHigh Issues: {summary["high_issues"]}')
        logger.info(f'\t\tMed Issues: {summary["medium_issues"]}')
        logger.info(f'\t\tLow Issues: {summary["low_issues"]}')
        logger.info(f'\t\tInfo Issues: {summary["info_issues"]}')
        logger.debug(f"{label} Scan Summary:\n" + json.dumps(summary, indent=2))

    def _combineSummaries(self, summaries):
        """Combine multiple scan summaries into a single aggregated summary.
        
        Args:
            summaries: dict keyed by scan type ('SAST', 'SCA') with summary dicts as values
        
        Returns:
            Combined summary dict with aggregated issue counts
        """
        if not summaries:
            return None
        if len(summaries) == 1:
            return list(summaries.values())[0]
        
        combined = {
            "scan_name": " + ".join(s.get("scan_name", "Unknown") for s in summaries.values()),
            "scan_ids": {k: v.get("scan_id") for k, v in summaries.items()},
            "duration_seconds": max(s.get("duration_seconds", 0) for s in summaries.values()),
            "critical_issues": sum(s.get("critical_issues", 0) for s in summaries.values()),
            "high_issues": sum(s.get("high_issues", 0) for s in summaries.values()),
            "medium_issues": sum(s.get("medium_issues", 0) for s in summaries.values()),
            "low_issues": sum(s.get("low_issues", 0) for s in summaries.values()),
            "info_issues": sum(s.get("info_issues", 0) for s in summaries.values()),
            "total_issues": sum(s.get("total_issues", 0) for s in summaries.values()),
        }
        return combined
        
    def exportScanResults(self, summary, scan_result, reportsDir):
        """
        Export scan results as environment variables and output files
        for use in subsequent Bitbucket Pipeline steps
        """
        sast_scan_id = scan_result.get('sast_scan_id', '')
        sca_scan_id = scan_result.get('sca_scan_id', '')
        
        # Create output files that can be sourced in bash or parsed
        outputFile = os.path.join(reportsDir, SCAN_RESULTS_FILENAME)
        envFile = os.path.join(reportsDir, SCAN_ENV_FILENAME)
        
        # Write human-readable output
        with open(outputFile, 'w') as f:
            if sast_scan_id:
                f.write(f"SAST_SCAN_ID={sast_scan_id}\n")
            if sca_scan_id:
                f.write(f"SCA_SCAN_ID={sca_scan_id}\n")
            f.write(f"SCAN_NAME={summary['scan_name']}\n")
            f.write(f"TOTAL_ISSUES={summary['total_issues']}\n")
            f.write(f"CRITICAL_ISSUES={summary['critical_issues']}\n")
            f.write(f"HIGH_ISSUES={summary['high_issues']}\n")
            f.write(f"MEDIUM_ISSUES={summary['medium_issues']}\n")
            f.write(f"LOW_ISSUES={summary['low_issues']}\n")
            f.write(f"INFO_ISSUES={summary['info_issues']}\n")
            f.write(f"SCAN_DURATION_SECONDS={summary['duration_seconds']}\n")
            if 'createdAt' in summary:
                f.write(f"CREATED_AT={summary['createdAt']}\n")
        
        # Write shell-sourceable environment variables
        with open(envFile, 'w') as f:
            if sast_scan_id:
                f.write(f"export ASOC_SAST_SCAN_ID='{sast_scan_id}'\n")
                f.write(f"export ASOC_SAST_SCAN_URL='{self.asoc.getDataCenterURL()}/main/myapps/{self.appID}/scans/{sast_scan_id}'\n")
            if sca_scan_id:
                f.write(f"export ASOC_SCA_SCAN_ID='{sca_scan_id}'\n")
                f.write(f"export ASOC_SCA_SCAN_URL='{self.asoc.getDataCenterURL()}/main/myapps/{self.appID}/scans/{sca_scan_id}'\n")
            f.write(f"export ASOC_SCAN_NAME='{summary['scan_name']}'\n")
            f.write(f"export ASOC_TOTAL_ISSUES={summary['total_issues']}\n")
            f.write(f"export ASOC_CRITICAL_ISSUES={summary['critical_issues']}\n")
            f.write(f"export ASOC_HIGH_ISSUES={summary['high_issues']}\n")
            f.write(f"export ASOC_MEDIUM_ISSUES={summary['medium_issues']}\n")
            f.write(f"export ASOC_LOW_ISSUES={summary['low_issues']}\n")
            f.write(f"export ASOC_INFO_ISSUES={summary['info_issues']}\n")
            f.write(f"export ASOC_SCAN_DURATION_SECONDS={summary['duration_seconds']}\n")
        
        logger.info(f"Scan results exported to: {outputFile}")
        logger.info(f"Environment variables exported to: {envFile}")
        logger.info("To use in next pipeline step, add 'source reports/scan_env.sh' or parse scan_results.txt")

    def exportReportPaths(self, report_paths, summary_paths, reportsDir):
        """
        Export report file paths for artifact collection
        
        Args:
            report_paths: dict keyed by scan type ('SAST', 'SCA') with HTML report paths
            summary_paths: dict keyed by scan type ('SAST', 'SCA') with JSON summary paths
            reportsDir: path to reports directory
        """
        pathsFile = os.path.join(reportsDir, REPORT_PATHS_FILENAME)
        with open(pathsFile, 'w') as f:
            for scan_type in ['SAST', 'SCA']:
                if scan_type in report_paths:
                    f.write(f"{scan_type}_HTML_REPORT={report_paths[scan_type]}\n")
                if scan_type in summary_paths:
                    f.write(f"{scan_type}_JSON_SUMMARY={summary_paths[scan_type]}\n")
            f.write(f"REPORTS_DIR={reportsDir}\n")
        
        logger.info(f"Report paths exported to: {pathsFile}")
        logger.info("")
        logger.info("=" * 55)
        logger.info("PIPELINE OUTPUT SUMMARY")
        logger.info("=" * 55)
        for scan_type in ['SAST', 'SCA']:
            if scan_type in report_paths:
                logger.info(f"{scan_type} HTML Report: {report_paths[scan_type]}")
            if scan_type in summary_paths:
                logger.info(f"{scan_type} JSON Summary: {summary_paths[scan_type]}")
        logger.info(f"Scan Results: {os.path.join(reportsDir, SCAN_RESULTS_FILENAME)}")
        logger.info(f"Environment File: {os.path.join(reportsDir, SCAN_ENV_FILENAME)}")
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
        url = self.asoc.getDataCenterURL() + SACLIENT_DOWNLOAD_ENDPOINT
        logger.info(f"Downloading SAClientUtil Zip from: {url}")
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
        chunk_size = DOWNLOAD_CHUNK_SIZE
        xfered = 0
        percent = 0
        start = time.time()
        save_path = os.path.join(self.cwd, SACLIENT_ZIP_FILENAME)
        with open(save_path, 'wb') as fd:
            for chunk in r.iter_content(chunk_size=chunk_size):
                fd.write(chunk)
                xfered += len(chunk)
                if file_size:
                    percent = round((xfered/file_size)*100)
                else:
                    percent = 0
                if(time.time()-start > DOWNLOAD_LOG_INTERVAL_SECS):
                    logger.info(f"SAClientUtil Download: {percent}%")
                    start = time.time()
        logger.info(f"SAClientUtil Download: {percent}%")

        # Check if the downloaded file is a valid zip
        if r.headers.get('content-type', '').lower() != CONTENT_TYPE_ZIP:
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
                os.chmod(os.path.join(root, d), FILE_PERMISSION_MODE)
            for f in files:
                os.chmod(os.path.join(root, f), FILE_PERMISSION_MODE)

        #Find the appscan executable
        logger.debug("Finding appscan bin path")
        appscanPath = None
        dirs = os.listdir(saclientPath)
        for file in dirs:
            appscanPath = os.path.join(self.cwd, saclientPath, file, "bin", APPSCAN_BIN_NAME)

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
    
    #Create the SAST/SCA scan(s) based on an IRX File
    #If Wait=True the function will sleep until the scan(s) are complete
    def _waitForScan(self, scanId, label=""):
        """Wait for a single scan to complete. Returns (scanId, execution)."""
        logger.info(f"Waiting for {label} scan [{scanId}] to complete...")
        execution = self.asoc.getScanStatus(scanId)
        status = execution["Status"] if execution else SCAN_STATUS_ABORT
        progress = execution.get("Progress", "N/A") if execution else "N/A"
        scan_start = time.time()
        while(status not in [SCAN_STATUS_READY, SCAN_STATUS_ABORT]):
            elapsed = time.time() - scan_start
            if elapsed >= SCAN_MAX_WAIT_SECS:
                logger.error(f"{label} scan [{scanId}] timed out after {SCAN_MAX_WAIT_SECS}s")
                execution = None
                break
            time.sleep(SCAN_POLL_INTERVAL_SECS)
            execution = self.asoc.getScanStatus(scanId)
            status = execution["Status"] if execution else SCAN_STATUS_ABORT
            progress = execution.get("Progress", "N/A") if execution else "N/A"
            logger.info(f"\t{label} scan [{scanId}] status={status}, progress={progress}")
        
        if(status == SCAN_STATUS_READY):
            logger.info(f"{label} Scan [{scanId}] Complete")
        elif execution is not None:
            logger.error(f"{label} scan returned invalid status... check login?")
            logger.error("If script continues, the scan might not be complete")
            execution = None
        return (scanId, execution)

    def runScan(self, scanName, appId, irxPath, comment="", wait=True, personal_scan=False):
        """Create and run scan(s) based on scan mode.
        
        Returns a dict with 'sast_scan_id' and/or 'sca_scan_id' keys,
        or None on error.
        
        - STATIC_ANALYSIS_ONLY: runs SAST scan only
        - OPEN_SOURCE_ONLY: runs SCA scan only
        - Neither: runs both SAST and SCA scans in parallel
        """
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
        
        #Upload the IRX File and get a FileId
        logger.debug("Uploading IRX File")
        fileId = self.asoc.uploadFile(irxPath)
        if(fileId is None):
            logger.error("Error uploading IRX File")
            return None
        logger.debug(f"IRX FileId: [{fileId}]")
        
        #Create scan(s) based on mode
        scan_result = {}
        
        if self.static_analysis_only:
            logger.info("Creating SAST scan (Static Analysis Only)")
            sast_id = self.asoc.createSastScan(scanName, appId, fileId, comment, personal_scan)
            if sast_id:
                scan_result['sast_scan_id'] = sast_id
                logger.info(f"SAST ScanId: [{sast_id}]")
            else:
                logger.error("SAST scan not created!")
                return None
        elif self.open_source_only:
            logger.info("Creating SCA scan (Open Source Only)")
            sca_id = self.asoc.createScaScan(scanName, appId, fileId, comment, personal_scan)
            if sca_id:
                scan_result['sca_scan_id'] = sca_id
                logger.info(f"SCA ScanId: [{sca_id}]")
            else:
                logger.error("SCA scan not created!")
                return None
        else:
            logger.info("Creating both SAST and SCA scans")
            sast_id = self.asoc.createSastScan(scanName, appId, fileId, comment, personal_scan)
            sca_id = self.asoc.createScaScan(scanName, appId, fileId, comment, personal_scan)
            if sast_id:
                scan_result['sast_scan_id'] = sast_id
                logger.info(f"SAST ScanId: [{sast_id}]")
            else:
                logger.error("SAST scan not created!")
                return None
            if sca_id:
                scan_result['sca_scan_id'] = sca_id
                logger.info(f"SCA ScanId: [{sca_id}]")
            else:
                logger.error("SCA scan not created!")
                return None
        
        #If Wait=False, return now with scan_result
        if(wait == False):
            logger.info("Do not wait for scan(s) to complete, return immediately")
            return scan_result
        
        #Wait for all scans in parallel
        self.lastExecutions = {}
        scans_to_wait = []
        if 'sast_scan_id' in scan_result:
            scans_to_wait.append(('SAST', scan_result['sast_scan_id']))
        if 'sca_scan_id' in scan_result:
            scans_to_wait.append(('SCA', scan_result['sca_scan_id']))
        
        with ThreadPoolExecutor(max_workers=len(scans_to_wait)) as executor:
            futures = {
                executor.submit(self._waitForScan, scan_id, label): (label, scan_id)
                for label, scan_id in scans_to_wait
            }
            for future in as_completed(futures):
                label, scan_id = futures[future]
                try:
                    _, execution = future.result()
                    self.lastExecutions[scan_id] = execution
                except Exception as e:
                    logger.error(f"Error waiting for {label} scan: {e}")
                    self.lastExecutions[scan_id] = None
        
        return scan_result
    
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
					"ReportFileType": DEFAULT_REPORT_FILE_TYPE,
					"Title": DEFAULT_REPORT_TITLE,
                    "Notes": note
				}
        }
        reportId = self.asoc.startReport(scanId, reportConfig)
        if(reportId is None):
            logger.error("Error starting report")
            return None
        
        statusMsg = self.asoc.reportStatus(reportId)
        while(statusMsg["Items"][0].get("Status") not in [SCAN_STATUS_READY, SCAN_STATUS_ABORT]):
            time.sleep(REPORT_POLL_INTERVAL_SECS)
            statusMsg = self.asoc.reportStatus(reportId)
            percent = statusMsg["Items"][0].get("Progress")
            logger.info(f"Report Progress: {percent}%")
        
        if(statusMsg["Items"][0].get("Status") != SCAN_STATUS_READY):
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
        executions = getattr(self, 'lastExecutions', {})
        execution = executions.get(scanId)
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
        return datetime.datetime.fromtimestamp(ts).strftime(TIMESTAMP_FORMAT)
    
        
if __name__ == '__main__':
    pipe = AppScanOnCloudSAST(pipe_metadata='/pipe.yml', schema=schema)
    pipe.run()
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    