from httpdiff import Baseline, Response
from httpinsert.location import Location

from threading import Thread, BoundedSemaphore, Lock
import random
import time
import string

import sys

from urllib.parse import urlunparse, quote,urlparse, unquote

class BatteringRam:
    def __init__(self, options, custom_blob=None):
        self.custom_blob=custom_blob
        self.stop=False
        self.options=options
        self.baseline = None
        self.job_lock = BoundedSemaphore(self.options.args.threads)
        self.calibration_lock = Lock()
        self.calibrating = False


    def calibrate_baseline(self,insertion_point):
        baseline = self.baseline or Baseline(custom_blob=self.custom_blob)
        baseline.verbose = self.options.args.verbose
        baseline.analyze_all = not self.options.args.no_analyze_all
        self.options.logger.verbose(f"Calibration baseline")

        for i in range(self.options.args.num_calibrations):
            payload= ''.join(random.choices(string.ascii_uppercase + string.digits, k=random.randint(10,20)))
            sleep_time = self.options.args.calibration_sleep/1000 or self.options.args.sleep/1000
            time.sleep(sleep_time)
            resp,response_time,error,_= self.send(insertion_point,payload)
            if error and self.options.args.ignore_errors is False:
                self.stop=True
                self.options.logger.critical(f"Error occurred during calibration, stopping scan as ignore-errors is not set - {error}")
                return None
            if error:
                self.options.logger.debug(error)
            baseline.add_response(resp,response_time,error,payload)

        time.sleep(self.options.args.sleep)
        resp, response_time, error,_= self.send(insertion_point,payload)
        if error and self.options.args.ignore_errors is False:
            self.stop=True
            self.options.logger.critical(f"Error occurred during calibration, stopping scan as ignore-errors is not set - {error}")
        if error:
            self.options.logger.debug(error)
        baseline.add_response(resp,response_time,error,payload)
        self.options.logger.verbose("Done calibrating")
        return baseline



    def send(self,insertion_points,payload):
        time.sleep(self.options.args.sleep)
        insertions = []
        for insertion_point in insertion_points:
            insertion = insertion_point.insert(payload,self.options.req,format_payload=True,default_encoding=not self.options.args.disable_encoding)
            insertions.append(insertion)
        resp,response_time,error = self.options.req.send(debug=self.options.args.debug,insertions=insertions,allow_redirects=self.options.args.allow_redirects,timeout=self.options.args.timeout,verify=self.options.args.verify,proxies=self.options.proxies)
        resp=Response(resp)
        return resp,response_time,error,insertion



    def check_payload(self,payload1,insertion_points,checks=0):
        payload2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=random.randint(10,20)))

        if self.baseline is None:
            self.calibration_lock.acquire()
            if self.baseline is None:
                self.baseline =  self.calibrate_baseline(insertion_points)
            self.calibration_lock.release()
            
        if self.stop is True:
            self.job_lock.release()
            return

        resp,response_time,error,insertion1 = self.send(insertion_points,payload1)
        if error:
            self.options.logger.debug(error)

        diffs = list(self.baseline.find_diffs(resp,response_time,error))

        if not diffs:
            self.job_lock.release()
            return
        resp2,response_time2,error2,_= self.send(insertion_points,payload2)
        if error2:
            self.options.logger.debug(error2)

        if self.stop is True:
            self.job_lock.release()
            return

        diffs2 = list(self.baseline.find_diffs(resp2,response_time2,error2))
        sections_diffs2_len = {}
        for i in diffs2:
            if i["section"] not in sections_diffs2_len.keys():
                sections_diffs2_len[i["section"]] = 0
            sections_diffs2_len[i["section"]] += len(i["diffs"])
        for _ in diffs2:
            if self.calibrating is True:
                self.calibration_lock.acquire() # Wait for calibration to finish
                self.calibration_lock.release()
                return self.check_payload(payload1,insertion_points,checks=checks)
            self.calibration_lock.acquire()
            self.calibrating = True
            self.options.logger.verbose(f"Baseline changed, calibrating again - {sections_diffs2_len}")
            self.baseline = self.calibrate_baseline(insertion_points)
            self.calibration_lock.release()
            self.calibrating = False
            return self.check_payload(payload1,insertion_points,checks=checks)

            
        if checks >= self.options.args.num_verifications:
            diffs_sections={}
            for i in diffs:
                if i["section"] not in diffs_sections.keys():
                    diffs_sections[i["section"]] = 0
                diffs_sections[i["section"]] += len(i["diffs"])

            self.options.logger.debug(f"Diffs:\n{str(diffs)}\n")
            self.options.logger.info(f"Found diff\nPayload: {insertion1.payload}\nDiffs: {diffs_sections}\n")
        else:
            return self.check_payload(payload1,insertion_points,checks=checks+1)
        self.job_lock.release()


    def scan(self, insertion_points):
        with open(self.options.args.wordlist, "r") as f:
            wordlist = f.read().splitlines()

        jobs=[]
        for payload in wordlist:
            if payload.startswith("URLENCODED:"):
                payload = payload.split("URLENCODED:")[1]
                payload = unquote(payload) # URL decoding
            self.job_lock.acquire()
            if self.stop is True:
                return
            job = Thread(target=self.check_payload,args=(payload,insertion_points))
            jobs.append(job)
            job.start()

        for job in jobs:
            job.join()
