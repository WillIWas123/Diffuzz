from httpdiff import Baseline, Response
from httpinsert.location import Location

from threading import Thread, BoundedSemaphore, Lock
import random
import time
import string

import sys

from urllib.parse import urlunparse, quote,urlparse,unquote

class Sniper:
    def __init__(self, options, custom_blob=None):
        self.custom_blob = custom_blob
        self.stop=False
        self.options=options
        self.baselines={}
        self.job_lock = BoundedSemaphore(self.options.args.threads)
        self.calibration_lock = Lock()
        self.calibrating = {}


    def calibrate_baseline(self,insertion_point):
        if self.stop is True:
            return None
        baseline = self.baselines.get(insertion_point, Baseline(custom_blob=self.custom_blob))
        baseline.verbose = self.options.args.verbose
        baseline.analyze_all = not self.options.args.no_analyze_all
        self.options.logger.verbose(f"Calibration baseline for {insertion_point}")

        sleep_time = self.options.args.calibration_sleep/1000 or self.options.args.sleep/1000
        for i in range(self.options.args.num_calibrations):
            payload= ''.join(random.choices(string.ascii_uppercase + string.digits, k=random.randint(10,20)))
            time.sleep(sleep_time)
            resp,response_time,error,_= self.send(insertion_point,payload)
            if error and self.options.args.ignore_errors is False:
                self.stop=True
                self.options.logger.critical(f"Error occurred during calibration, stopping scan as ignore-errors is not set - {error}")
                return None
            baseline.add_response(resp,response_time,error,payload)

        time.sleep(sleep_time)
        resp, response_time, error,_= self.send(insertion_point,payload)
        if error and self.options.args.ignore_errors is False:
            self.stop=True
            self.options.logger.critical(f"Error occurred during calibration, stopping scan as ignore-errors is not set - {error}")
            return None
        baseline.add_response(resp,response_time,error,payload)
        self.options.logger.verbose(f"Done calibrating for {insertion_point}")
        return baseline



    def send(self,insertion_point,payload):
        time.sleep(self.options.args.sleep/1000)
        insertion = insertion_point.insert(payload,self.options.req,format_payload=True,default_encoding=not self.options.args.disable_encoding)
        resp,response_time,error = self.options.req.send(debug=self.options.args.debug,insertions=[insertion],allow_redirects=self.options.args.allow_redirects,timeout=self.options.args.timeout,verify=self.options.args.verify,proxies=self.options.proxies)
        if error:
            self.options.logger.debug(f"Error occured while sending request: {error}")
            error = str(type(error)).encode()
        resp=Response(resp)
        return resp,response_time,error,insertion



    def check_payload(self,payload1,insertion_point,url_encoded, checks=0):
        payload2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=random.randint(10,20)))

        if self.baselines.get(insertion_point) is None:
            self.calibration_lock.acquire()
            if self.baselines.get(insertion_point) is None:
                self.baselines[insertion_point] =  self.calibrate_baseline(insertion_point)
            self.calibration_lock.release()
        baseline = self.baselines[insertion_point]
        if self.stop is True:
            self.job_lock.release()
            return

        resp,response_time,error,insertion1= self.send(insertion_point,payload1)

        diffs = list(baseline.find_diffs(resp,response_time,error))

        if not diffs:
            self.job_lock.release()
            return
        resp2,response_time2,error2,_= self.send(insertion_point,payload2)

        if self.stop is True:
            self.job_lock.release()
            return
        diffs2 = list(self.baselines[insertion_point].find_diffs(resp2,response_time2,error2))
        sections_diffs2_len = {}
        for i in diffs2:
            if i["section"] not in sections_diffs2_len.keys():
                sections_diffs2_len[i["section"]] = 0
            sections_diffs2_len[i["section"]] += len(i["diffs"])
        for _ in diffs2:
            if self.calibrating.get(insertion_point) is True:
                self.calibration_lock.acquire() # Wait for calibration to finish
                self.calibration_lock.release()
                return self.check_payload(payload1,insertion_point,url_encoded, checks=checks)
            self.calibration_lock.acquire()
            self.calibrating[insertion_point] = True
            self.options.logger.verbose(f"Baseline for {insertion_point} changed, calibrating again - {sections_diffs2_len}")
            self.baselines[insertion_point] = self.calibrate_baseline(insertion_point)
            self.calibration_lock.release()
            self.calibrating[insertion_point] = False
            return self.check_payload(payload1,insertion_point,url_encoded, checks=checks)

            
        diffs_sections={}
        if checks >= self.options.args.num_verifications:
            if self.options.args.verbose:
                for i in diffs:
                    if i["section"] not in diffs_sections.keys():
                        diffs_sections[i["section"]] = 0
                    diffs_sections[i["section"]] += len(i["diffs"])

            self.options.logger.debug(f"Diffs:\n{str(diffs)}\n")
            payload1 = insertion1.payload
            if url_encoded is True:
                payload1 = f"URLENCODED:{quote(payload1)}"
            self.options.logger.info(f"Found diff\nInsertion point: {insertion_point}\nPayload: {payload1}\nDiffs: {diffs_sections}\n")
        else:
            return self.check_payload(payload1,insertion_point,url_encoded, checks=checks+1)
        self.job_lock.release()


    def scan(self, insertion_points):
        with open(self.options.args.wordlist, "r") as f:
            wordlist = f.read().splitlines()

        jobs=[]
        for insertion_point in insertion_points:
            for payload in wordlist:
                url_encoded=False
                if payload.startswith("URLENCODED:"):
                    payload = payload.split("URLENCODED:")[1]
                    payload = unquote(payload) # URL decoding
                    url_encoded=True
                self.job_lock.acquire()
                if self.stop is True:
                    return
                job = Thread(target=self.check_payload,args=(payload,insertion_point,url_encoded))
                jobs.append(job)
                job.start()

        for job in jobs:
            job.join()
