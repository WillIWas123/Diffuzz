from httpdiff import Baseline, Response
from httpinsert.location import Location

from threading import Thread, BoundedSemaphore, Lock
import random
import time
import string

import sys

from urllib.parse import urlunparse, quote,urlparse,unquote

class DualSniper: # Sniper that compares payload1 to payload2
    def __init__(self, options):
        self.stop=False
        self.options=options
        self.baselines={}
        self.job_lock = BoundedSemaphore(self.options.args.threads)
        self.calibration_lock = Lock()
        self.calibrating = {}


    def calibrate_baseline(self,insertion_point):
        if self.stop is True:
            return None
        baseline = self.baselines.get(insertion_point, Baseline())
        baseline.verbose = self.options.args.verbose
        baseline.analyze_all = not self.options.args.no_analyze_all
        self.options.logger.verbose(f"Calibration baseline for {insertion_point}")

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
            return None
        if error:
            self.options.logger.debug(error)
        baseline.add_response(resp,response_time,error,payload)
        self.options.logger.verbose(f"Done calibrating for {insertion_point}")
        return baseline



    def send(self,insertion_point,payload):
        time.sleep(self.options.args.sleep)
        insertion = insertion_point.insert(payload,self.options.req,format_payload=True,default_encoding=not self.options.args.disable_encoding)
        if self.stop is True:
            return None, 0.0, b"self.stop is True, terminating execution", insertion
        resp,response_time,error = self.options.req.send(debug=self.options.args.debug,insertions=[insertion],allow_redirects=self.options.args.allow_redirects,timeout=self.options.args.timeout,verify=self.options.args.verify,proxies=self.options.proxies)
        resp=Response(resp)
        return resp,response_time,error,insertion



    def check_payload(self,payload1,payload2,insertion_point,checks=0):
        payload3 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=random.randint(10,20)))

        if self.baselines.get(insertion_point) is None:
            self.calibration_lock.acquire()
            if self.baselines.get(insertion_point) is None:
                self.baselines[insertion_point] =  self.calibrate_baseline(insertion_point)
            self.calibration_lock.release()
        baseline = self.baselines[insertion_point]
        if self.stop is True:
            self.job_lock.release()
            return

        resp,response_time,error,insertion1 = self.send(insertion_point,payload1)
        if error:
            self.options.logger.debug(error)

        resp2,response_time2,error2,insertion2 = self.send(insertion_point,payload2)
        if error2:
            self.options.logger.debug(error2)

        
        diffs = list(baseline.find_diffs(resp,response_time,error))
        diffs2 = list(baseline.find_diffs(resp2,response_time2,error2))

        if diffs == diffs2:
            self.job_lock.release()
            return

        resp3,response_time3,error3,_= self.send(insertion_point,payload3)
        if error3:
            self.options.logger.debug(error3)

        if self.stop is True:
            self.job_lock.release()
            return

        diffs3 = list(self.baselines[insertion_point].find_diffs(resp3,response_time3,error3))
        sections_diffs3_len = {}
        for i in diffs3:
            if i["section"] not in sections_diffs3_len.keys():
                sections_diffs3_len[i["section"]] = 0
            sections_diffs3_len[i["section"]] += len(i["diffs"])
        for _ in diffs3:
            if self.calibrating.get(insertion_point) is True:
                self.calibration_lock.acquire() # Wait for calibration to finish
                self.calibration_lock.release()
                return self.check_payload(payload1,payload2,insertion_point,checks=checks)
            self.calibration_lock.acquire()
            self.calibrating[insertion_point] = True
            self.options.logger.verbose(f"Baseline for {insertion_point} changed, calibrating again - {sections_diffs3_len}")
            self.baselines[insertion_point] = self.calibrate_baseline(insertion_point)
            self.calibration_lock.release()
            self.calibrating[insertion_point] = False
            return self.check_payload(payload1,payload2,insertion_point,checks=checks)

            
        if checks >= self.options.args.num_verifications:
            sections_diffs_len = {}
            for i in diffs:
                if i["section"] not in sections_diffs_len.keys():
                    sections_diffs_len[i["section"]] = [0,0]
                sections_diffs_len[i["section"]][0] += len(i["diffs"])
            for i in diffs2:
                if i["section"] not in sections_diffs_len.keys():
                    sections_diffs_len[i["section"]] = [0,0]
                sections_diffs_len[i["section"]][1] += len(i["diffs"])

            self.options.logger.info(f"Found diff\nInsertion point: {insertion_point}\nPayload1: {insertion1.payload}\nPayload2: {insertion2.payload}\ndiffs: {sections_diffs_len}\n")

        else:
            return self.check_payload(payload1,payload2,insertion_point,checks=checks+1)
        self.job_lock.release()


    def scan(self,insertion_points):
        with open(self.options.args.wordlist, "r") as f:
            wordlist = f.read().splitlines()

        jobs=[]
        for insertion_point in insertion_points:
            for word in wordlist:
                if word.startswith("URLENCODED:"):
                    word = word.split("URLENCODED")[1]
                    word = unquote(word) # URL decoding
                self.job_lock.acquire()
                payload1,payload2 = word.split("§§§§")
                if self.stop is True:
                    return
                job = Thread(target=self.check_payload,args=(payload1,payload2,insertion_point))
                jobs.append(job)
                job.start()

        for job in jobs:
            job.join()
