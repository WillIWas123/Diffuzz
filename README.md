# Diffuzz

A fuzzer finding vulnerabilities based on response diffing

- [Disclaimers](https://github.com/WillIWas123/Diffuzz#disclaimers)
- [Requirements](https://github.com/WillIWas123/Diffuzz#requirements)
- [Usage](https://github.com/WillIWas123/Diffuzz#usage)
- [Why](https://github.com/WillIWas123/Diffuzz#usecases)
- [Help](https://github.com/WillIWas123/Diffuzz#example-usage)

## Disclaimers

- This is considered to be a beta release, and may contain bugs and unintentional behavior. Consider yourself warned!

## Requirements

Diffuzz requires [HTTPDiff](https://github.com/WillIWas123/HTTPDiff) and [HTTPInsert](https://github.com/WillIWas123/HTTPInsert) which can be install with `python3 -m pip install httpdiff httpinsert` or `python3 -m pip install -r requirements.txt`.

## Why

Why create another fuzzer when so many already exists?

Most (not all) fuzzing tools rely on hardcoded values or regexes for differentiating responses. This is simply not good enough in many cases. This tool is made to minimize false-negatives, and to find vulnerabilities that are easily overlook by utilizing hardcoded values, regexes, and even manual testing. Some tools do provide advanced filtering, which still is not good enough for discovering minor deviations in responses.

[Diffuzz](https://github.com/WillIWas123/Diffuzz) uses [HTTPDiff](https://github.com/WillIWas123/HTTPDiff) to analyze all sections of the responses; the status code, reason, headers, body, response times, errors, etc. This allows the fuzzer to find minor deviations in behavior, which may be a vulnerability or perhaps some noteworthy behavior.

## Usage

```
$ diffuzz -u https://example.site/endpoint?param=value -w wordlists/sqli.txt
[INFO] Found diff
Insertion point: <InsertionPoint location=Query location_key=query key=param value=value>
Payload1: dwzajSOliSlhKyVELLvyRVL' or '3680'='3680' or '3680'='1675
Payload2: gHjaKhZVperxCVRRXIpSsiDDv' or '7934'='5698' or '7934'='5698
diffs: {'body': [25, 0]}
```

## Help

```
usage: diffuzz [-h] (--url URL | --request REQUEST) --wordlist WORDLIST [--method METHOD] [--header HEADER [HEADER ...]] [--body BODY] [--https] [--proxy PROXY] [--threads THREADS]
               [--allow-redirects] [--verify] [--disable-encoding] [--verbose] [--debug] [--scan-query] [--scan-path] [--scan-headers] [--scan-body] [--scan-type SCAN_TYPE]
               [--sleep SLEEP] [--calibration-sleep CALIBRATION_SLEEP] [--timeout TIMEOUT] [--ignore-errors] [--no-analyze-all] [--num-calibrations NUM_CALIBRATIONS]
               [--num-verifications NUM_VERIFICATIONS] [--word WORD]

An awesome web fuzzer

options:
  -h, --help            show this help message and exit
  --wordlist WORDLIST, -w WORDLIST
                        Specify wordlist to use

target:
  --url URL, -u URL
  --request REQUEST, --req REQUEST, -r REQUEST
                        Specify a file containing a raw request for scanning

request:
  --method METHOD, -m METHOD
  --header HEADER [HEADER ...]
  --body BODY, -b BODY  Specify content to be in the body of the request
  --https, --tls
  --proxy PROXY, -p PROXY
  --threads THREADS, -t THREADS
  --allow-redirects, -ar
                        Specify if requests should follow redirects
  --verify              Verify SSL certificates
  --disable-encoding    Disable default encoding of payloads

verbosisty:
  --verbose, -v
  --debug, -d

scan:
  --scan-query
  --scan-path
  --scan-headers
  --scan-body
  --scan-type SCAN_TYPE
                        Specify which type of scan to perform (Sniper, DualSniper, PitchFork, DualPitchFork, ClusterBomb, DualClusterBomb, BatteringRam, DualBatterinRam)
  --sleep SLEEP, -s SLEEP
                        Determines how long (ms) the scanner should sleep between each request during scan
  --calibration-sleep CALIBRATION_SLEEP, -cs CALIBRATION_SLEEP
                        Determines how long (ms) the scanner should sleep between each request while calibrating
  --timeout TIMEOUT     Determines the timeout duration (s) for each request
  --ignore-errors, -ie  Ignore errors if any errors occurs during calibration

analyzer:
  --no-analyze-all      Make analyzer skip analyzing the body if the content length is static
  --num-calibrations NUM_CALIBRATIONS
                        Specify how many requests should be sent during calibration
  --num-verifications NUM_VERIFICATIONS
                        Specify how many times an endpoint should be verified/re-tested
  --word WORD           Specify a specific word to search for in responses
```
