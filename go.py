#!/usr/bin/python

import requests
import json
import os
import pprint
from time import sleep
from sets import Set
import traceback

from utils import *

test_sets = grabYamls()
raw_tests = parseYamls(test_sets)

#parsed powershell executor list
executors_powershell = raw_tests[0]
#parsed cmd executor list
executors_command = raw_tests[1]
#parsed manual executor list
executors_manual = raw_tests[2]

#normalize Yamls into eligible signature types for executor - "command"
getSigData_command_cmd_interps = Cbsig.is_command_interpreter(executors_command)
getSigData_command_lol_bins = Cbsig.is_lol_bin(executors_command)
getSigData_command_dev_bins = Cbsig.is_dev_bin(executors_command)

#normalize Yamls into eligible signature types for executor - "powershell"
getSigData_powershell_cmd_interps = Cbsig.is_command_interpreter(executors_powershell)
getSigData_powershell_lol_bins = Cbsig.is_lol_bin(executors_powershell)
getSigData_powershell_dev_bins = Cbsig.is_dev_bin(executors_powershell)


#create lists of eligable rules to be created
getRuleData_command_cmd_interps = Cbsig.cmd_interp_rules(getSigData_command_cmd_interps)
getRuleData_command_lol_bins = Cbsig.lol_bin_rules(getSigData_command_lol_bins)
getRuleData_command_dev_bins = Cbsig.dev_tools_rules(getSigData_command_dev_bins)
getRuleData_powershell_cmd_interps = Cbsig.cmd_interp_rules(getSigData_powershell_cmd_interps)
getRuleData_powershell_lol_bins = Cbsig.lol_bin_rules(getSigData_powershell_lol_bins)
getRuleData_powershell_dev_bins = Cbsig.dev_tools_rules(getSigData_powershell_dev_bins)


#print rules for command executor cmd_interp atomics
print "Command executor - cmd_interps"
for tid,ruledata in getRuleData_command_cmd_interps.iteritems():
	dedupe_ruledata = Set(ruledata)
	for rule in dedupe_ruledata:
		print "Potential detection indicator: {}".format(rule)

#print rules for command executor lol_bin atomics
print "Command executor - lol bins"
for tid,ruledata in getRuleData_command_lol_bins.iteritems():
	dedupe_ruledata = Set(ruledata)
	for rule in dedupe_ruledata:
		print "Potential detection indicator: {}".format(rule)

#create rules for command executor dev_tools atomics
print "Command executor - dev bins"
for tid,ruledata in getRuleData_command_dev_bins.iteritems():
	dedupe_ruledata = Set(ruledata)
	for rule in dedupe_ruledata:
		print "Potential detection indicator: {}".format(rule)


#create rules for powershell executor cmd_interp atomics
print "Powershell executor - cmd_interps"
for tid,ruledata in getRuleData_powershell_cmd_interps.iteritems():
	dedupe_ruledata = Set(ruledata)
	for rule in dedupe_ruledata:
		print "Potential detection indicator: {}".format(rule)

#create rules for powershell executor lol_bin atomics
print "Powershell executor - lol bins"
for tid,ruledata in getRuleData_powershell_lol_bins.iteritems():
	dedupe_ruledata = Set(ruledata)
	for rule in dedupe_ruledata:
		print "Potential detection indicator: {}".format(rule)

#create rules for powershell executor dev_tools atomics
print "Powershell executor - dev bins"
for tid,ruledata in getRuleData_powershell_dev_bins.iteritems():
	dedupe_ruledata = Set(ruledata)
	for rule in dedupe_ruledata:
		print "Potential detection indicator: {}".format(rule)





