import yaml
import os
import time
import requests
import json
from pprint import pprint

#Return list of yamls to parse relative to the atomic-red-team dir

windows_executors = ['powershell', 'command_prompt']

def grabYamls():
   yamls = []
   #Grab the current dir
   currentdir = os.path.dirname(__file__)
   #Get relative path for atomic test descriptions
   atomic_red_dir = os.path.join(currentdir, 'atomic-red-team', 'atomics')

   #Grab all the yamls
   for root, subdirs, files in os.walk(atomic_red_dir):
      for filename in files:
         file_path = os.path.join(root, filename)
         if ".yaml" in file_path:
            yamls.append(file_path)

   return yamls

def parseYamls(yaml_list):
   executor_counts = {}
   executor_counts['powershell'] = 0
   executor_counts['command_prompt'] = 0
   executor_counts['manual'] = 0
   powershell_command_dict = {}
   cmd_command_dict = {}
   manual_command_dict = {}
   powershell_commands = []
   cmd_commands = []
   manual_commands = []
   for atomic_yaml in yaml_list:
      with open(atomic_yaml, 'r') as atomic_set:
         objAtomicYaml = yaml.load(atomic_set)
         attckTID = objAtomicYaml['attack_technique']
         powershell_command_dict.setdefault(attckTID, None)
         cmd_command_dict.setdefault(attckTID, None)
         manual_command_dict.setdefault(attckTID, None)
         testCases = objAtomicYaml['atomic_tests']
         for item in testCases:
            if "windows" in item.get("supported_platforms"):
               #print objAtomicYaml['attack_technique']
               executors = item.get("executor")
               #print executors['name']
               if "powershell" in executors['name']:
                  #print item.get("name")
                  #print "Executor: Powershell"
                  #print "Powershell command: ",  executors['command']
                  executor_counts['powershell'] += 1
                  powershell_commands.append(executors['command'])
               elif "command_prompt" in executors['name']:
                  #print item.get("name")
                  #print "Executor: Command Prompt"
                  #print "Interactive Command: ",  executors['command']
                  executor_counts['command_prompt'] += 1
                  cmd_commands.append(executors['command'])
               elif "manual" in executors['name']:
                  #print item.get("name")
                  #print "Executor: Manual"
                  #print "Manual Test Case: ", executors['steps']
                  executor_counts['manual'] += 1
                  manual_commands.append(executors['steps'])
               elif "sh" in executors['name']:
                  break
               else:
                  print "Could match executor for count"
                  print executors
                  time.sleep(10)

         powershell_command_dict[attckTID] = powershell_commands
         powershell_commands = []
         cmd_command_dict[attckTID] = cmd_commands
         cmd_commands = []
         manual_command_dict[attckTID] = manual_commands
         manual_commands = []

   return powershell_command_dict, cmd_command_dict, manual_command_dict


class Cbsig:
   windows_cmd_interps = ["powershell.exe", "wmic.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"]
   lol_bins = ["certutil.exe", "pcalua.exe", "forfiles", "mavinject", "regsvr32.exe", "rundll32.exe", "cmstp.exe"]
   dev_bins = ["csc.exe", "installutil.exe", "msbuild.exe", "regsvcs.exe", "regasm.exe"]
   special_bins = ["services.exe", "sc", "wmiprvse.exe", "sc.exe", "bitsadmin.exe"]
   manual_strings = ["word"]

   credential = ["mimi"]
   exec_memory = ["iex"]
   makes_netconn = ["http", "javascript", "url"]
   injects = ["mavinject"]

   @staticmethod
   def is_command_interpreter(command_list):
      command_interpreter_dict = {}
      command_interpreter_list = []
      for tid, attack in command_list.iteritems():
         if attack:
            for one_liner in attack:
               if any(x in one_liner.lower() for x in Cbsig.windows_cmd_interps):
                  #print "*******IS COMMAND INTERP*******"
                  #print "{} - {}".format(tid,one_liner)
                  command_interpreter_list.append(one_liner)
               if command_interpreter_list:
                  command_interpreter_dict[tid] = command_interpreter_list
            command_interpreter_list = []
      return command_interpreter_dict

   @staticmethod
   def is_lol_bin(command_list):
      lol_bin_dict = {}
      lol_bin_list = []
      for tid, attack in command_list.iteritems():
         if attack:
            for one_liner in attack:
               if any(x in one_liner.lower() for x in Cbsig.lol_bins):
                  #print "*******IS LOL BIN*******"
                  #print "{} - {}".format(tid,one_liner)
                  lol_bin_list.append(one_liner)
               if lol_bin_list:
                  lol_bin_dict[tid] = lol_bin_list
            lol_bin_list = []
      return lol_bin_dict

   @staticmethod
   def is_special_bin(command_list):
      special_bin_dict = {}
      special_bin_list = []
      for tid, attack in command_list.iteritems():
         if attack:
            for one_liner in attack:
               if any(x in one_liner.lower() for x in Cbsig.special_bins):
                  #print "*******IS SPECIAL BIN*******"
                  #print "{} - {}".format(tid,one_liner)
                  special_bin_list.append(one_liner)
               if special_bin_list:
                  special_bin_dict[tid] = special_bin_list
            special_bin_list = []
      return special_bin_dict

   @staticmethod
   def is_dev_bin(command_list):
      dev_bin_dict = {}
      dev_bin_list = []
      for tid, attack in command_list.iteritems():
         if attack:
            for one_liner in attack:
               if any(x in one_liner.lower() for x in Cbsig.dev_bins):
                  #print "*******IS DEV BIN*******"
                  #print "{} - {}".format(tid,one_liner)
                  dev_bin_list.append(one_liner)
               if dev_bin_list:
                  dev_bin_dict[tid] = dev_bin_list
            dev_bin_list = []
      return dev_bin_dict

   @staticmethod
   def cmd_interp_rules(indicators):
      print "Generating command rules"
      print "*************************************"
      cmd_interp_rules_dict = {}
      cmd_interp_rule_list = []
      for tid,attack in indicators.iteritems():
         for one_liner in attack:
            #Check the list of cmd interps for cred theft atomic indicators
            if any(x in one_liner.lower() for x in Cbsig.credential):
               print "Indicator for command_interpreter performing credential theft"
               if "powershell" in one_liner.lower():
                  print "Powershell wants to perform credential theft"
                  print "{} - {}".format(tid,one_liner)
                  cmd_interp_rule_list.append("Powershell*.exe:MEMORY_SCRAPE")
               elif "cscript" in one_liner.lower():
                  print "cscript wants to perform credential theft"
                  print "{} - {}".format(tid,one_liner)
                  cmd_interp_rule_list.append("cscript.exe:MEMORY_SCRAPE")
               elif "wscript" in one_liner.lower():
                  print "wscript wants to perform credential theft"
                  print "{} - {}".format(tid,one_liner)
                  cmd_interp_rule_list.append("wscript.exe:MEMORY_SCRAPE")
            #Check ths list of cmd interps for execution of code from memory atomic indicators
            if any(x in one_liner.lower() for x in Cbsig.exec_memory):
               print "Indicator for command_interpreter executing code from memory"
               if "powershell" in one_liner.lower():
                  print "Powershell wants to execute code from memory"
                  print "{} - {}".format(tid,one_liner)
                  cmd_interp_rule_list.append("Powershell*.exe:RUN_INMEMORY_CODE")
                  cmd_interp_rule_list.append("Powershell*.exe:INVOKE_CMD_INTERPRETER")
            #Check the list of cmd interps for netconn activity from atomic indicators
            if any(x in one_liner.lower() for x in Cbsig.makes_netconn):
               print "Indicator for command_interpreter attempting to make netconns"
               if "powershell" in one_liner.lower():
                  print "Powershell wants to make a netconn"
                  print "{} - {}".format(tid,one_liner)
                  cmd_interp_rule_list.append("Powershell*.exe:NETWORK")
               if "mshta" in one_liner.lower():
                  print "mshta wants to make a netconn"
                  print "{} - {}".format(tid,one_liner)
                  cmd_interp_rule_list.append("mshta.exe:NETWORK")
            if cmd_interp_rule_list:
               cmd_interp_rules_dict[tid] = cmd_interp_rule_list

         cmd_interp_rule_list = []

      return cmd_interp_rules_dict



   @staticmethod
   def lol_bin_rules(indicators):
      print "Generatng LOL Bin Rules"
      print "*****************************"
      lol_bin_rules_dict = {}
      lol_bin_rule_list = []
      for tid,attack in indicators.iteritems():
         for one_liner in attack:
            #Check the list of lol bins for netconn activity from atomic indicators
            if any(x in one_liner.lower() for x in Cbsig.makes_netconn):
               print "Indicator for command_interpreter attempting to make netconns"
               if "certutil" in one_liner.lower():
                  print "certutil wants to make a netconn"
                  print "{} - {}".format(tid,one_liner)
                  lol_bin_rule_list.append("certutil.exe:NETWORK")
               if "regsvr32.exe" in one_liner.lower():
                  print "regsvr32 want to make a netconn"
                  print "{} - {}".format(tid,one_liner)
                  lol_bin_rule_list.append("regsvr32.exe:NETWORK")
               if "rundll32.exe" in one_liner.lower():
                  print "rundll32 wants to invoke cmd-interp"
                  print "{} - {}".format(tid,one_liner)
                  lol_bin_rule_list.append("rundll32.exe:INVOKE_CMD_INTERPRETER")
            #prevention rules for pcalua atomics
            if "pcalua" in one_liner.lower():
               print "pcalua is being used to execute code"
               print "{} - {}".format(tid,one_liner)
               lol_bin_rule_list.append("pcalua.exe:NETWORK")
               lol_bin_rule_list.append("pcalua.exe:INVOKE_CMD_INTERPRETER")
               lol_bin_rule_list.append("pcalua.exe:POL_INVOKE_NOT_TRUSTED")
            #prevention for forfiles atomics
            if "forfiles" in one_liner.lower():
               print "forfiles is being used to execute code"
               print "{} - {}".format(tid,one_liner)
               lol_bin_rule_list.append("forfiles.exe:INVOKE_CMD_INTERPRETER")
               lol_bin_rule_list.append("forfiles.exe:POL_INVOKE_NOT_TRUSTED")
            #prevention for cmstp.exe atomic
            if "cmstp.exe" in one_liner.lower():
               print "cmstp is being used to execute code"
               print "{} - {}".format(tid,one_liner)
               lol_bin_rule_list.append("cmstp.exe:RUN")
            #general prevention for sketch atomic regsvr32 atomics
            if "regsvr32.exe" in one_liner.lower():
               if "dll_name" in one_liner.lower():
                  print "regsvr32 is loading sketchy stuff too!"
                  print "{} - {}".format(tid,one_liner)
                  lol_bin_rule_list.append("regsvr32.exe:POL_INVOKE_NOT_TRUSTED")
            if lol_bin_rule_list:
               lol_bin_rules_dict[tid] = lol_bin_rule_list

         lol_bin_rule_list = []

      return lol_bin_rules_dict

   @staticmethod
   def dev_tools_rules(indicators):
      print "Generating Dev Tools Rules"
      print "*************************************"
      dev_tools_rules_dict = {}
      dev_tools_rules_list = []
      for tid,attack in indicators.iteritems():
         for one_liner in attack:
            #Check the list of msbuild is being invoked as an atomic
            if "msbuild" in one_liner.lower():
               print "MSbuild is being used to execute code"
               print "{} - {}".format(tid,one_liner)
               dev_tools_rules_list.append("msbuild.exe:NETWORK")
            if "csc.exe" in one_liner.lower():
               print "csc is being used to compile/execute payloads"
               print "{} - {}".format(tid,one_liner)
               dev_tools_rules_list.append("csc.exe:NETWORK")
            if "regasm.exe" in one_liner.lower():
               print "regasm is being used to execute code"
               print "{} - {}".format(tid,one_liner)
               dev_tools_rules_list.append("regasm.exe:NETWORK")
            if "regsvcs.exe" in one_liner.lower():
               print "regsvcs.exe is being used to execute code"
               print "{} - {}".format(tid,one_liner)
               dev_tools_rules_list.append("regsvcs.exe:NETWORK")
            if "installutil" in one_liner.lower():
               print "installutil is being used to execute code"
               print "{} - {}".format(tid,one_liner)
               dev_tools_rules_list.append("installutil.exe:RUN")
            if dev_tools_rules_list:
               dev_tools_rules_dict[tid] = dev_tools_rules_list
         dev_tools_rules_list = []

      return dev_tools_rules_dict




   @staticmethod
   def strict_rules_generic(enabled):
      pass




