#!/usr/bin/python3

from selenium import webdriver
from selenium.common.exceptions import TimeoutException , WebDriverException
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary # for specifying the path to firefox binary
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
import argparse
import time
import datetime
import pandas
import json

#for IP address generation
import socket, struct


# parser for the command line arguements
parser = argparse.ArgumentParser(description="Start firefox with a DoH resolver's URI set as argument!")
parser.add_argument('-p', '--path_to_resources', action="store", default="../resources", type=str, dest="path_to_resources" , help="Specify the PATH to resources (Default: ../resources)")
parser.add_argument('-r', '--resolver', action="store", default="", type=str, dest="resolver" , help="Specify DoH resolver URI (Default: None)")
parser.add_argument('-j', '--resolver_json', action="store_true", dest="resolver_json", help="Indicate to iterate through all reasolvers instead (defined in r_config.json) if setting one at a time. If indicated other arguments about resolvers and bootstrap address will be ignored (Default: False).")
parser.set_defaults(resolver_json=False)
parser.add_argument('-n', '--skip-first-n-resolver', action="store", type=int, default=-1, dest="skip_first_n_resolver", help="If -j argument is used, define here how many resolvers should be skipped from the beginning of r_config.json. (Default: 0)")
parser.add_argument('-m', '--skip-last-n-resolver', action="store", type=int, default=-1, dest="skip_last_m_resolver", help="If -j argument is used, define here how many resolvers should be skipped from the end of r_config.json. (Default: 0)")
parser.add_argument('-b', '--bootstrap-address', action="store", default="", type=str, dest="bootstrap" , help="Specify DoH resolver's bootstrap address (Default: None)")
parser.add_argument('-s', '--start-from', action="store", default=1, type=int, dest="str" , help="Specify the start ID of the websites from Alexa\'s list (Default: 1)")
parser.add_argument('-e', '--stop-at', action="store", default=5000, type=int, dest="end" , help="Specify the end ID of the websites from Alexa\'s list (Default: 5000)")
parser.add_argument('-w', '--website-to-visit', action="store", default=None, type=str, dest="website" , help="Specify a website to visit INSTEAD of the top 10 sites (Default: No website)")
parser.add_argument('-t', '--timeout', action="store", default=16, type=int, dest="timeout",
                    help="Specify the timeout for a webpage to load (Default: 16)")
parser.add_argument('-f', '--flush-dns-cache', action="store_true", dest="flush_dns",
                    help="Specify if Firefox should flush DNS cache before every website. It increases processing time as Firefox is restarted every time then (Default: False)")               
parser.set_defaults(flush_dns=False)

parser.add_argument('-v', '--verbose', action="store_true", dest="v", help="Verbose mode (Default: False)")             
parser.set_defaults(v=False)
args=parser.parse_args()

PATH_TO_RESOURCES=args.path_to_resources
RESOLVER_JSON=args.resolver_json
URI=args.resolver
BOOTSTRAP=args.bootstrap
START=args.str
STOP=args.end
TIMEOUT=args.timeout
FLUSH_DNS=args.flush_dns
VERBOSE=args.v
SKIP_N_FIRST=int(args.skip_first_n_resolver)
SKIP_M_LAST=int(args.skip_last_m_resolver)
WEBSITE=args.website

def getDateFormat(timestamp):
    '''
    This simple function converts traditional UNIX timestamp to YMD_HMS format
    timestamp int - unix timestamp to be converted
    return String - the YMD_HMS format as a string
    '''
    return datetime.datetime.\
        fromtimestamp(float(timestamp)).strftime('%Y%m%d_%H%M%S')


def generateIPs(start, end):
    
    start = struct.unpack('>I', socket.inet_aton(start))[0]
    end = struct.unpack('>I', socket.inet_aton(end))[0]
    return [socket.inet_ntoa(struct.pack('>I', i)) for i in range(start, end)]
    
    
# ips=generateIPs('104.12.0.1','104.31.255.255')
# print(ips)
# exit(-1)
  
#get current timestamp and convert it
ts = time.time()
timestamp = getDateFormat(str(ts))
# setup logging features
log_file = "log_"+str(timestamp)
if(VERBOSE):
  print("Creating log file "+log_file)

logs = open(log_file, 'a')
logs.write("Logging for start_firefox.py started on "+timestamp+"\n\n")
if(URI != ""):
  logs.write("Resolver: " + URI + "\n")
  print("Resolver: " + URI)
elif not RESOLVER_JSON:
  logs.write("No DoH resolver will be used\n")
  print("No DoH resolver will be used")
else:
  logs.write("Testing all possible resolvers\n")
  print("Testing all possible resolvers")
  if(SKIP_N_FIRST != -1):
    logs.write("...with {} skipped from the beginning\n".format(SKIP_N_FIRST))
    print("...with {} skipped from the beginning".format(SKIP_N_FIRST))
  
if(BOOTSTRAP != ""):
  logs.write("Bootstrap address: " + BOOTSTRAP + "\n")
  print("Bootstrap address: " + BOOTSTRAP)
elif not RESOLVER_JSON:
  logs.write("No DoH bootstrap address is specified\n")
  print("No DoH bootstrap address is specified")
else:
  logs.write("Testing all possible bootstrap addresses\n")
  print("Testing all possible bootsrap addresses")
  if(SKIP_N_FIRST != -1):
    logs.write("...with {} skipped from the beginning\n".format(SKIP_N_FIRST))
    print("...with {} skipped from the beginning".format(SKIP_N_FIRST))
  if(SKIP_M_LAST != -1):
    logs.write("...with {} skipped from the end\n".format(SKIP_M_LAST))
    print("...with {} skipped from the end".format(SKIP_M_LAST))

if WEBSITE is None:
  logs.write("Iterating through all 10 websites from Alexa's list!\n")
  print("Iterating through all 10 websites from Alexa's list!")
else:
  logs.write("Check only the following website: {}\n".format(WEBSITE))
  print("Check only the following website: {}".format(WEBSITE))

options = Options()
options.headless = True


if(RESOLVER_JSON):
  with open(PATH_TO_RESOURCES+'/r_config.json') as f:
    resolver_config = json.load(f)
else:
  resolver_config=dict()
  resolver_config["1"] = dict()
  resolver_config["1"]['name']=URI 
  resolver_config["1"]['uri']=URI
  resolver_config["1"]['bootstrap']=BOOTSTRAP

NUM_RESOLVERS=len(resolver_config)

if(WEBSITE is None):
  data=pandas.read_csv(PATH_TO_RESOURCES+'/top-1m.csv', names=['rank','website'])
else:
  data=dict()
  tmp=list()
  tmp.append(WEBSITE)
  data['website']=tmp



## specifying the binary path
binary = FirefoxBinary('/docker_firefox/firefox/firefox')


# if(URI!=""):
  # profile.set_preference("network.trr.mode", 3)
  # profile.set_preference("network.trr.uri", URI)

# if(BOOTSTRAP!=""):
  # profile.set_preference("network.trr.bootstrapAddress", BOOTSTRAP)


def init_webdriver(uri, bootstrap):
  global driver
  profile = webdriver.FirefoxProfile()
  if(uri!=""):
    profile.set_preference("network.trr.mode", 3)
    profile.set_preference("network.trr.uri", uri)

  if(bootstrap!=""):
    profile.set_preference("network.trr.bootstrapAddress", bootstrap)
    
  try:
    if(VERBOSE):
      print("Driver is initilizing...")
      logs.write("Driver is initilizing...")
    driver = webdriver.Firefox(options=options, firefox_profile=profile, executable_path="/docker_firefox/geckodriver")
    # driver = webdriver.Firefox()
    driver.set_page_load_timeout(TIMEOUT)
    print("Initialized: {} --- {}".format(uri, bootstrap))
    logs.write("Initialized: {} --- {}\n".format(uri, bootstrap))
  except WebDriverException as ex:
    if(VERBOSE):
      print("Driver creation failed: " + str(ex))
      logs.write("Driver creation failed: " + str(ex) + "\n")
      print("Retrying...")
      logs.write("Retrying...\n")
    #init_webdriver()
  except DeprecationWarning as ex:
    if(VERBOSE):
      print("Driver creation mode is deprecated! Migrate to new functions and arguments")
      logs.write("Driver creation mode is deprecated! Migrate to new functions and arguments\n")

def close_webdriver():
  global driver
  if(VERBOSE):
    print("closing Firefox driver...")
    logs.write("closing Firefox driver...")
  try:
    driver.close()
  except WebDriverException as ex:
    if(VERBOSE):
      print("failed: \n" + str(ex))
      logs.write("failed: " + str(ex) + "\n")

def quit_webdriver():
  global driver
  if(VERBOSE):  
    print("closing Firefox...")
  try:
    driver.quit()
  except WebDriverException as ex:
    if(VERBOSE):
      print("failed: \n" + str(ex))
      logs.write("failed: " + str(ex) + "\n")



resolver_count=0
for j in resolver_config:
  resolver_count+=1 #increase resolver count var used for skipping some resolvers in the beginning (indicated via SKIP_N_FIRST)
  
  if(RESOLVER_JSON and SKIP_N_FIRST != -1):
    #resolver file is used and SKIP_N_FIRST is defined
    if(resolver_count <= SKIP_N_FIRST):
      if(VERBOSE):
        print("Skipping resolver #{}".format(resolver_count))
        logs.write("Skipping resolver #{}\n".format(resolver_count))
      continue #skip resolver  
  if(RESOLVER_JSON and SKIP_M_LAST != -1):
    if(resolver_count >= (NUM_RESOLVERS-SKIP_M_LAST)):
      if(VERBOSE):
        print("Stopping at resolver #{}".format(resolver_count))
        logs.write("Stopping at resolver #{}\n".format(resolver_count))
      break #stop here
  
  #get resolver data
  name=str(resolver_config[j]['name'])
  uri=str(resolver_config[j]['uri'])
  bootstrap=str(resolver_config[j]['bootstrap'])
  print()
  logs.write("\n\n")
  #init webdriver
  init_webdriver(uri, bootstrap)

  for i,u in enumerate(data['website']):
    # i should start at 1 not 0
    i+=1
    if(START > i):
      if(VERBOSE):
        print("Skipping {}:{}".format(i,u))
        logs.write("Skipping {}:{}\n".format(i,u))
      continue
    elif(i > STOP):
      # print("Reached the end at {}:{}".format(i,u))
      if(VERBOSE):
        logs.write("Reached the end at {}:{}\n".format(i,u))
      break
    else:
      try:
        a = time.time()
        address="https://www."+str(u)
        print("looking for address no {} -- {} ({})".format(i,address, timestamp))
        logs.write("looking for address no {} -- {} ({})\n".format(i,address,timestamp))
        driver.get(address)
        b = time.time()
        load_time=b-a
        print("Loadtime: {}".format(load_time))
        logs.write("Loadtime: {}\n".format(load_time))
        print("Succeed ({})".format(timestamp))
        logs.write("Succeed ({})\n".format(timestamp))
        time.sleep(2)
        if(FLUSH_DNS): #if we want to restart firefox after each website
          close_webdriver()
          init_webdriver(uri, bootstrap)
      except TimeoutException as ex1 :
        # driver.execute_script("alert(\'Timeout exception:"+str(ex1)+"\');")
        print("Loadtime: Timeout")
        logs.write("Loadtime: Timeout\n")
        print("Timeout: "  +str(ex1))
        logs.write("Timeout"+"\n")
        
      except WebDriverException as ex2 :
        # driver.execute_script("alert(\'Webdriver exception:"+str(ex2)+"\');")
        print("Loadtime: Not_resolved")
        logs.write("Loadtime: Not_resolved\n")
        if(VERBOSE):
          print("webdriver exception: "+str(ex2))
          logs.write("webdriver exception: "+str(ex2)+"\n")
          print("Reinit driver")
          logs.write("Reinit driver\n")
        close_webdriver()
        init_webdriver(uri, bootstrap)

      except Exception as ex3:
        # driver.execute_script("alert(\'Unknown exception:"+str(ex3)+"\');")
        if(VERBOSE):
          print("unknown exception: "+str(ex3))
          logs.write("unknown exception: "+str(ex3)+"\n")
          print("Reinit driver")
          logs.write("Reinit driver\n")
        close_webdriver()
        init_webdriver(uri, bootstrap)
        
      continue
      logs.flush()
      # driver.switch_to.alert.text
    

  quit_webdriver()
logs.close()
