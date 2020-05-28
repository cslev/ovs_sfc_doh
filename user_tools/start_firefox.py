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

#for IP address generation
import socket, struct


# parser for the command line arguements
parser = argparse.ArgumentParser(description="Start firefox with a DoH resolver's URI set as argument!")

parser.add_argument('-r', '--resolver', action="store", default="", type=str, dest="resolver" , help="Specify DoH resolver URI (Default: None)")
parser.add_argument('-b', '--bootstrap-address', action="store", default="", type=str, dest="bootstrap" , help="Specify DoH resolver's bootstrap address (Default: None)")
parser.add_argument('-s', '--start-from', action="store", default=0, type=int, dest="str" , help="Specify the start ID of the websites from Alexa\'s list (Default: 1)")
parser.add_argument('-e', '--stop-at', action="store", default=5000, type=int, dest="end" , help="Specify the end ID of the websites from Alexa\'s list (Default: 5000)")
parser.add_argument('-t', '--timeout', action="store", default=16, type=int, dest="timeout",
                    help="Specify the timeout for a webpage to load (Default: 16)")
parser.add_argument('-f', '--flush-dns-cache', action="store_true", dest="flush_dns",
                    help="Specify if Firefox should flush DNS cache before every website. It increases processing time as Firefox is restarted every time then (Default: False)")               
parser.set_defaults(flush_dns=False)

args=parser.parse_args()

URI=args.resolver
BOOTSTRAP=args.bootstrap
START=args.str
STOP=args.end
TIMEOUT=args.timeout
FLUSH_DNS=args.flush_dns

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
print("Creating log file "+log_file)

logs = open(log_file, 'a')
logs.write("Logging for start_firefox.py started on "+timestamp+"\n\n")
if(URI != ""):
  logs.write("Resolver: " + URI + "\n")
  print("Resolver: " + URI)
else:
  logs.write("No DoH resolver will be used\n")
  print("No DoH resolver will be used")
if(BOOTSTRAP != ""):
  logs.write("Bootstrap address: " + BOOTSTRAP + "\n")
  print("Bootstrap address: " + BOOTSTRAP)
else:
  logs.write("No DoH bootstrap address is specified\n")
  print("No DoH bootstrap address is specified")


options = Options()
options.headless = True


data=pandas.read_csv('top-1m.csv', names=['rank','website'])


## specifying the binary path
binary = FirefoxBinary('/docker_firefox/firefox/firefox')
profile = webdriver.FirefoxProfile()

if(URI!=""):
  profile.set_preference("network.trr.mode", 3)
  profile.set_preference("network.trr.uri", URI)

if(BOOTSTRAP!=""):
  profile.set_preference("network.trr.bootstrapAddress", BOOTSTRAP)


def init_webdriver():
  global driver
  try:
    print("Driver is initilizing...")
    logs.write("Driver is initilizing...")
    driver = webdriver.Firefox(options=options, firefox_profile=profile, executable_path="/docker_firefox/geckodriver")
    # driver = webdriver.Firefox()
    driver.set_page_load_timeout(TIMEOUT)
  except WebDriverException as ex:
    print("Driver creation failed: " + str(ex))
    logs.write("Driver creation failed: " + str(ex) + "\n")
    print("Retrying...")
    logs.write("Retrying...\n")
    #init_webdriver()

def close_webdriver():
  global driver
  print("closing Firefox driver...")
  logs.write("closing Firefox driver...")
  try:
    driver.close()
  except WebDriverException as ex:
    print("failed: \n" + str(ex))
    logs.write("failed: " + str(ex) + "\n")

def quit_webdriver():
  global driver
  print("closing Firefox...")
  try:
    driver.quit()
  except WebDriverException as ex:
    print("failed: \n" + str(ex))
    logs.write("failed: " + str(ex) + "\n")



init_webdriver()

for i,u in enumerate(data['website']):
  if(START > i):
    print("Skipping {}:{}".format(i,u))
    logs.write("Skipping {}:{}\n".format(i,u))
    continue
  elif(i == STOP):
    # print("Reached the end at {}:{}".format(i,u))
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
        init_webdriver()
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
      print("webdriver exception: "+str(ex2))
      logs.write("webdriver exception: "+str(ex2)+"\n")
      print("Reinit driver")
      logs.write("Reinit driver\n")
      close_webdriver()
      init_webdriver()
    except Exception as ex3:
      # driver.execute_script("alert(\'Unknown exception:"+str(ex3)+"\');")
      print("unknown exception: "+str(ex3))
      logs.write("unknown exception: "+str(ex3)+"\n")
      print("Reinit driver")
      logs.write("Reinit driver\n")
      close_webdriver()
      init_webdriver()
      
    continue
    logs.flush()
    # driver.switch_to.alert.text
  

quit_webdriver()
logs.close()
