from selenium import webdriver
from selenium.common.exceptions import TimeoutException , WebDriverException
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary # for specifying the path to firefox binary
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
import argparse
import time
import datetime
import pandas
# parser for the command line arguements
parser = argparse.ArgumentParser(description="STart firefox with a DoH resolver's URI set as argument!")

parser.add_argument('-r', '--resolver', action="store", default="", type=str, dest="resolver" , help="Specify DoH resolver URI (Default: None)")
parser.add_argument('-s', '--start-from', action="store", default=1, type=int, dest="str" , help="Specify the start ID of the websites from Alexa\'s list (Default: 1)")
parser.add_argument('-e', '--stop-at', action="store", default=5000, type=int, dest="end" , help="Specify the end ID of the websites from Alexa\'s list (Default: 5000)")
args=parser.parse_args()

uri=args.resolver
start=args.str
stop=args.end

def getDateFormat(timestamp):
    '''
    This simple function converts traditional UNIX timestamp to YMD_HMS format
    timestamp int - unix timestamp to be converted
    return String - the YMD_HMS format as a string
    '''
    return datetime.datetime.\
        fromtimestamp(float(timestamp)).strftime('%Y%m%d_%H%M%S')
   
#get current timestamp and convert it
ts = time.time()
timestamp = getDateFormat(str(ts))
# setup logging features
log_file = "log_"+str(timestamp)
print("Creating log file "+log_file)
print("Resolver: " + uri + "\n")

logs = open(log_file, 'a')
logs.write("Logging for start_firefox.py started on "+timestamp+"\n\n")
if(uri != ""):
  logs.write("Resolver: " + uri + "\n")
else:
  logs.write("No DoH resolver will be used\n")

options = Options()
options.headless = True


data=pandas.read_csv('top-1m.csv', names=['rank','website'])


url=("google.com","facebook.com","ebay.com", "cnn.com", "index.hu")

## specifying the binary path
binary = FirefoxBinary('/docker_firefox/firefox/firefox')
profile = webdriver.FirefoxProfile()
if(uri!=""):
  profile.set_preference("network.trr.mode", 3)
  profile.set_preference("network.trr.uri", uri)


driver = webdriver.Firefox(options=options, firefox_profile=profile)
driver.set_page_load_timeout(16)
# for u in url:
for i,u in enumerate(data['website']):
  if(start > i):
    print("Skipping {}:{}".format(i,u))
    continue
  elif(i == stop):
    print("Reached the end at {}:{}".format(i,u))
    break
  else:
    try:
      address="https://www."+str(u)
      print("looking for address no {} -- {}".format(i,address))
      logs.write("looking for address no {} -- {}\n".format(i,address))
      driver.get(address)
      print("Succeed")
      logs.write("Succeed\n")
      time.sleep(2)
    except TimeoutException as ex1 :
      # driver.execute_script("alert(\'Timeout exception:"+str(ex1)+"\');")
      print("Timeout")
      logs.write("Timeout"+"\n")
      
    except WebDriverException as ex2 :
      # driver.execute_script("alert(\'Webdriver exception:"+str(ex2)+"\');")
      print("webdriver exception: "+str(ex2))
      logs.write("webdriver exception: "+str(ex2)+"\n")
    except Exception as ex3:
      # driver.execute_script("alert(\'Unknown exception:"+str(ex3)+"\');")
      print("unknown exception: "+str(ex3))
      logs.write("unknown exception: "+str(ex3)+"\n")
      
    continue
    logs.flush()
    # driver.switch_to.alert.text
  
logs.close()
print("closing Firefox driver...")
try:
  driver.close()
except Exception as ex:
  print("failed: \n" + str(ex))

print("closing Firefox...")
try:
  driver.quit()
except Exception as ex:
  print("failed: \n" + str(ex))

