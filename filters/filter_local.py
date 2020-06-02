#!/usr/bin/python3
# coding: utf-8

from scapy.all import sniff , send , sendp, IP
from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.tls.all import TLS
import argparse

#for ML model
from collections import Counter
import joblib
import numpy as np 

# for generating a good hash for 5-tuples
import hashlib

# for running ovs-ofctl command
import os

# for timestamping
import time
import datetime

# for linux signal processing
import signal

def getDateFormat(timestamp):
  '''
  This simple function converts traditional UNIX timestamp to YMD_HMS format
  timestamp int - unix timestamp to be converted
  return String - the YMD_HMS format as a string
  '''
  return datetime.datetime.\
          fromtimestamp(float(timestamp)).strftime('%Y%m%d_%H%M%S')


parser = argparse.ArgumentParser(description="Python-based DoH filter that adds corresponding 5-tuples of a DoH communication to a blacklist in OVS!")
parser.add_argument('-n', '--num-doublechecks', action="store", default=1, type=int, dest="ndc" , help="Specify the number of double-checks before deciding to block a predicted DoH service's IP (Default: 1)!")
parser.add_argument('-i', '--interface', action="store", default="eth0", type=str, dest="dev" , help="Specify the interface to sniff on (Default: eth0)!")
parser.add_argument('-d', '--do-not-block', action="store_true", dest="dnb", help="Do not block, only log the IPs! (Default: False)")
parser.add_argument('-m', '--ml-model', action="store", dest="model", default="../ml_models/modelv3.pkl", help="Specify the ML model's location! (Default: ../ml_models/modelv3.pkl <- mind the relative path!)")
parser.add_argument('-b', '--ovs-bridge', action="store", dest="ovs", default="ovsbr-int", help="Specify OVS switch where filtering is done! (Default: ovsbr-int)")
parser.add_argument('-o', '--only-block-4-tuple', action="store_true", dest="only_4tuple",help="Block 4-tuple only (5-tuple w/o source port) (Default: False)")
parser.set_defaults(dnb=False)
parser.set_defaults(only_ip=False)

results = parser.parse_args()

NUM_DOUBLE_CHECKS=results.ndc
INTERFACE=results.dev
ONLY_LOG=results.dnb
MODEL=results.model
OVS=results.ovs
ONLY_4TUPLE=results.only_4tuple

logfile_suffix=""
if ONLY_4TUPLE:
  logfile_suffix="_4tuple_NDC"+str(NUM_DOUBLE_CHECKS)+"_"
else:
  logfile_suffix="_5tuple_NDC"+str(NUM_DOUBLE_CHECKS)+"_"



print("DNS-over-HTTPS needs to be blocked")
print("Numer of double-checks for proof: {}".format(NUM_DOUBLE_CHECKS))
print("The OVS switch where the filtering is done: {}".format(OVS))
print("Loading model {}".format(MODEL))
rf3 = joblib.load(MODEL)
rf3.verbose=0
print("ML model has been loaded")

packet_data={ 
  "src_ip"   : "",
  "src_port" : "",
  "dst_ip"   : "",
  # dst_port : "", #THIS IS KNOWN AND STATIC FOR DoH packets (443)
  # ip_proto : "", #THIS IS KNOWN AND STATIC FOR DoH packets (6)
  "count"    : 0,
  "confirmed"  : False
}
doh = dict()
http2 = dict()
blacklist=list()

ip_class={

  "class"   : None,
}
ips=dict()


#get current timestamp and convert it
ts = time.time()
timestamp = getDateFormat(str(ts))

# Open log files for blacklist five-tuples
logfile = open("filter-local-blocklist.flows_"+logfile_suffix+str(timestamp), "w")
logs = open("filter_local.log_"+logfile_suffix+str(timestamp),"w")
ip_data_log = open("filter_ipdata.log_"+logfile_suffix+str(timestamp), "w")


def receiveSignal(signalNumber, frame):
  if(signalNumber == 2): #Ctrl+C signal caught
    print("Signal received:{}".format(signalNumber))
    logfile.write("Signal received:{}\n".format(signalNumber))
    
    # print("Printing out runtime data...")
    # logfile.write("Printing out runtime data...\n")
    # for i in ips:
      # ip_data_log.write("{} - {}\n".format(i,ips[i]['class']))
      # ip_data_log.flush()
    print("Exiting...")
    logfile.write("Exiting...")
    
    ip_data_log.close()
    logs.flush()
    logs.close()
    logfile.flush()
    logfile.close()
    exit(-1)

def block_reverse_path(**kwargs):
  '''
  Adds a blocking flow rule to OVS for the reverse direction
  :param src_ip: The source IP for the 5-tuple
  :param dst_ip: The destination IP for the 5-tuple
  :param src_port: The source port for the 5-tuple
  
  The rest of the parameters of a 5-tuple are constant
  :return: returns nothing
  '''
  pass


def block_5_tuple(src_ip,dst_ip,src_port):
  '''
  Adds a blocking flow rule to OVS via the 5-tuple
  :param src_ip: The source IP for the 5-tuple
  :param dst_ip: The destination IP for the 5-tuple
  :param src_port: The source port for the 5-tuple
  
  The rest of the parameters of a 5-tuple are constant
  :return: returns nothing
  '''
  r="\"table=1,priority=1000,tcp,nw_src=" + str(src_ip) + "," + \
    "nw_dst=" + str(dst_ip) + "," + \
    "tp_src=" + str(src_port) + "," + \
    "tp_dst=443,idle_timeout=10,actions=drop\""
  
  logfile.write(r + str("\n"))
  logfile.flush()
  if(not ONLY_LOG):
    cmd=str("sudo ovs-ofctl add-flow " + OVS + " " + r)
    print(cmd)
    os.system(cmd)


def block_4_tuple(src_ip, dst_ip):
  '''
  Adds a blocking flow rule to OVS via the 4-tuple (no src_port)
  :param src_ip: The source IP for the 5-tuple
  :param dst_ip: The destination IP for the 5-tuple
  
  The rest of the parameters of a 5-tuple are constant
  :return: returns nothing
  '''
  r="\"table=1,priority=1000,tcp,nw_src=" + str(src_ip) + "," + \
  "nw_dst=" + str(dst_ip) + "," + \
  "tp_dst=443, idle_timeout=10, actions=drop\""
  logfile.write(r + str("\n"))
  logfile.flush()
  if(not ONLY_LOG):
    cmd=str("sudo ovs-ofctl add-flow " + OVS + " " + r)
    print(cmd)
    os.system(cmd)

#simplest and one of the fastest hash function according to a test here
#https://www.peterbe.com/plog/best-hashing-function-in-python
#so, we will use this for now
def h11(w):
    return hashlib.md5((w.encode('utf-8'))).hexdigest()[:9]


## ============  DNS-over-HTTPS filtering ===========
def filter_doh_packets(packet):
  # sendp(packet, iface="eth0")
  # print("DoH Filter not implemented...FORWARDING")
  def make_pred(packet):
    # custom_action.number+=1
    # print(f"Packet #{sum(packet_counts.values())}: {packet[0][1].src} ==> {packet[0][1].dst}")
    #key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
    # packet_counts.update([key])

    ### calculating packet parameters
    time = packet.time 
    time_lag_curr = time - filter_doh_packets.prev_time
    time_lag_prev = filter_doh_packets.prev_lag
    length = len(packet)
    prev_length = filter_doh_packets.prev_len
    packet_difference = filter_doh_packets.number - filter_doh_packets.prev_number

    ### prediction
    #t0=time
    X_train =[length , prev_length , time_lag_curr, time_lag_prev, packet_difference]
    X_train = np.array(X_train)
    X_train = X_train.reshape(1,-1)
    prediction = rf3.predict(X_train)
    #t1 = time

    #initialize data structure
    ips[packet[0][1].dst]=ip_class
    
    three_tuple=str(packet[0][1].src) + \
                str(packet[0][1].dst) + \
                str(packet[0][2].sport)
      
    h=h11(three_tuple)
    #### ----------- DoH -------------
    if(prediction==1) :
      ans = 'DoH'
      # print("packet looks like DoH...DROP")
      # print("DoH service IP? : {}".format(packet[0][1].dst))
      logs.write("DoH service IP? : {}\n".format(packet[0][1].dst))
      
      #if IP was already identified as DoH service
      if h in doh:        
        # if(doh[h]['confirmed'] == True):
          # continue
        #increase its count
        doh[h]["count"]+=1
        doh[h]["dst_ip"]=packet[0][1].dst  
        doh[h]["src_ip"]=packet[0][1].src
        doh[h]["src_port"]=packet[0][2].sport
        #check if the current number is above the threshold
        if(doh[h]["count"] >= NUM_DOUBLE_CHECKS):
          logs.write("Classified as DoH:{},{},{},{}\n".format(packet[0][1].src, packet[0][2].sport, packet[0][1].dst, 443))
          # logs.write("Classified as DoH:{}\n".format(packet[0][1].dst))
          ips[packet[0][1].dst]['class']="DoH"
          if(ONLY_4TUPLE):
            block_4_tuple(doh[h]["src_ip"], doh[h]["dst_ip"])
          else:
            block_5_tuple(doh[h]["src_ip"],doh[h]["dst_ip"],doh[h]["src_port"])
          del doh[h]
          # doh[h]["blocked"]=True
      #otherwise, initialize it
      else:
        doh[h]=packet_data
    #### ----------- HTTP2 -----------
    else :
      ans = 'Http2'
      # print("HTTP service IP? : {}".format(packet[0][1].dst))
      logs.write("HTTP2 service IP? : {}\n".format(packet[0][1].dst))

      # logs.write("Classified as HTTP2:{},{},{},{}\n".format(packet[0][1].src, packet[0][2].sport, packet[0][1].dst, 443))
      if h in http2:
        # if(http2[h]['confirmed'] == True):
          # continue
        #increase its count
        http2[h]["count"]+=1
        http2[h]["dst_ip"]=packet[0][1].dst  
        http2[h]["src_ip"]=packet[0][1].src
        http2[h]["src_port"]=packet[0][2].sport
        #check if the current number is above the threshold
        
        if(http2[h]["count"] >= NUM_DOUBLE_CHECKS):
          logs.write("Classified as HTTP2:{},{},{},{}\n".format(packet[0][1].src, packet[0][2].sport, packet[0][1].dst, 443))
          # logs.write("Classified as HTTP2:{}\n".format(packet[0][1].dst))
          del http2[h]
        
      else:
        http2[h]=packet_data
      
      
      # if(ips[packet[0][1].dst]['class'] is None):
        # ips[packet[0][1].dst]['class']="HTTP2"
    logs.flush()

    ### updating values for next cycle
    filter_doh_packets.prev_time = time
    filter_doh_packets.prev_lag = time_lag_curr
    filter_doh_packets.prev_number = filter_doh_packets.number 
    filter_doh_packets.prev_len = length
    

  return make_pred(packet)

filter_doh_packets.prev_time = 0
filter_doh_packets.prev_len = 0 
filter_doh_packets.prev_lag = 0
filter_doh_packets.number = 0
filter_doh_packets.prev_number= 0   
## ----- DNS-over-HTTPS filtering END ----------------




def filter_packets(packet):
  if IP in packet:
    #packets coming from the user
    if(packet[0][1].src == "10.10.10.100"):
      
      ### ------- HERE COMES ANY FILTERING --------- ###
      ## ============  DNS-over-HTTPS filtering ===========
      if(packet.haslayer(TLS)):
        filter_doh_packets(packet)
      ## ----- DNS-over-HTTPS filtering END ----------------
      else:
        pass
        # print("FORWARDING non-filtered packets")
      ####============== FILTERING ENDS ============####

# signing up for all UNIX signals
signal.signal(signal.SIGHUP, receiveSignal)
signal.signal(signal.SIGINT, receiveSignal)
signal.signal(signal.SIGQUIT, receiveSignal)
signal.signal(signal.SIGILL, receiveSignal)
signal.signal(signal.SIGTRAP, receiveSignal)
signal.signal(signal.SIGABRT, receiveSignal)
signal.signal(signal.SIGBUS, receiveSignal)
signal.signal(signal.SIGFPE, receiveSignal)
#signal.signal(signal.SIGKILL, receiveSignal) # has to be able to be killed :)
signal.signal(signal.SIGUSR1, receiveSignal)
signal.signal(signal.SIGSEGV, receiveSignal)
signal.signal(signal.SIGUSR2, receiveSignal)
signal.signal(signal.SIGPIPE, receiveSignal)
signal.signal(signal.SIGALRM, receiveSignal)
signal.signal(signal.SIGTERM, receiveSignal)

#we cannot filter on anything, because then packets missing the filter will not
#be forwarded by default
sniff(iface=INTERFACE, prn=filter_packets, store=0)

# logfile.flush()
# logfile.close()
