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
parser.add_argument('-m', '--ml-model', action="store", dest="model", default="./model2_rf3.pkl", help="Specify the ML model's location! (Default: ./model2_rf3.pkl)")
parser.add_argument('-b', '--ovs-bridge', action="store", dest="ovs", default="ovsbr-int", help="Specify OVS switch where filtering is done! (Default: ovsbr-int)")
parser.add_argument('-o', '--only-block-IP', action="store_true", dest="only_ip",help="Block destination IP only instead of 5-tuple (Default: False)")
parser.set_defaults(dnb=False)
parser.set_defaults(only_ip=False)

results = parser.parse_args()

NUM_DOUBLE_CHECKS=results.ndc
INTERFACE=results.dev
ONLY_LOG=results.dnb
MODEL=results.model
OVS=results.ovs
ONLY_DST_IP=results.only_ip


print("DNS-over-HTTPS needs to be blocked")
print("Numer of double-checks for proof: {}".format(NUM_DOUBLE_CHECKS))
print("The OVS switch where the filtering is done: {}".format(OVS))
print("Loading model {}".format(MODEL))
rf3 = joblib.load(MODEL)
rf3.verbose=0
print("ML model has been loaded")

doh_data={ 
  "src_ip"   : "",
  "src_port" : "",
  "dst_ip"   : "",
  # dst_port : "", #THIS IS KNOWN AND STATIC FOR DoH packets (443)
  # ip_proto : "", #THIS IS KNOWN AND STATIC FOR DoH packets (6)
  "count"    : 0#,
  # "blocked"  : False
}
doh = dict()
blacklist=list()


#get current timestamp and convert it
ts = time.time()
timestamp = getDateFormat(str(ts))

# Open log files for blacklist five-tuples
logfile = open("five-tuples-to-block.flows_"+str(timestamp), "w")
logs = open("filter_5tuple.log_"+str(timestamp),"w")

def block_5_tuple(src_ip,dst_ip,src_port):
  r="\"table=1,priority=1000,tcp,nw_src=" + str(src_ip) + "," + \
    "nw_dst=" + str(dst_ip) + "," + \
    "tp_src=" + str(src_port) + "," + \
    "tp_dst=" + str(443) + ",idle_timeout=100,actions=drop\""
  
  logfile.write(r + str("\n"))
  logfile.flush()
  if(not ONLY_LOG):
    cmd=str("sudo ovs-ofctl add-flow " + OVS + " " + r)
    print(cmd)
    os.system(cmd)
  
def block_dst_ip(dst_ip):
  r="\"table=1,priority=1000,tcp,nw_dst=" + str(dst_ip) + ",idle_timeout=100, actions=drop\""
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

    #### ----------- DoH -------------
    if(prediction==1) :
      ans = 'DoH'
      # print("packet looks like DoH...DROP")
      # print("DoH service IP? : {}".format(packet[0][1].dst))
      logs.write("DoH service IP? : {}\n".format(packet[0][1].dst))
      three_tuple=str(packet[0][1].src) + \
                  str(packet[0][1].dst) + \
                  str(packet[0][2].sport)
      h=h11(three_tuple)
      #if IP was already identified as DoH service
      if h in doh:
        #increase its count
        doh[h]["count"]+=1
        doh[h]["dst_ip"]=packet[0][1].dst  
        doh[h]["src_ip"]=packet[0][1].src
        doh[h]["src_port"]=packet[0][2].sport
        #check if the current number is above the threshold
        if(doh[h]["count"] >= NUM_DOUBLE_CHECKS):
          logs.write("Classified as DoH : {}\n".format(packet[0][1].dst))
          if(ONLY_DST_IP):
            block_dst_ip(doh[h]["dst_ip"])
          else:
            block_5_tuple(doh[h]["src_ip"],doh[h]["dst_ip"],doh[h]["src_port"])
          del doh[h]
          # doh[h]["blocked"]=True
      #otherwise, initialize it
      else:
        doh[h]=doh_data
    #### ----------- HTTP2 -----------
    else :
      ans = 'Http2'
      # print("HTTP service IP? : {}".format(packet[0][1].dst))
      logs.write("Classified as HTTP2 : {}\n".format(packet[0][1].dst))
      
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

#we cannot filter on anything, because then packets missing the filter will not
#be forwarded by default
sniff(iface=INTERFACE, prn=filter_packets, store=0)

logfile.flush()
logfile.close()
