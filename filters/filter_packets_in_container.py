#!/usr/bin/python3
# coding: utf-8

from scapy.all import sniff , send , sendp, IP
from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.tls.all import TLS
from scapy.layers.tls.handshake import TLSClientHello,TLS13ClientHello,TLSServerHello,TLS13ServerHello
import argparse

#for ML model
from collections import Counter
import joblib
import numpy as np

import ja3 as ja3

parser = argparse.ArgumentParser(description="Python-based DNS filter!")

parser.add_argument('-f', '--filter-dns', action="store_true", dest="filter_dns" , help="Enable pure DNS based filtering (Default: False)")
parser.set_defaults(filter_dns=False)

parser.add_argument('-d', '--domain', action="store", default="index.hu", type=str, dest="domain_to_filter" , help="Specify the domain to filter for with DNS (Default: index.hu)! Use only with -f/--filter-dns option!")

parser.add_argument('-g', '--filter-doh', action="store_true", dest="filter_doh" , help="Enable DoH-based filtering - This will drop all packets that looks like a DoH query (Default: False)")
parser.set_defaults(filter_doh=False)

results = parser.parse_args()

filter_dns=results.filter_dns
domain_to_filter=results.domain_to_filter
filter_doh=results.filter_doh

print("Configuration:")
if(not filter_dns):
  print("BLIND FORWARDING MODE")
else:
  print("The following domain will be blocked via pure DNS: {}".format(domain_to_filter))

if(not filter_doh):
  print("DNS-over-HTTPS is allowed")
else:
  print("DNS-over-HTTPS needs to be blocked")
  rf3 = joblib.load("model2_rf3.pkl")
  rf3.verbose=0
  print("ML model has been loaded")


##  ============ PURE DNS FILTERING ============
def filter_dns_packets(packet):
  if packet.qdcount > 0 and isinstance(packet.qd, DNSQR):
    #print("DNS query")
    name = packet[DNSQR].qname
    #print(name)
    if(domain_to_filter in str(name)):
      # DNS queries looking for domain_to_filter will be dropped
      print("Gotcha {}  - DROP".format(domain_to_filter))
    else:
      # FORWARD every other DNS queries
      sendp(packet, iface="eth0", verbose=0)
      print("FORWARDING DNS query ({})...".format(name))
## ------- PURE DNS FILTERING END ------


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

      if(prediction==1) :
        ans = 'DoH'
        # print("packet looks like DoH...DROP")
        print("DoH service IP? : {}".format(packet[0][1].dst))
      else :
        ans = 'Http2'
        print("HTTP service IP? : {}".format(packet[0][1].dst))
        sendp(packet, iface="eth0",verbose=0)

      print("The packet was : "+ ans)
      # print(X_train)
      # diff = t1-t0
      # diff = round(diff,5)
      #print("Prediction time is "+ str(diff) +"sec" )


      ### updating values for next cycle
      filter_doh_packets.prev_time = time
      filter_doh_packets.prev_lag = time_lag_curr
      filter_doh_packets.prev_number = filter_doh_packets.number
      filter_doh_packets.prev_len = length

  # print("Making prediction for packet:")
  # print(packet.summary())
  return make_pred(packet)

filter_doh_packets.prev_time = 0
filter_doh_packets.prev_len = 0
filter_doh_packets.prev_lag = 0
filter_doh_packets.number = 0
filter_doh_packets.prev_number= 0
## ----- DNS-over-HTTPS filtering END ----------------




def filter_packets(packet):
  #Scapy cannot distinguish between incoming and outgoing packets, so
  #to avoid infinite loop, let's change outgoing packet's MAC
  new_mac="00:11:22:33:44:55"

  if IP in packet:
    #packets coming from the user
    if(packet[0][1].dst != "10.10.10.101" and packet[0][0].src != new_mac):
      #setting the source MAC to a pseudo-random one
      packet[0][0].src=new_mac

      ### ------- HERE COMES ANY FILTERING --------- ###
      ##------- NO FILTER ---------
      if(not filter_dns and not filter_doh):
        # FORWARD everything else
        sendp(packet, iface="eth0", verbose=0)
        print("FORWARDING without restriction")
      ## -------- FILTERING -------
      else:
        ##  ============ PURE DNS FILTERING ============
        if(packet.haslayer(DNS) and filter_dns):
          filter_dns_packets(packet)
        ## ------- PURE DNS FILTERING END ------

        ## ============  DNS-over-HTTPS filtering ===========
        elif(packet.haslayer(TLS) and filter_doh):
          filter_doh_packets(packet)
        ## ----- DNS-over-HTTPS filtering END ----------------
        else:
          sendp(packet, iface="eth0", verbose=0)
          # print("FORWARDING non-filtered packets")
      ####============== FILTERING ENDS ============####


    elif(packet[0][1].dst == "10.10.10.101"):
      # This host was the destination
      # print("I was the destination")
      pass
    elif(packet[0][1].src == "10.10.10.101"):
      # Reply sent
      # print("Reply sent")
      pass
    else:
      #this is actually the same packet but outgoing...scapy sniffer
      # print("Packet sent out")
      pass


#we cannot filter on anything, because then packets missing the filter will not
#be forwarded by default
sniff(iface="eth0", prn=filter_packets)
