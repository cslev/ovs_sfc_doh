#!/bin/bash
 
 source sources/extra.sh
 
 
function show_help 
 { 
 	c_print "Green" "This script does ...!"
 	c_print "Bold" "Example: sudo ./analyze_filter_log.sh "
 	c_print "Bold" "\t\t-l <LOGFILE>: Set the logfile of the filter_local.py here."
 	c_print "Bold" "\t\t-j <RESOLVER_JSON>: Set the resolver json file here (path to r_config.json)."
 	exit
 }

LOGFILE=""
RESOLVERS=""


while getopts "h?l:j:" opt
 do
 	case "$opt" in
 	h|\?)
 		show_help
 		;;
 	l)
 		LOGFILE=$OPTARG
    c_print "None" "Logfile: ${LOGFILE}"
 		;;
 	j)
 		RESOLVERS=$OPTARG
    c_print "None" "r_config.json: ${RESOLVERS}"
 		;;
 
 	*)
 		show_help
 		;;
 	esac
 done


if [ -z $LOGFILE ] || [ -z $RESOLVERS ]
 then
 	c_print "Red" "Undefined arguments!"
 	show_help
 fi

echo ""
get_http2_cmd="cat $LOGFILE|grep -i \"classified as HTTP2\"|cut -d ":" -f 2"

c_print "None" "Number of tuples classified as HTTP2:\t" 1
num_http=$(cat $LOGFILE|grep -i "classified as HTTP2"|cut -d ":" -f 2 |cut -d ',' -f 3|wc -l)
c_print "Blue" "${num_http}"

 
c_print "None" "Number of tuples classified as DoH:\t" 1
num_doh=$(cat $LOGFILE|grep -i "classified as DoH"|cut -d ":" -f 2 |cut -d ',' -f 3|wc -l)
c_print "Blue" "${num_doh}"


c_print "None" "How many tuples were misclassified as DoH (false-positives):\t" 1
num_fp=0
for i in $(cat $LOGFILE|grep -i "classified as DoH"|cut -d ":" -f 2|cut -d ',' -f 3)
do
  cat $RESOLVERS|grep bootstrap|grep $i > /dev/null
  if [ $? -eq 1 ] #IP address not found in the bootstrap addresses, i.e., False-positive
  then
    num_fp=`expr $num_fp + 1`
  fi
done
c_print "Blue" "${num_fp}"


#c_print "None" "Looking for false negatives..." 
num_fn=0
for i in $(cat $RESOLVERS|grep -i "bootstrap"|cut -d ":" -f 2|sed "s/\"//g")
do
  #looking for the DoH resolvers IPs that were once identified as HTTP2
  cat $LOGFILE|grep -i "classified as HTTP2"| grep $i > /dev/null
  if [ $? -eq 0 ] #DoH bootstrap address not found in the DoH-classified tuples, i.e., False-negatives
  then
    num_fn=`expr $num_fn + 1`
    #c_print "Yellow" "${i}"
  fi
done

c_print "Yellow" "==========================="

c_print "None" "True positives (sum DoH - #FP):\t" 1
num_tp=`expr $num_doh - $num_fp`
c_print "Blue" "${num_tp}"


c_print "None" "True negatives (sum HTTP2 - #FN):\t" 1
num_tn=`expr $num_http - $num_fn`
c_print "Blue" "${num_tn}"

c_print "None" "False positives (How many HTTP2 tuples were classified as DoH):\t" 1
c_print "Blue" "${num_fp}"

c_print "None" "False negatives (How many DoH tuples were misclassified as HTTP2):\t" 1
c_print "Blue" "${num_fn}"






