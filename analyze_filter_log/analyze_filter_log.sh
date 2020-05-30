#!/bin/bash
 
 source sources/extra.sh
 
 
function show_help 
 { 
 	c_print "Green" "This script does ...!"
 	c_print "Bold" "Example: sudo ./analyze_filter_log.sh "
 	c_print "Bold" "\t\t-l <LOGFILE>: Set the logfile of the filter_local.py here."
 	c_print "Bold" "\t\t-j <RESOLVER_JSON>: Set the resolver json file here (path to r_config.json)."
  c_print "Bold" "\t\t-n <DOUBLE_CHECKS_USED>: Set the number of double-checks used for the filter."
 	exit
 }

LOGFILE=""
RESOLVERS=""
DOUBLE_CHECKS=""

while getopts "h?l:j:n:" opt
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
  n)
 		DOUBLE_CHECKS=$OPTARG
    c_print "None" "#double-checls: ${DOUBLE_CHECKS}"
 		;;
 
 	*)
 		show_help
 		;;
 	esac
 done


if [ -z $LOGFILE ] || [ -z $RESOLVERS ] || [ -z $DOUBLE_CHECKS ]
 then
 	c_print "Red" "Undefined arguments!"
 	show_help
 fi

echo ""
get_http2_cmd="cat $LOGFILE|grep -i \"classified as HTTP2\"|cut -d ":" -f 2"

c_print "None" "Number of tuples classified as HTTP2:\t\t\t" 1
num_http=$(cat $LOGFILE|grep -i "classified as HTTP2"|cut -d ":" -f 2 |wc -l)
c_print "Blue" "${num_http}"

 
c_print "None" "Number of tuples classified as DoH (num double-checks: ${DOUBLE_CHECKS}) (TP):\t" 1
num_doh=$(cat $LOGFILE|grep -i "classified as DoH"|cut -d ":" -f 2 |wc -l)
num_doh=$(echo "${num_doh}/${DOUBLE_CHECKS}" | bc )
c_print "Blue" "${num_doh}"


c_print "None" "How many tuples were misclassified as DoH (false-positives):\t" 1
num_fp=0
for i in $(cat $LOGFILE|grep -i "classified as DoH"|cut -d ":" -f 2)
do
  cat $RESOLVERS|grep bootstrap|grep $i > /dev/null
  if [ $? -eq 1 ] #IP address not found in the bootstrap addresses, i.e., False-positive
  then
    num_fp=`expr $counter + 1`
  fi
done
c_print "Blue" "${num_fp}"


c_print "None" "Looking for false negatives..." 
num_fn=0
for i in $(cat $RESOLVERS|grep -i "bootstrap"|cut -d ":" -f 2|sed "s/\"//g")
do
  cat $LOGFILE|grep -i "classified as DoH"| grep $i > /dev/null
  if [ $? -eq 1 ] #DoH bootstrap address not found in the DoH-classified tuples, i.e., False-negatives
  then
    num_fn=`expr $counter + 1`
    c_print "Yellow" "${i}"
  fi
done
c_print "None" "How many DoH tuples were misclassified as HTTP2 (false-negative):\t" 1
c_print "Blue" "${num_fn}"


c_print "None" "True positives (sum DoH - #FP):\t" 1
num_tp=`expr $num_doh - $num_fp`
c_print "Blue" "${num_tp}"


c_print "None" "True negatives (sum HTTP2 - #FN):\t" 1
num_tp=`expr $num_http - $num_fn`
c_print "Blue" "${num_tp}"






