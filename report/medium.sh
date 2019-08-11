#!/bin/bash
# [ SEVERITY MEDIUM ]
# [ M SECURITY ONION - SGUIL DATABSE ]
# [ By Tiago Silva Leite tleite@bsd.com.br ]

MYSQL="mysql --defaults-file=/etc/mysql/debian.cnf -Dsecurityonion_db -e"

case $1 in

count)
$MYSQL "SELECT COUNT(event.priority) as cnt FROM event  INNER JOIN sensor ON event.sid=sensor.sid WHERE event.priority  BETWEEN 3 AND 4 AND sensor.hostname='$2';" |awk '{print $1}' |sed -e "1d"
;;

sensor)
$MYSQL "SELECT hostname FROM sensor WHERE sensor.hostname='$2';" |awk '{print $1}' |sed -e "1d"
;;

ip_src)
$MYSQL "SELECT timestamp,INET_NTOA(event.src_ip) FROM event IGNORE INDEX (event_p_key,sid_time) INNER JOIN sensor ON event.sid=sensor.sid WHERE event.priority  BETWEEN 3 AND 4 AND sensor.hostname='$2' ORDER BY timestamp DESC LIMIT 1;" |awk '{print $3}' |sed -e "1d"
;;

port_src)
$MYSQL "SELECT timestamp,src_port FROM event IGNORE INDEX (event_p_key,sid_time) INNER JOIN sensor ON event.sid=sensor.sid WHERE event.priority  BETWEEN 3 AND 4 AND sensor.hostname='$2' ORDER BY timestamp DESC LIMIT 1;" |awk '{print $3}' |sed -e "1d" 
;;

ip_dst)
$MYSQL "SELECT timestamp,INET_NTOA(event.dst_ip) FROM event IGNORE INDEX (event_p_key,sid_time) INNER JOIN sensor ON event.sid=sensor.sid WHERE event.priority  BETWEEN 3 AND 4 AND sensor.hostname='$2' ORDER BY timestamp DESC LIMIT 1;" |awk '{print $3}' |sed -e "1d"
;;

port_dst)
$MYSQL "SELECT timestamp,dst_port FROM event IGNORE INDEX (event_p_key,sid_time) INNER JOIN sensor ON event.sid=sensor.sid WHERE event.priority  BETWEEN 3 AND 4 AND sensor.hostname='$2' ORDER BY timestamp DESC LIMIT 1;" |awk '{print $3}' |sed -e "1d"
;;

signature)
$MYSQL "SELECT signature FROM event IGNORE INDEX (event_p_key,sid_time) INNER JOIN sensor ON event.sid=sensor.sid WHERE event.priority  BETWEEN 3 AND 4 AND sensor.hostname='$2' ORDER BY timestamp DESC LIMIT 1;" |sed -e "1d"
;;

id_signature)
$MYSQL "SELECT signature_id FROM event IGNORE INDEX (event_p_key,sid_time) INNER JOIN sensor ON event.sid=sensor.sid WHERE event.priority  BETWEEN 3 AND 4 AND sensor.hostname='$2' ORDER BY timestamp DESC LIMIT 1;" |sed -e "1d" 
;;

date_event)
$MYSQL "SELECT timestamp FROM event IGNORE INDEX (event_p_key,sid_time) INNER JOIN sensor ON event.sid=sensor.sid WHERE event.priority  BETWEEN 3 AND 4 AND sensor.hostname='$2' ORDER BY timestamp DESC LIMIT 1;" |sed -e "1d"
;;

#event_now)
#$MYSQL "SELECT timestamp,priority FROM event  INNER JOIN sensor ON event.sid=sensor.sid WHERE event.priority  BETWEEN 3 AND 4 AND sensor.hostname='loki-02-ens192-3' ORDER BY timestamp DESC LIMIT 1;" |awk '{print $3}' |sed -e "1d"
#;;

esac
