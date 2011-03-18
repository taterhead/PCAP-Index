#!/bin/bash

TOOL_PATH='/work/pcap_index/'

mkfifo $2.fifo

# index the packets, output to the fifo
$TOOL_PATH/index_pkts $1 > $2.fifo &

# Read the fifo
sqlite3 -init $TOOL_PATH/create_db.sql -csv $2 ".import $2.fifo pkt_index"

rm $2.fifo

