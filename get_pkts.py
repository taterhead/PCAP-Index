#!/usr/bin/env python

from struct import unpack
from scapy.all import *
from pkt_utils import * # custom library for common functions
import sys
import socket
import sqlite3
from optparse import OptionParser
from pyparsing import *
import datetime
import os


# Get packets script
# parseing portion inspired by http://pyparsing.wikispaces.com/file/view/simpleSQL.py
# Just want to essentially offer a 'sql' interface to the sqlite db

# To get list of offsets: c = db.execute("select group_concat(offset),group_concat(data_len) from pkt_index where dst_addr_ll=3232238591 order by offset").fetchone()
# gives a two element array of 'strings' of offsets

# Time format: 3-mar-2004 00:00:00

# Set up argument parser
clparser = OptionParser()

clparser.add_option("-s", "--sql", help="SQLite3 file to read from", action="store", type="string", dest="sql_fn")
clparser.add_option("-d", "--debug", help="Print debug output", action="store_true", default=False, dest="debug")
clparser.add_option("-f","--filter", help="Filter used to extract packets", action="store", type="string", dest="filter")
clparser.add_option("-w","--write", help="File to write output to. If not given, new PCAP file is written to standard output", action="store", type="string", dest="output_fn")

(options, args) = clparser.parse_args(sys.argv[1:])

if options.debug:
	sys.stderr.write("\nScript arguments: " + str(options))


### LEXICAL PARSING STUFF ###
# The lexical parser here might have been overkill. Probably could have accomplished what I wanted with regex's

# keywords
# TODO: should implement a generic 'host' and 'port' keyword - but these will get difficult because of how the rest of this parser works
time = Literal("time")
src = Literal("src")
sport = Literal("sport")
dst = Literal("dst")
dport = Literal("dport")
ether_type = Literal("ether_type")
ip_proto = Literal("ip_proto")

field = src|sport|dst|dport|ether_type|ip_proto

integer = Word(nums)

# IPv4 address
dottedIPv4 = Combine( Word(nums, max=3) + "." + Word(nums, max=3) + "." + Word(nums, max=3) + "." + Word(nums, max=3) )

# set up a parser action to replace the dotted quad IP with a number when it's matched
dottedIPv4.setParseAction(tokDottedQuadToNum)

# Ethernet address
colonEther = Combine( Word(hexnums, max=2) + ":" + Word(hexnums, max=2) + ":" + Word(hexnums, max=2) + ":" + Word(hexnums, max=2) + ":" + Word(hexnums, max=2) + ":" + Word(hexnums, max=2))

# Add a parse action for ethernet
colonEther.setParseAction(tokMacToInt)

# ok, kind of a kluge to get IPv6 together, from http://flex.sourceforge.net/manual/Addresses.html
hex4 = Word(hexnums, max=4)
hexseq = Combine(hex4 + ZeroOrMore( Combine(":" + hex4) ) )
hexpart = Combine( hexseq + Literal("::") + ZeroOrMore(hexseq)) |  Combine(Literal("::") + hexseq) 
colonIPv6 = hexpart | Optional(hexpart)

# Possible arguments. Only IPv4 and ethernet addressess since ipv6 takes it's own special format
arg = dottedIPv4 | colonEther | integer

# logic operators
and_ = Keyword("and", caseless=True)
or_ = Keyword("or", caseless=True)
# in_ = Keyword("in", caseless=True) not sure if I'll have this...
binop = oneOf("= != < > >= <=", caseless=True)

# We need to do some special stuff for replacing ipv6 - take single v6 address then compare it against four separate fields in the DB

# Set up a specific whereCondition for ipv6 addresses
whereConditionV6 = Group(field + binop + colonIPv6)

# Add a parse action
whereConditionV6.setParseAction(tokV6Replace)

# set up time expression
whereConditionTime = Group(time + binop + Word(nums,max=2) + "-" + Word(alphas, exact=3) + "-" + Word(nums, exact=4) + White(max=1) + Word(nums, exact=2) + ":" + Word(nums, exact=2) + ":" + Word(nums, exact=2))

whereConditionTime.setParseAction(tokModTime)

# build up complex expressions
whereExpression = Forward()
whereCondition = Group(
	( whereConditionV6 ) |
	( whereConditionTime ) |
	( time + binop + integer ) |
	( field + binop + arg ) |
	( "(" + whereExpression + ")" )
	)
whereExpression << whereCondition + ZeroOrMore( (and_ | or_) + whereExpression)

filterParsed = whereExpression.parseString(options.filter)

if options.debug:
	sys.stderr.write("\nFilter parsed: " + str(filterParsed))
filterStr = getStrFromNestedLists(filterParsed)

# Now need to replace src and dst with lowest order src/dst fields
# TODO: Could do this more elegantly using the parser - then could also specify the other src/dst ports as 0
filterStr = filterStr.replace("src ", "src_addr_ll ")
filterStr = filterStr.replace("dst ", "dst_addr_ll ")
filterStr = filterStr.replace("sport ", "src_port ")
filterStr = filterStr.replace("dport ", "dst_port ")

# Replace any 'time' values left with tv_s
filterStr = filterStr.replace("time ", "tv_s ")

if options.debug:
	sys.stderr.write("\nFilter as a string: " + filterStr)


# Now that the filter has been parsed, we can connect to the DB and get our info out of it
# Query is sorted by order they were inserted
db = sqlite3.connect(options.sql_fn)
cur = db.cursor()

query = cur.execute("select offset,data_len,pcap_fname from pkt_index where " + filterStr + " order by ROWID")


if options.debug:
	sys.stderr.write("\nQuery returns from sqlite: " + str(query))


# Open output file/stdout, open first input file, get pkt header -> iterate thru filenames -> seek through files and pull out data, write to file/stdout
if options.output_fn:
	f = open(options.output_fn, 'wb')
else:
	f = sys.stdout

# open the first pcap file and copy the header over - this should work in all cases(? - *knock on wood*)
first_row = query.fetchone()

# Check to make sure it actually returned something
if first_row:
	current_pcap = str(first_row[2])
	r = open(current_pcap,'rb')
	f.write(r.read(24)) # PCAP file header is 24 bytes long

	# write the first pkt data as well since we've already fetched that row off the results
	r.seek(int(first_row[0]),0)
	f.write(r.read( int(first_row[1])))

	# now iterate through offsets - check to make sure we have the right file open first though
	for row in query:
		if current_pcap != str(row[2]):
			r.close()
			current_pcap = str(row[2])
			r = open(current_pcap, 'rb')
		
		# Do an absolute seek
		r.seek(int(row[0]),0)
		f.write(r.read(int(row[1])))
		
	r.close()
		
else:
	sys.stderr.write("\nERROR: No results for that query\n")

	
db.close()
f.close()

		
	
