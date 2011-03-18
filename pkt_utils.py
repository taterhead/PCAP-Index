#!/usr/bin/env python

import socket, struct
import datetime
### functions
# inspiration from: http://code.activestate.com/recipes/577191-ip-and-mac-addresses/

def mac2int(addr, sep=":"):
     # convert a MAC str to an int
	h = addr.split(sep)
	i = 0
	for d in h:
		d = int(d, 16)
		if 0 <= d < (1<<8):
			i = (i << 8) | d
		else:
			break
		
	return i

# Also for retrieval, from http://code.activestate.com/recipes/66517-ip-address-conversion-functions-with-the-builtin-s/
# IP address manipulation functions, dressed up a bit

def dottedQuadToNum(ip):
    "convert decimal dotted quad string to long integer"
    return struct.unpack('!L',socket.inet_aton(ip))[0]
	
def numToDottedQuad(n):
    "convert long int to dotted quad string"
    return socket.inet_ntoa(struct.pack('!L',n))

##
# Return an array of four ints, indicating four 32 bit chunks of an IPv6 address
#
def colonIPv6To4Int(ip):
	raw_addr = socket.inet_pton(socket.AF_INET6, ip)
	addr_hh = struct.unpack('!L', raw_addr[0:4])[0]
	addr_h = struct.unpack('!L', raw_addr[4:8])[0]
	addr_l = struct.unpack('!L', raw_addr[8:12])[0]
	addr_ll = struct.unpack('!L', raw_addr[12:])[0]
	return addr_hh, addr_h, addr_l, addr_ll

##
# Function to modify the matched time tokens when they include a date
#
def tokModTime(tok):
	time_str = getStrFromNestedLists(tok[0][2:], '')
	# print "Time str " + time_str

	# rename 'time' to 'tv_s' to match DB schema
	tok[0][0] = 'tv_s'

	# convert the timestamp - should do some error checking here at some point...
	tok[0][2] = str( datetime.datetime.strptime(time_str, "%d-%b-%Y %H:%M:%S").strftime("%s") )
	# delete the remainder to the token list
	del(tok[0][3:])

	# print "New time token " + str(tok)
	return tok

##
# Take the tokens that match a dotted quad IP, convert to an int and return the number
#
def tokDottedQuadToNum(toks):
	toks[0] = str(dottedQuadToNum(toks[0]))
	return toks

##
# Take tokens for MAC, convert to an int and return number
#
def tokMacToInt(toks):
	toks[0] = str(mac2int(toks[0]))
	return toks


##
# Function to take matched IPv6 fields and the field and operator (ie/ "src > fe80::1"). 
# Separates the v6 address into four 32 bit addresses, then returns a token list which includes comparisons against each of the appropriate DB fields (ie/ src_addr_hh, src_addr_h, etc)
#
def tokV6Replace(toks):
	v6_array = colonIPv6To4Int(toks[0][2])
	new_toks = []
	new_toks.append([])
	new_toks[0].append(toks[0][0] + "_addr_hh")
	new_toks[0].append(toks[0][1])
	new_toks[0].append(str(v6_array[0]))
	new_toks[0].append("and")

	new_toks[0].append(toks[0][0] + "_addr_h")
	new_toks[0].append(toks[0][1])
	new_toks[0].append(str(v6_array[1]))
	new_toks[0].append("and")

	new_toks[0].append(toks[0][0] + "_addr_l")
	new_toks[0].append(toks[0][1])
	new_toks[0].append(str(v6_array[2]))
	new_toks[0].append("and")

	new_toks[0].append(toks[0][0] + "_addr_ll")
	new_toks[0].append(toks[0][1])
	new_toks[0].append(str(v6_array[3]))
	
	# print new_toks
	return new_toks

## 
# Recursive function to take a list of lists of lists... of strings and return a single string
# needed this because this is what pyparsing returns, but I just wanted the string
#
def getStrFromNestedLists(l, separator = " "):
    y = ''
    for i in l:
            if type(i) == str:
                    y = y + i + separator
            else:
                    y = y + getStrFromNestedLists(i)
    return y
