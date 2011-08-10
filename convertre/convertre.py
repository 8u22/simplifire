#!/usr/bin/python
################################################################################
# Copyright (c) 2011
# Daniel Plohmann <daniel.plohmann<at>gmail<dot>com>
# All rights reserved.
################################################################################
# Description:
#   collection of converter functions for flexible use.
#
################################################################################
#
#  This file is part of simpliFiRE
#
#  simpliFiRE is free software: you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see
#  <http://www.gnu.org/licenses/>.
#
################################################################################

import os, sys, optparse, traceback
import string, binascii, base64, zlib

VERSION = 1.0
PRINT_RANGE = 0x20
OUTPUT_DEST = None


# TODO Implement following features:
# XOR multikey guess (based on frequent substings / 0x20 sequences)
### http://crucialsecurityblog.harris.com/2011/07/06/decoding-data-exfiltration-%E2%80%93-reversing-xor-encryption/
# batch application of several hashing / checking algorithms

################################################################################
# implementation of manipulation options
################################################################################

def store_result(filename, contents):
    if OUTPUT_DEST is not None:
        out_file = open(OUTPUT_DEST + os.sep + filename, "wb")
        out_file.write(contents)
        out_file.close()
            
# apply multi-byte XOR against input string
def apply_xor(in_str, xor_str):
    """
    apply exclusive-or (XOR) operation to an input string with a specified 
    (multi-byte) pattern.
    @param in_str: (binary) string which is subject to manipulation
    @type in_str: (binary) string
    @param xor_str: (binary) string used for encryption / decryption
    @type xor_str: (binary) string
    @return: manipulated string
    """
    
    # unescape xor_str so that binary XOR strings can be easily input from 
    # console check for single backslash as special case, this would cause 
    # problems when unescaping
    if len(xor_str) == 1 and xor_str[0] == "\\":
        pass
    else:
        xor_str = xor_str.decode("string-escape")
    out_str = ""
    if len(xor_str) > 0:
        for index, char in enumerate(in_str):
            out_str += chr(ord(char) ^ ord(xor_str[index % len(xor_str)]))
    else: 
        out_str = in_str 
    store_result("xor_%s.bin" % binascii.hexlify(xor_str), out_str)           
    return out_str
    
# reverse order of given input
def reverse(in_str, size=0):
    """
    reverse the order of byte blocks found in an input string 
    @param in_str: (binary) string which is subject to manipulation
    @type in_str: (binary) string
    @param size: block size
    @type size: int
    @return: manipulated string
    """
    try:
        size = int(size)
    except Exception as exc:
        print "%s: \"%s\"" % (type(exc), exc)
    out_str = ""
    if size == 0:
        out_str = in_str
    elif size == 1:
        str_as_list = list(in_str)
        str_as_list.reverse()
        out_str = "".join(str_as_list)
    elif len(in_str) < size:
        out_str = in_str
    else:
        last_block_len = len(in_str) % size
        out_str = in_str[(len(in_str) - last_block_len):]
        loop_start = len(in_str) - last_block_len - size
        for index in xrange(loop_start, -1, -1*size):
            out_str += in_str[index:index+size]
    store_result("reverse_%04d.bin" % size, out_str)   
    
    return out_str

# shift bytes by n positions
def rotate_left(in_str, count):
    """
    rotate byte value by count into left direction (subtraction)
    @param in_str: (binary) string which is subject to manipulation
    @type in_str: (binary) string
    @param count: amount to shift
    @type count: int
    @return: manipulated string
    """
    try:
        count = int(count)
    except Exception as exc:
        print "%s: \"%s\"" % (type(exc), exc)
    out_str = ""
    for char in in_str:
        out_str += chr((ord(char) - count) % 256)
    store_result("rot_%03d.bin" % count, out_str)   
    return out_str

# caesar-style shift characters of alphabet by n positions
def caesar(in_str, count):
    """
    perform linear caesar substitution on input, only the alphabet is affected
    @param in_str: (binary) string which is subject to manipulation
    @type in_str: (binary) string
    @param count: amount to shift
    @type count: int
    @return: manipulated string
    """
    try:
        count = int(count) % 26
    except Exception as exc:
        print "%s: \"%s\"" % (type(exc), exc)
    out_str = ""
    for char in in_str:
        if char in string.ascii_uppercase:
            out_str += chr((ord(char) - 0x41 + count) % 26 + 0x41)
        elif char in string.ascii_lowercase:
            out_str += chr((ord(char) - 0x61 + count) % 26 + 0x61)
        else:
            out_str += char
    store_result("caesar_%02d.bin" % count, out_str)   
    return out_str
        
    
# byte-wise rotation of bits to the left
def bitrotate_left(in_str, count):
    """
    on byte-level rotate bits by count into left direction 
    @param in_str: (binary) string which is subject to manipulation
    @type in_str: (binary) string
    @param count: amount to shift
    @type count: int
    @return: manipulated string
    """
    try:
        count = int(count) % 8
    except Exception as exc:
        print "%s: \"%s\"" % (type(exc), exc)
    # python does not support rotate but only binary shift operations
    # implement by doing a shift in both directions 
    out_str = ""
    for char in in_str:
        out_str += chr((ord(char) << count | ord(char) >> (8 - count)) & 0xFF)
    store_result("rol_%d.bin" % count, out_str)   
    return out_str

# BASE(16, 32, 64) encoding / decoding
def encode_base64(in_str):
    out_str = base64.b64encode(in_str)
    store_result("en_b64.bin", out_str)   
    return out_str

def decode_base64(in_str):
    if not len(in_str) % 4 == 0:
        in_str = in_str[:len(in_str)-(len(in_str) % 4)]
    out_str = base64.b64decode(in_str)
    store_result("de_b64.bin", out_str)  
    return out_str
    
def encode_base32(in_str):
    # standard RFC 3548 encoding
    out_str = base64.b32encode(in_str)
    store_result("en_b32.bin", out_str)   
    return out_str

def decode_base32(in_str):
    # ensure length of input string is a multiple of 8 or crop from the end
    # otherwise 
    if not len(in_str) % 8 == 0:
        in_str = in_str[:len(in_str)-(len(in_str) % 8)]
    out_str = base64.b32decode(in_str)
    store_result("de_b32.bin", out_str)  
    return out_str
      
def encode_base32hex(in_str):
    # For encoding in base32hex (RFC 4648), make use of base64's encoding 
    # function for base32 and map the result to base32hex charset
    pre_str = base64.b32encode(in_str)
    b32 = (string.ascii_uppercase+"234567=")
    b32hex = (string.digits+string.ascii_uppercase)[:32] + "="
    b32_to_b32hex = dict(zip(b32, b32hex))
    out_str = "".join([b32_to_b32hex[c] for c in pre_str])
    store_result("en_b32h.bin", out_str)   
    return out_str

def decode_base32hex(in_str):
    if not len(in_str) % 8 == 0:
        in_str = in_str[:len(in_str)-(len(in_str) % 8)]
    b32 = (string.ascii_uppercase+"234567=")
    b32hex = (string.digits+string.ascii_uppercase)[:32] + "="
    b32hex_to_b32 = dict(zip(b32hex, b32))
    pre_str = "".join([b32hex_to_b32[c] for c in in_str])
    out_str = base64.b32decode(pre_str)
    store_result("de_b32h.bin", out_str)  
    return out_str
    
def encode_base16(in_str):
    out_str = binascii.hexlify(in_str)
    store_result("en_b16.bin", out_str)   
    return out_str
    
def decode_base16(in_str):
    if not len(in_str) % 2 == 0:
        in_str = in_str[:len(in_str)-(len(in_str) % 2)]
    out_str = binascii.unhexlify(in_str)
    store_result("de_b16.bin", out_str)  
    return out_str
    

# Infalte / Deflate
# TODO validate correctness
# source: http://stackoverflow.com/questions/2424945/are-zlib-compress-on-python-and-deflater-deflate-on-java-android-compatible
def deflate(in_str):
    zobj = zlib.compressobj(6, zlib.DEFLATED, -zlib.MAX_WBITS, \
        zlib.DEF_MEM_LEVEL, 0)
    out_str = zobj.compress(in_str)
    out_str += zobj.flush()
    store_result("deflate.bin", out_str)  
    return out_str
    
def inflate(in_str):
    zobj = zlib.compressobj(6, zlib.DEFLATED, zlib.MAX_WBITS, \
        zlib.DEF_MEM_LEVEL, 0)
    out_str = zobj.compress(in_str)
    out_str += zobj.flush()
    store_result("inflate.bin", out_str)  
    return out_str
    
# standard compression
def compress(in_str):
    out_str = zlib.compress(in_str)
    store_result("compress.bin", out_str)
    return out_str  

def decompress(in_str):
    out_str = zlib.decompress(in_str)
    store_result("decompress.bin", out_str)
    return out_str 


################################################################################
# searching for occurences of a search string in a search space made up by 
# application of manipulations on an input string
################################################################################

def find_all(in_str, target, offset=0):
    """
    find all occurrences of target in in_str, start at offset
    @param in_str: (binary) string to search in
    @type in_str: (binary) string
    @param target: target sequence to find
    @type target: string
    @param offset: offset to start search at
    @type offset: int
    @return: list of found indices
    """
    index = in_str.find(target, offset)
    indices = []
    while index >= 0:
        indices.append(index)
        index = in_str.find(target, index + 1)
    return indices

# Search for a target string in all possible one-byte XOR, ROL and ROT 
# manipulations of a input string credits for the idea go to Didier Stevens. 
# source: http://blog.didierstevens.com/programs/xorsearch/
def multi_find(in_str, target):
    """
    perform a search of target against the search space made up by all possible
    combinations of in_str against xor, rol, rot, and caesar.
    @param in_str: (binary) string to search in
    @type in_str: (binary) string
    @param target: target sequence to find
    @type target: string
    @return: list of dicitionaries {manipulation, parameter, offset}
    """
    results = []
    for param in xrange(256):
        mod = apply_xor(in_str, chr(param))
        indices = find_all(mod, target)
        if len(indices) > 0:
            for index in indices:
                result = {"manipulation": "XOR", 
                            "parameter": param,
                            "offset": index}
                results.append(result)
    print "-> XOR completed"
                
    for param in xrange(1, 8):
        mod = bitrotate_left(in_str, param)
        indices = find_all(mod, target)
        if len(indices) > 0:
            for index in indices:
                result = {"manipulation": "ROTATE_BIT", 
                            "parameter": param,
                            "offset": index}
                results.append(result)
    print "-> ROL completed"
                
    for param in xrange(1, 256):
        mod = rotate_left(in_str, param)
        indices = find_all(mod, target)
        if len(indices) > 0:
            for index in indices:
                result = {"manipulation": "ROTATE_BYTE", 
                            "parameter": param,
                            "offset": index}
                results.append(result)
    print "-> ROT completed"    
                
    for param in xrange(1, 26):
        mod = caesar(in_str, param)
        indices = find_all(mod, target)
        if len(indices) > 0:
            for index in indices:
                result = {"manipulation": "CAESAR", 
                            "parameter": param,
                            "offset": index}
                results.append(result)
    print "-> CAESAR completed."
    print "finished, generating output."
    
    return results
    
def print_multi_find_results(in_str, results):
    """
    nicely format the results of multi_find
    @param in_str: (binary) string to extract results from
    @type in_str: (binary) string
    @param results: results of multi_find()
    @type results: list of dicitionaries {manipulation, parameter, offset}
    @return: None
    """
    results = list(results)
    xors = []
    rols = []
    rots = []
    caesars = []
    for result in results:
        result = dict(result)
        if result["manipulation"] == "XOR":
            xors.append(result)
        elif result["manipulation"] == "ROTATE_BIT":
            rols.append(result)
        elif result["manipulation"] == "ROTATE_BYTE":
            rots.append(result)
        elif result["manipulation"] == "CAESAR":
            caesars.append(result)
        else:
            raise ValueError("Unknown manipulation method for multi find")
    print "Multi-Find Results: %d total occurrences (XOR: %d, ROL: %d, ROT: " \
        "%d, CAESAR: %d)" % (len(results), len(xors), len(rols), len(rots), \
        len(caesars))
    
    sections = ["XOR", "ROL", "ROT", "CAESAR"]
    manipulators = [apply_xor, bitrotate_left, rotate_left, caesar]
    for index, section in enumerate([xors, rols, rots, caesars]):
        section = list(section)
        for manipulation in section:
            manipulation = dict(manipulation)
            param = manipulation["parameter"]
            offset = manipulation["offset"]
            # modify only the extracted substring for efficiency reasons 
            occurrence = in_str[max(0, offset-PRINT_RANGE):offset+PRINT_RANGE]
            if index == 0:
                # XOR receives a string as input
                occurrence = manipulators[index](occurrence, chr(param))
            else:
                occurrence = manipulators[index](occurrence, param)
            
            print "% 8s(%03d) 0x%08x: %s" % (sections[index], param, offset, \
                occurrence)
            
    return
    
################################################################################
# parsing, error handling
################################################################################

# dummy in case some unimplemented method is called
def not_implemented(in_str):
    print "not implemented yet."
    sys.exit(1)

# map arguments to functions to allow easy parsing
ENCODERS = {"BASE64": encode_base64, 
            "BASE32": encode_base32, 
            "BASE32HEX": encode_base32hex, 
            "BASE16": encode_base16, 
            "INFLATE": inflate, 
            "COMPRESS": compress}
            
DECODERS = {"BASE64": decode_base64, 
            "BASE32": decode_base32, 
            "BASE32HEX": decode_base32hex,
            "BASE16": decode_base16,  
            "DEFLATE": deflate, 
            "DECOMPRESS": decompress}

# these callbacks validate that only one of the input options is used
def check_order(option, opt_str, value, parser):
    if str(option) == "-i/--input-file":
        if parser.values.input_string:
            print "only use one option of (input-string, input-file, input-pipe)"
            sys.exit(1)
        else:
            setattr(parser.values, option.dest, value) 
    elif str(option) == "-p/--input-pipe":
        if parser.values.input_string or parser.values.input_file:
            print "only use one option of (input-string, input-file, input-pipe)"
            sys.exit(1)
        else:
            setattr(parser.values, option.dest, True)
    else:
        pass
          
def setup_parser():
    """ 
    helper function for setting up the argument parser
    """
    parser = optparse.OptionParser()
	
	# I/O control options
    input_group = optparse.OptionGroup(parser, "I/O options",
                        "these parameters control the input source.")

    parser.add_option("-v", "--version", 
        dest="version",
        action="store_true",
        help="show disclaimer",
        default=False)
        
    input_group.add_option("-s", "--input-string", 
        dest="input_string", 
        type=str, 
        help="input string to manipulate",
        default=None)
        
    input_group.add_option("-i", "--input-file", 
        dest="input_file", 
        type=str, 
        help="input file to load and manipulate",
        action="callback", callback=check_order,
        default=None)
        
    input_group.add_option("-p", "--input-pipe", 
        dest="input_pipe", 
        help="receive input from pipe",
        action="callback", callback=check_order,
        default=False)
        
    input_group.add_option("-o", "--output-destination", 
        dest="output_dest", 
        type=str,
        help="this option allows definition of an output folder where " \
        "manipulation results will be stored.",
        default=None)
        
    parser.add_option_group(input_group)
        
	# manipulation control options
    manipulation_group = optparse.OptionGroup(parser, "MANIPULATION options",
                        "these parameters control the type of manipulation.")
	
    manipulation_group.add_option("-c", "--caesar",
        dest="caesar", 
        type=str,
        default=None,
        help="apply caesar-style byte-wise rotation by ROT=[0-25] positions " \
            "in the alphabet")
        
    manipulation_group.add_option("-d", "--decoder",
        dest="decoder", 
        type=str,
        default=None,
        help="decode with specified method: (%s)" % ", ".join(DECODERS))
        
    manipulation_group.add_option("-e", "--encoder", 
        dest="encoder", 
        type=str,
        default=None,
        help="encode with specified method: (%s)" % ", ".join(ENCODERS))
        
    manipulation_group.add_option("-f", "--find",
        dest="find", 
        type=str,
        default=None,
        help="find occurences of a target in the search space created by all " \
            "possible XOR, ROL, ROT and CAESAR operations against the input.")
        
    manipulation_group.add_option("-l", "--rol",
        dest="rol", 
        type=str,
        default=None,
        help="apply byte-wise bitrotation by ROL=[0-7] bits")
        
    manipulation_group.add_option("-r", "--rotate",
        dest="rot", 
        type=str,
        default=None,
        help="apply byte-wise linear shift left by ROT=[0-255] positions in " \
            "ASCII range.")
        
    manipulation_group.add_option("-x", "--xor",
        dest="xor", 
        type=str,
        default=None,
        help="apply byte-wise XOR operation with given (multi-byte) string " \
            "XOR. It is possible to specify arbitrary bytes with usual " \
            "string-escaping: \"\\x41\\x20\\x42\" equals \"A B\". Will spit " \
            "errors if XOR stings ends on a single \"\\\"")
            
    manipulation_group.add_option("-y", "--reverse",
        dest="reverse", 
        type=str,
        default=None,
        help="reverse input, ordered in blocks of size REVERSE=[0..len(input)].")
        
    parser.add_option_group(manipulation_group)
        
    return parser

# MAIN function - parse input and call above defined algorithms

def main():
    """ 
    main function, will be executed when used from command line. 
    """

    parser = setup_parser()
        
    # parse arguments
    options, args = parser.parse_args()

    # print version
    if options.version:
        # simplifire_utils.print_disclaimer()
        info_text = "# convertRE v%1.02f\n" \
                    "# A python-based shell tool for easy manipulation of " \
                    "input with frequently used\n" \
                    "# techniques for obfuscation" % VERSION
        print info_text
        sys.exit(0)
    
    input_source = ""
    global OUTPUT_DEST
    combined_input = ""
    
    # check if either string or file input is given, otherwise read from stdin
    try:
        if options.input_string is not None:
            combined_input = options.input_string
            input_source = "string (len: %d)" % len(combined_input)
        elif options.input_file is not None:
            f_input = open(options.input_file, "rb")
            combined_input = f_input.read()
            input_source = "file \"%s\" (len: %d)" % (options.input_file, \
                len(combined_input))
        elif options.input_pipe: 
            # reopen stdin as unbuffered
            sys.stdin = os.fdopen(sys.stdin.fileno(), 'rb', 0)
            combined_input = sys.stdin.read()
            input_source = "stdin (len: %d)" % len(combined_input)
        else:
            parser.print_help()
        if options.output_dest is not None:
            OUTPUT_DEST = options.output_dest
            if not os.path.isdir(OUTPUT_DEST):
                os.makedirs(OUTPUT_DEST)
    except Exception as exc:
        print "%s: \"%s\"" % (type(exc), exc)
        traceback.print_exc()
        sys.exit(1)
        
    # parse manipulation method
    try:
        if options.caesar:
            sys.stdout.write(caesar(combined_input, options.caesar))
            sys.stdout.flush()
        elif options.decoder is not None:
            if options.decoder.upper() in DECODERS:
                # parse decoder type and call corresponding function
                dec_str = DECODERS.get(options.decoder.upper(), \
                    not_implemented)(combined_input)
                sys.stdout.write(dec_str)
                sys.stdout.flush()
            else:
                print "unsupported decoder, try: ", DECODERS
        elif options.encoder is not None:
            if options.encoder.upper() in ENCODERS:
                # parse encoder type and call corresponding function
                enc_str = ENCODERS.get(options.encoder.upper(), \
                    not_implemented)(combined_input)
                sys.stdout.write(enc_str)
                sys.stdout.flush()
            else:
                print "unsupported encoder, try: ", ENCODERS
        elif options.find:
            results = multi_find(combined_input, options.find)
            print_multi_find_results(combined_input, results)
        elif options.rol:
            sys.stdout.write(bitrotate_left(combined_input, options.rol))
            sys.stdout.flush()
        elif options.rot:
            sys.stdout.write(rotate_left(combined_input, options.rot))
            sys.stdout.flush()
        elif options.xor:
            sys.stdout.write(apply_xor(combined_input, options.xor))
            sys.stdout.flush()
        elif options.reverse:
            sys.stdout.write(reverse(combined_input, options.reverse))
            sys.stdout.flush()

    except Exception as exc:
        print "%s: \"%s\"" % (type(exc), exc)
        traceback.print_exc()
        sys.exit(1)

    return

if __name__ == "__main__":
    sys.exit(main())
    
