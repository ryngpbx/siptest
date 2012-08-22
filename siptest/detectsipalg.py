#! /usr/bin/env python

"""
Script to detect SIP ALG activity on client's upstream router. It sends an
INVITE packet to Jazinga's SIP ALG detecting server and receives responses
from the server. It tests if SIP ALG is enabled on router by comparing its
sent request and the mirrored request received from the server.
"""

import random, socket, base64, fcntl, struct, errno, sys
import os, sys, logging, logging.handlers
from optparse import OptionParser

log = logging.getLogger( __name__ )
SYSLOG_DEV = '/dev/log'
SYS_FORMAT = os.path.basename(sys.argv[0]) + '[%(process)d]: %(levelname)s: %(name)s: %(message)s'

def random_string( length = 6, chars = "abcdefghjkmnpqrstuvwxyz0123456789" ):
    return "".join([
        random.choice( chars )
        for x in range( length )
    ])

def generate_tag():
    return random_string( 8 )

def generate_branch():
    return 'z9hG4bK' + random_string( 8 )

def generate_callid():
    return random_string( 10 )

def generate_cseq():
    return random.randint( 0, 999 )

def get_gateway_interface():
    """ Determine the interface which the default gateway is associated with """
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] !=  '00000000' or not int(fields[3], 16) & 2:
                continue
            return fields[0]

def get_ip_address(ifname):
    """ Get IP address of an ethernet interface """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

TIMEOUT = 5
BUFSIZE = 4096
SERVER_IP = None
SERVER_PORT = None
LOCAL_IP = get_ip_address( get_gateway_interface() )
LOCAL_PORT = 12345
TRANSPORT = "udp"

(
    EXIT_CODE_DETECTED,
    EXIT_CODE_NOT_DETECTED,
    EXIT_CODE_TEST_FAILED_SOCKET_TIMEOUT,
    EXIT_CODE_TEST_FAILED_CONN_REFUSED,
    EXIT_CODE_TEST_FAILED_SOCKET_ERRORS,
    EXIT_CODE_TEST_FAILED_BAD_RESPONSES,
    EXIT_CODE_TEST_FAILED_UNKNOWN,
) = range( 10, 17 )

def get_request():
    # Generate an INVITE as request
    body = """v=%s\r
o=%s %s %s IN IP4 %s\r
s=-\r
c=IN IP4 %s\r
t=0 0\r
m=audio %s RTP/AVP 8 0 3 101\r
a=rtpmap:8 PCMA/8000\r
a=rtpmap:0 PCMU/8000\r
a=rtpmap:3 GSM/8000\r
a=rtpmap:101 telephone-event/8000\r
a=fmtp:101 0-15\r
a=ptime:20\r
""" % ( random_string(1, "0123456789"), random_string(8), random_string(8, "0123456789"), random_string(7, "0123456789"), LOCAL_IP, LOCAL_IP, random_string(4, "123456789") )
    headers = """INVITE sip:sip-alg-detector-daemon@%s:%s SIP/2.0\r
Via: SIP/2.0/%s %s:%s;rport;branch=%s\r
Max-Forwards: 5\r
To: <sip:sip-alg-detector-daemon@%s:%s>\r
From: "SIP ALG Detector" <sip:sip-alg-detector@killing-alg-routers.war>;tag=%s\r
Call-ID: %s@%s\r
CSeq: %s INVITE\r
Contact: <sip:0123@%s:%s;transport=%s>\r
Allow: INVITE\r
Content-Type: application/sdp\r
Content-Length: %s\r
""" % ( SERVER_IP, SERVER_PORT, TRANSPORT.upper(), LOCAL_IP, LOCAL_PORT, generate_branch(), SERVER_IP, SERVER_PORT, generate_tag(), generate_callid(), LOCAL_IP, generate_cseq(), LOCAL_IP, LOCAL_PORT, TRANSPORT, len(body) )
    return headers + "\r\n" + body

def s_receive(s):
    # For testing with globalsub
    return s.recv( BUFSIZE )

def compare_request_and_mirror( request, mirror_request ):
    # Compare sent request and mirrored request
    try:
        request = request.split("\r\n")
        mirror_request = mirror_request.split("\r\n")
        for i in range(len(request) - 1):
            if not request[i] == mirror_request[i]:
                return EXIT_CODE_DETECTED
        return EXIT_CODE_NOT_DETECTED
    except IndexError, err:
        return EXIT_CODE_TEST_FAILED_BAD_RESPONSES
    except Exception, err:
        return EXIT_CODE_TEST_FAILED_UNKNOWN

def main():
    sys_log = logging.handlers.SysLogHandler( SYSLOG_DEV )
    sys_log.setLevel( logging.DEBUG )
    sys_log.setFormatter( logging.Formatter( SYS_FORMAT ) )
    log.setLevel( logging.DEBUG )
    log.addHandler(sys_log)

    parser = OptionParser()
    parser.add_option("--address", action="store", dest="address")
    parser.add_option("--port", action="store", dest="port", default="5060")
    options, args = parser.parse_args()
    SERVER_IP = options.address
    SERVER_PORT = int(options.port)
    return perform_test(SERVER_IP, SERVER_PORT)

def perform_test(server, port):
    try:
        request = get_request()
        try:
            # Send request to server
            s = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
            s.bind( ( LOCAL_IP, LOCAL_PORT ) )
            s.settimeout( TIMEOUT )
            s.connect( ( server, port ) )
            s.send( request )
            # Receive responses from server
            response_1 = s_receive(s)
            response_2 = s_receive(s)
            s.close()
        except socket.timeout:
            # Timed out sending or receiving data
            return EXIT_CODE_TEST_FAILED_SOCKET_TIMEOUT
        except socket.error, err:
            if err.errno == errno.ECONNREFUSED:
                # Connection refused by server
                return EXIT_CODE_TEST_FAILED_CONN_REFUSED
            else:
                # Other socket related errors
                return EXIT_CODE_TEST_FAILED_SOCKET_ERRORS
        # Decode 2 encoded chunks received
        try:
            response_1_decoded = base64.b64decode(response_1.split("\r\n\r\n")[1])
            response_2_decoded = base64.b64decode(response_2.split("\r\n\r\n")[1])
            # Get mirrored request sent in responses
            mirror_request = response_1_decoded + response_2_decoded
        except TypeError:
            # Errors on b64decoding responses
            return EXIT_CODE_TEST_FAILED_BAD_RESPONSES
        except IndexError:
            # Errors on lists and splits
            return EXIT_CODE_TEST_FAILED_BAD_RESPONSES
        # Compare original request and mirrored request 
        return compare_request_and_mirror( request, mirror_request )
    except Exception:
        # Catch unexpected errors
        return EXIT_CODE_TEST_FAILED_UNKNOWN

if __name__ == "__main__":
    sys.exit( main() )
