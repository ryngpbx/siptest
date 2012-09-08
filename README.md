siptest
=======

Performs a SIP registration and then optionally places a call into an echo
test, plays audio, and verifies that the audio is echoed back clearly. The
result is returned using shell exit codes.

detectsipalg
============

Can be used to detect SIP-ALG packet manipulation, common in many consumer
routers, and often implemented incorrectly.

siptest documentation
=====================

Dependencies:
    sox for audio analysis
    pjsip for SIP registration and dialing

To build pjsip python libraries:

    debian/ubuntu:
        apt-get install build-essential python-dev
        wget http://www.pjsip.org/release/2.0.1/pjproject-2.0.1.tar.bz2
        tar xjf pjproject-2.0.1.tar.bz2
        cd pjproject-2.0.1
        ./configure
        make dep; make
        cd pjsip-apps/src/python
        python setup.py install

Sample usage:

    siptest --username=simon --password=secret --server=sip.example.com
    echo $?
    0

    siptest --username=simon --password=secret --server=sip.example.com \
        --number=8888 --wav=8000hz.wav
    echo $?
    0

Exit codes:
    0 - SUCCESS
    1 - REG_FAILURE
    2 - UNKNOWN_USER
    3 - BAD_PASSWORD
    4 - CONNECT_FAILURE_HOST_BAD
    5 - CONNECT_FAILURE_HOST_GOOD
    6 - AUTH_FAILURE
    7 - FREQUENCY_MISMATCH_FAILURE
    8 - SILENCE_RECORDED

Sample Asterisk dialplan:
    
    [echotest] 
    exten => 8888,1,NoOp(Echo in Jail)
    exten => 8888,n,Answer()
    exten => 8888,n,Set(TIMEOUT(absolute)=10)
    exten => 8888,n,Echo()
    exten => 8888,n,Hangup()

detectsipalg documentation
==========================

Dependencies: 
    A remote SIP ALG test server (see http://dev.sipdoc.net/wiki/sip-stuff/SIP-ALG-Detector)

Example:
    detectsipalg --address=sipalg.example.com
    echo $?
    11
 
Exit codes:
    10 - DETECTED
    11 - NOT_DETECTED
    12 - TEST_FAILED_SOCKET_TIMEOUT
    13 - TEST_FAILED_CONN_REFUSED
    14 - TEST_FAILED_SOCKET_ERRORS
    15 - TEST_FAILED_BAD_RESPONSES
    16 - TEST_FAILED_UNKNOWN
