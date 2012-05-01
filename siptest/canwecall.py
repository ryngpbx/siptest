#! /usr/bin/env python
"""Script to perform test of an "external phone" scenario using PJSUA

Tests, in essence, that an external UA would be able to register,
and then make calls on the target account.

Expects an asterisk server with a dialplan like so::

    exten => 8888,1,NoOp(Echo in Jail)
    exten => 8888,n,Answer()
    exten => 8888,n,Set(TIMEOUT(absolute)=10)
    exten => 8888,n,Echo()
    exten => 8888,n,Hangup()

Formats the destination URL as sip:%(number)s@%(proxy)s;user=phone 

Requires that sox and pjsua be installed on the testing machine...
"""
import sys, os, threading, logging, traceback, tempfile, shutil, subprocess, Queue, socket
import pjsua as pj
log = logging.getLogger( __name__ )
pjsua_log = logging.getLogger( 'pjsua' )

siptest_directory = os.path.dirname( __file__ )
DEFAULT_TEST_FILE = os.path.join( siptest_directory, 'test.wav' )
REGISTER_TIMEOUT = 5

VERBOSITY = [log.error,log.warn,log.info,log.debug]
def _pg_log_cb( level, str, len ):
    func = VERBOSITY[ min((level,len(VERBOSITY))) ]
    pjsua_log( "%s", str )

class AccountCallback(pj.AccountCallback):
    """Handle callbacks related to account registration status"""
    queue = None
    def wait(self, max_wait=REGISTER_TIMEOUT):
        self.queue = Queue.Queue()
        try:
            self.queue.get( True, max_wait )
        except Queue.Empty, err:
            # Our info will report our status as unregistered...
            pass 
    def on_reg_state(self):
        info = self.account.info()
        log.info( "Registration state: %r reason: %s", info.reg_status, info.reg_reason )
        if self.queue:
            if info.reg_status >= 200:
                log.info( 'Complete' )
                self.queue.put( 'Complete' )
                self.queue = None

class CallCallback(pj.CallCallback):
    # Notification when call state has changed
    queue = None
    confirmed = False 
    def __init__( self, call=None, play_handle=None, record_handle=None ):
        pj.CallCallback.__init__( self,call )
        self.play_handle = play_handle
        self.record_handle = record_handle
    def wait(self, max_wait=REGISTER_TIMEOUT):
        self.queue = Queue.Queue()
        try:
            self.queue.get( True, max_wait )
        except Queue.Empty, err:
            # Our info will report our status as unregistered...
            pass 
    def on_state(self):
        info = self.call.info()
        log.info( 'Last Code: %s (%s) -> %s', info.last_code, info.last_reason, info.state_text )
        if info.state_text == 'CONFIRMED':
            # Only notice we get that says "we *should* have audio"
            self.confirmed = True
        if info.last_code > 200 or info.state_text == 'DISCONNCTD':
            log.info( "Call termination detected" )
            try:
                self.call.hangup()
            except pj.Error, err:
                # already hung up...
                pass 
            self.queue.put( 'Finished' )
            self.queue = None
        
    # Notification when call's media state has changed.
    def on_media_state(self):
        global lib
        log.info( 'Call media state: %s', self.call.info().media_state )
        if self.call.info().media_state == pj.MediaState.ACTIVE:
            # Get the incoming call's conference slot
            call_slot = self.call.info().conf_slot
            log.info( 'Active call media slot: %s', call_slot )
            record_slot = lib.recorder_get_slot( self.record_handle )
            play_slot = lib.player_get_slot( self.play_handle )
            # Now connect them all up...
            lib.conf_connect(play_slot,call_slot)
            lib.conf_connect(call_slot,record_slot)

def compare_audio( first, second ):
    """
    
    returns [frequency(first), frequency(second)]
    """
    first_stats,second_stats = stats_output( first), stats_output( second )
    log.info( 'Frequencies: source=%s result=%s', first_stats['rough frequency'], second_stats['rough frequency'] )
    return first_stats,second_stats

def audio_stats( file ):
    """Run sox over file to extract statistics
    
    Cuts a second out of each file and runs sox stat on that 1s slice,
    parses the resulting statistics to floats and returns the float values 
    for each file.
    """
    log.info( 'Analysing %s', file )
    command = [
        'sox',
        file,
        '-n',
        # trim 1 second out of the middle...
        'trim',
        '00:02',
        '00:03',
        # produce frequency statistics on that period
        'stat',
        '-freq',
    ]
    pipe = subprocess.Popen( command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT )
    stdout,_ = pipe.communicate()
    def as_float( x ):
        try:
            return float( x )
        except Exception, err:
            return x
    stat_lines = [
        # Clean up sox' creative formatting...
        (' '.join(key.lower().strip().split()),as_float( value.strip()) )
        for key,value in 
        [ 
            line.split(':',1) for line in stdout.splitlines() 
            if ':' in line
        ]
    ]
    return dict( stat_lines )
def start_pj( ):
    """Start PJSUA library, open a listening port"""
    global lib
    lib = pj.Lib()
    lib.init(
        log_cfg=pj.LogConfig(
            level=0,
            filename='',
            callback=None,
            console_level=0)
    )
    lib.set_null_snd_dev()
    # Choose any open port, rather than restricting to a particular port...
    lib.create_transport(pj.TransportType.UDP)
    lib.start()
    return lib


def register_account( lib, proxy,username, password ):
    """Register on proxy with given username and password"""
    acc = lib.create_account(
        pj.AccountConfig(
            proxy,
            username,
            password)
    )
    acc.reg_timeout = REGISTER_TIMEOUT

    acc_cb = AccountCallback(acc)
    acc.set_callback(acc_cb)
    acc_cb.wait()
    return acc, acc_cb

def make_call( lib, acc, target, play_file, record_file ):
    """Make a call to the given SIP target using account specified"""
    log.info( "Using playback file: %s", play_file )
    log.info( "Recording to file: %s", record_file )
    play_handle = lib.create_player( play_file, loop=True )
    try:
        try:
            record_handle = lib.create_recorder( record_file )
            callback = CallCallback(None,play_handle=play_handle,record_handle=record_handle)
            acc.make_call( target, callback)
            callback.wait()
        finally:
            lib.recorder_destroy( record_handle )
    finally:
        lib.player_destroy( play_handle )
    return callback

def check_proxy( proxy ):
    """Check if the proxy can be resolved"""
    if ':' in proxy: # port was specified...
        proxy = proxy.split( ':' )[0]
    try:
        host = socket.gethostbyname( proxy )
    except Exception, err:
        return False 
    else:
        return host

MAX_FREQUENCY_DELTA = 20 # in Hz
(
    EXIT_CODE_SUCCESS,
    EXIT_CODE_REG_FAILURE,
    EXIT_CODE_UNKNOWN_USER,
    EXIT_CODE_BAD_PASSWORD,
    EXIT_CODE_CONNECT_FAILURE_HOST_BAD,
    EXIT_CODE_CONNECT_FAILURE_HOST_GOOD,
    EXIT_CODE_AUTH_FAILURE,
    EXIT_CODE_FREQUENCY_MISMATCH_FAILURE,
    EXIT_CODE_SILENCE_RECORDED,
) = range( 9 )

def main():
    from optparse import OptionParser, OptionGroup
    global lib
    parser = OptionParser()
    for name, optionset in [
        ('SIP Registration', [
            ('username', 'Username with which to register with proxy', None),
            ('password', 'Password with which to register with proxy', None),
            ('proxy', 'Proxy server (often an IP address, domain name is fine too), port can be specified with :5060 after the server name', None),
        ]),
        ('RTP Audio', [
            ('number', 'Phone Number, if provided, attempt to make a call to this number, should be an Echo() application.  Note: this will be formatted as sip:<number>@<proxy>;user=phone', None),
            ('wav','Wave file to play to the Echo application (frequency analysis of this file should == capture of the call to the Echo application)', DEFAULT_TEST_FILE ),
        ]),
    ]:
        group = OptionGroup( parser, name )
        for (option, description, default) in optionset:
            group.add_option(
                '--%s' % (option),
                dest=option.replace('-', '_'),
                default=default,
                help=description
            )
        parser.add_option_group( group )
    options, args = parser.parse_args()
    lib = start_pj()
    try:
        acc,acc_cb = register_account( lib, options.proxy, options.username, options.password )
        info = acc.info()
        print 'Status=%s (%s)'%(info.reg_status, info.reg_reason )
        if info.reg_status != 200:
            log.error(
                "Unable to register in %s seconds: %s %s", REGISTER_TIMEOUT,
                info.reg_status, info.reg_status,
            )
            if info.reg_status in (404,):
                log.error( "Registration failed due to unknown account/username (Note: your service provider should have reported a 403 error (Forbidden) but reported a 404 error (Unknown) instead, this allows hostile systems to scan for accounts)." )
                returncode = EXIT_CODE_UNKNOWN_USER
            elif info.reg_status in (401,403):
                log.error( "Registration failed due to authorization failure (account/username incorrect)" )
                returncode = EXIT_CODE_BAD_PASSWORD
            elif info.reg_status == 100:
                host = check_proxy( options.proxy )
                if host:
                    # TODO: nmap -sU -p 5060 to see if the UDP port is open|filtered, but that 
                    # requires su access to perform the scan...
                    log.error( 'Registration failed to host: %s (%s)', options.proxy, host )
                    returncode = EXIT_CODE_CONNECT_FAILURE_HOST_GOOD
                else:
                    log.error( "Unable to resolve host: %s", options.proxy )
                    returncode = EXIT_CODE_CONNECT_FAILURE_HOST_BAD
            else:
                returncode = EXIT_CODE_REG_FAILURE
        else:
            if options.number:
                tempdir = tempfile.mkdtemp( 'rec', 'siptest' )
                try:
                    record_file = os.path.join( tempdir, 'recording.wav' )
                    
                    call_callback = make_call( 
                        lib,acc, 'sip:%s@%s;user=phone'%(options.number,options.proxy,),
                        record_file = record_file,
                        play_file = options.wav,
                    )
                    if call_callback.confirmed:
                        first,second = audio_stats( options.wav), audio_stats( record_file )
                        if abs(first['rough frequency'] - second['rough frequency']) > MAX_FREQUENCY_DELTA:
                            if second['maximum amplitude'] == second['minimum amplitude'] == 0.0:
                                log.error(
                                    "Silence recorded, likely the RTP (audio) transport is blocked")
                                returncode = EXIT_CODE_SILENCE_RECORDED
                            else:
                                log.error( 
                                    "Frequencies do not match, possibly redirected to the wrong extension or a server not configured with an Echo() application? %s != %s",
                                    first, second,
                                )
                                returncode = EXIT_CODE_FREQUENCY_MISMATCH_FAILURE
                        else:
                            returncode = EXIT_CODE_SUCCESS
                finally:
                    shutil.rmtree( tempdir, True )
            else:
                returncode = EXIT_CODE_SUCCESS
        acc.delete()
        lib.destroy()
        lib = None
        return returncode

    except Exception, e:
        log.error(
            "Exception: %s", traceback.format_exc(),
        )
        if lib:
            lib.destroy()
        lib = None

if __name__ == "__main__":
    logging.basicConfig( level=logging.DEBUG )
    sys.exit( main() )
