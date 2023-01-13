#!/usr/bin/env python
def str2bytes(x, enc='latin-1'): return bytes(x, enc)

import random
def randbytes(n):
    return int.to_bytes(random.randint(0, 2**(n*8)-1), byteorder="big", length=n)

import time

def simpleserial(target, cmd, payload, verbose=False, delay=0.05, timeout=1):
    target.simpleserial_write(cmd, payload)
    start = time.time()
    time.sleep(delay)
    while target.in_waiting() == 0:
        time.sleep(delay)
        if time.time() - start > timeout:
            break
    
    time.sleep(delay)
    out = target.read(timeout=timeout)
    if verbose: print(f"'{cmd}' response (len={len(out)}): {str2bytes(out).hex() if len(out) > 0 else '-'}")
    
    return str2bytes(out)

def elapsed_simpleserial(target, cmd, x, timeout=300):
    target.simpleserial_write(cmd, x)
    start = time.time()
    num_char = target.in_waiting()
    while num_char == 0:
        num_char = target.in_waiting()
        end = time.time()
        if end - start > timeout:
            raise TimeoutError
    end = time.time()
    return end - start

def log_info(info, f_log=None, end="\n", p=True):
    """
    Log information both on stdout and in logfile.

    @input info  The information to log (String)
    @input f_log Logfile handler to write in
    @input end   End character (as with print)
    """
    if p:
        print(info, end=end)
    if f_log:
        f_log.write(info + end)

import datetime

def simpleserial_logsend(target, cmd, payload, timeout=10, delay=0.05, preamble="", f_log=None, p=True):
    """
    Send command with payload to target and log sending/receiving.

    @input target   ChipWhisperer's target
    @input cmd      Command to send (single ascii)
    @input payload  Command's payload
    @input timeout  Timeout before exiting the while loop
    @input delay    Sleep duration before reading (in seconds)
    @input preamble Short string to logged things
    @input f_log    Logfile handler to write in
    @output out     Board's response
    """
    # Log sending
    now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    log_info(f"{now} {preamble}\tsending \'{cmd}\'... {payload.hex()} (len={len(payload)})", f_log=f_log, p=p)

    # Send command and receive response
    out = simpleserial(target, cmd, payload, timeout=timeout, delay=delay)

    # Log receiving
    now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    log_info(f"{now} {preamble}\treceiving ... {out.hex()} (len={len(out)})", f_log=f_log, p=p)

    # Clear buffer (if any)
    target.flush()

    return out

def fileread_bytes(filepath, expected_len):
    """
    Read entire file in bytes and return content.

    @input filepath     Path to file
    @input expected_len Expected number of bytes to read (sanity check)
    @output content     Entire file content
    """
    assert os.path.isfile(filepath), f"File does not exist: {filepath}"
    with open(filepath, "rb") as f:
        content = f.read()
    assert len(content) == expected_len, f"Unexpected number of bytes read in {filepath}: {len(content)} != {expected_len}"
    return content

from PythonLibraries.EtherLib import EtherInstrument

class Lecroy(EtherInstrument):
    '''
    Generic class for Lecroy oscilloscop
    '''

    def __init__(self, address="10.0.236.128"):
        '''
        Constructor
        '''
        super(Lecroy, self).__init__(host=address)
    
    def capture(self, chan='C1'):
        '''
        Capture trace from specified channel.
        '''
        return self.ask(chan + ':WAVEFORM? ALL')

def connect2lecroy(host='10.0.236.157'): return Lecroy(host)