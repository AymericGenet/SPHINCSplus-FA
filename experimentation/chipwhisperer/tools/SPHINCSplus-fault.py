#!/usr/bin/env python

import random
import datetime
import os

exec(open("Utils.py").read())

RECOMPILE=False
REFLASH=False
CRYPTO_TARGET='SPHINCSplus'
CRYPTO_OPERATION=''
PLATFORM='CW308_STM32F4'

exec(open("SPHINCSplus-setup.py").read())

# Program seed
seed = "Preoccupied with a single leaf, you won't see the tree. Preoccupied with a single tree, you'll miss the entire forest."
random.seed(seed)

# SPHINCS+-256s parameter sets
KEYLEN = 32
PKLEN = 32
MSGLEN = 32
FORSMSGLEN = 39

key = randbytes(KEYLEN) # (function in Utils.ipnyb) # also, unused (it's skseed)
msg = randbytes(MSGLEN)

pkseed = randbytes(MSGLEN)
skseed = randbytes(MSGLEN)
randadrs = randbytes(MSGLEN)

skprf = randbytes(MSGLEN)

forsmsg = randbytes(FORSMSGLEN)

# Resulting root
pkroot = int.to_bytes(0xfc5429b364889d213a26d5a69986560179dac9c6e20d55f424cee9339179dae8, byteorder="big", length=PKLEN)

scope.glitch.clk_src = "clkgen" # set glitch input clock
scope.glitch.output = "glitch_only" # glitch_out = clk ^ glitch
scope.glitch.trigger_src = "manual" # glitch only when scope.glitch.manual_trigger() is called
scope.io.glitch_hp = True
scope.io.glitch_lp = True

scope.glitch.ext_offset = 0
scope.glitch.offset = -4
scope.glitch.width = 20

target.simpleserial_write('t', b'\xff')

target.read()[-2]

#DURATION = int(elapsed_simpleserial(target, 'x', b'\x00'*8))
DURATION = 79
print(DURATION)

elapsed_simpleserial(target, 'c', b'\x00'*32)

SPHINCS_XMSS_HEIGHT = 8

# =============================================================================
# Experiment #2 - Cached branches
# =============================================================================

# API to glitch ('z': sign_cached)
cmd = 'z'
inplength = 2 # to hit layer 7 with addresses of 1 byte
zeropad = 6

# Experiments parameters
N = 10 # 4 days
#M = (2**10) # goal: put faulty in cache + evict + re-query in 3+511.14+256 queries on average
M = 512 # goal: put valid/faulty in cache + evict + re-query in ~318 queries on average
CACHE_SIZE = 171

total_wots = 2**(SPHINCS_XMSS_HEIGHT*(inplength-1))

logged = True

def fill_cache(target, scope, cached, f_log=None):
    now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    log_info(f"{now}: Filling cache ...", f_log=f_log, p=False)
    for adrs in cached:
        filled = False
        inp = 6*b'\x00' + adrs + b'\x00'
        while not filled:
            try:
                elapsed_simpleserial(target, 'q', inp, timeout=1)
                time.sleep(0.005)
                filled = True
            except TimeoutError:
                now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
                log_info(f"{now}: TimeoutError when sending {adrs.hex()}! Resetting ...", f_log=f_log, p=False)
                reset_target(scope)
                target.flush()
    now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    log_info(f"{now}: Cache filled ! [{', '.join([c.hex() for c in cached])}]", f_log=f_log, p=False)

# Open log file
f_log = None
LOG_FOLDER = "log"

if logged:
    logfilename = datetime.datetime.now().strftime(os.path.join(LOG_FOLDER, f"%Y-%m-%d_%H-%M-%S_SPHINCSplus.txt"))
    f_log = open(logfilename, 'w')
    print(f"Opened {logfilename}")
    
try:
    # Start experimentation
    log_info(f"SPHINCSplus (256s, robust) glitch campaign launched", f_log=f_log, p=False)
    log_info(f"N: {N}", f_log=f_log, p=False)
    log_info(f"M: {M}", f_log=f_log, p=False)
    log_info(f"="*80, f_log=f_log, p=False)
    log_info(f"Clock speed: {scope.clock.clkgen_freq}", f_log=f_log, p=False)
    log_info(f"Baud rate: {target.baud}", f_log=f_log, p=False)
    log_info(f"="*80, f_log=f_log, p=False)
    log_info(f"Glitch ext offset: {scope.glitch.ext_offset}", f_log=f_log, p=False)
    log_info(f"Glitch clock offset: {scope.glitch.offset}", f_log=f_log, p=False)
    log_info(f"Glitch width: {scope.glitch.width}", f_log=f_log, p=False)
    log_info(f"Glitch source: {scope.glitch.clk_src}", f_log=f_log, p=False)
    log_info(f"Glitch output: {scope.glitch.output}", f_log=f_log, p=False)
    log_info(f"Glitch trigger source: {scope.glitch.trigger_src}", f_log=f_log, p=False)
    log_info(f"="*80, f_log=f_log, p=False)
    
    ### LAUNCH CAMPAIGN (cached) ###
    for idx in range(N):
        # Preamble
        now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        log_info(f"{now} ({idx+1:02d}/{N:02d}) Launching experiment", f_log=f_log, p=False)
        
        # Set up initial cache
        reset_target(scope)
        target.flush()
        cached = []
        #cached = [int.to_bytes(s, byteorder='big', length=inplength-1) for s in random.sample(range(total_wots), CACHE_SIZE)]
        #cache_idx = 0
        #fill_cache(target, scope, cached, f_log=f_log)

        collections = {}

        # Program secret seed
        #simpleserial_logsend(target, 'k', skseed, preamble=f"({idx+1:02d}/{N:02d})", f_log=f_log, p=False)

        # LAUNCH GLITCHES
        for i in range(M, desc='Queries'):
            # Resets target
            #reset_target(scope)
            target.flush()
            f_log.flush()

            inp = b"\x00"*zeropad + randbytes(inplength)
            
            # Address of the W-OTS is the last 8 bits of the tree address
            address = (int.from_bytes(inp, byteorder='big') >> SPHINCS_XMSS_HEIGHT) & (2**SPHINCS_XMSS_HEIGHT - 1)
            
            now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
            log_info(f"{now}: [{i+1:04d}/{M}] Sending  ... {inp.hex()}, waiting {DURATION*(i/M)} sec ...", f_log=f_log, p=False)

            # 1. Send command
            target.simpleserial_write(cmd, inp)
            
            # 2. Update internal cache
            predicted = True
            if not inp[-2:-1] in cached:
                predicted = False
                if len(cached) < CACHE_SIZE:
                    cached += [inp[-2:-1]]
                else:
                    cached = cached[1:] + [inp[-2:-1]]
                #cached[cache_idx] = inp[-2:-1]
                #cache_idx = ((cache_idx + 1) % CACHE_SIZE)

            # 3. Quick read of returned value (in case cached)
            time.sleep(0.005)
            val = target.read()
            if len(val) >= 4:
                now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
                log_info(f"{now}: [{i+1:04d}/{M}] CACHE HIT (STATUS={val[-2]}, HIT PREDICTION={predicted})!", f_log=f_log, p=False)
                if not predicted: # Should be True, if not => refill cache
                    log_info(f"{now}: [{i+1:04d}/{M}] Cache mismatch, resetting ...", f_log=f_log, p=False)
                    reset_target(scope)
                    target.flush()
                    fill_cache(target, scope, cached, f_log=f_log)
                continue
            else:
                now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
                log_info(f"{now}: [{i+1:04d}/{M}] CACHE MISS (HIT PREDICTION={predicted})!", f_log=f_log, p=False)
                if predicted: # Should be False, if not => refill cache
                    log_info(f"{now}: [{i+1:04d}/{M}] Cache mismatch, resetting ...", f_log=f_log, p=False)
                    reset_target(scope)
                    target.flush()
                    fill_cache(target, scope, cached, f_log=f_log)
                    continue
                    

            # 4. Wait a few seconds
            time.sleep(DURATION*(i/(M+1)))

            # 5. Send glitch
            scope.glitch.manual_trigger()
            
            # 6. Wait remaining time
            time.sleep(DURATION*(1-(i/(M+1))) + 0.5)
            
            # 7. Check if anything is wrong
            ret = scope.capture()

            if ret:
                now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
                log_info(f"{now}: [{i+1:04d}/{M}] TIMED OUT!", f_log=f_log, p=False)
                reset_target(scope)
                target.flush()
                fill_cache(target, scope, cached, f_log=f_log)
            else:
                sig = read_sig(target, 67+8)

                now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
                if sig:
                    log_info(f"{now}: [{i+1:04d}/{M}] Received ... {' '.join([s.hex() for s in sig])}", f_log=f_log, p=False)
                    if address in collections:
                        collections[address] += [sig]
                    else:
                        collections[address] = [sig]
                else:
                    log_info(f"{now}: [{i+1:04d}/{M}] Received ... Nothing!", f_log=f_log, p=False)
                    reset_target(scope)
                    target.flush()
                    fill_cache(target, scope, cached, f_log=f_log)

        # Log findings
        now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        log_info(f"{now} ({idx+1:05d}/{N:05d}) Finished acquisition\n", f_log=f_log, p=False)

finally:
    if f_log:
        print(f"Closing {logfilename}...")
        f_log.close()
    #if target:
        #print(f"Closing target")
        #target.dis()
    #if scope:
        #print(f"Closing scope")
        #scope.dis()

# =============================================================================
# Experiment #1 - Cached layers
# =============================================================================

# Open log file
f_log = None
LOG_FOLDER = "log"

if logged:
    logfilename = datetime.datetime.now().strftime(os.path.join(LOG_FOLDER, f"%Y-%m-%d_%H-%M-%S_SPHINCSplus.txt"))
    f_log = open(logfilename, 'w')
    print(f"Opened {logfilename}")
    
try:    
    # Start experimentation
    log_info(f"SPHINCSplus (256s, robust) glitch campaign launched", f_log=f_log, p=False)
    log_info(f"N: {N}", f_log=f_log, p=False)
    log_info(f"M: {M}", f_log=f_log, p=False)
    log_info(f"="*80, f_log=f_log, p=False)
    log_info(f"Clock speed: {scope.clock.clkgen_freq}", f_log=f_log, p=False)
    log_info(f"Baud rate: {target.baud}", f_log=f_log, p=False)
    log_info(f"="*80, f_log=f_log, p=False)
    log_info(f"Glitch ext offset: {scope.glitch.ext_offset}", f_log=f_log, p=False)
    log_info(f"Glitch clock offset: {scope.glitch.offset}", f_log=f_log, p=False)
    log_info(f"Glitch width: {scope.glitch.width}", f_log=f_log, p=False)
    log_info(f"Glitch source: {scope.glitch.clk_src}", f_log=f_log, p=False)
    log_info(f"Glitch output: {scope.glitch.output}", f_log=f_log, p=False)
    log_info(f"Glitch trigger source: {scope.glitch.trigger_src}", f_log=f_log, p=False)
    log_info(f"="*80, f_log=f_log, p=False)

    ### LAUNCH CAMPAIGN (straight) ###
    for idx in range(N):
        # Preamble
        now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        log_info(f"{now} ({idx+1:02d}/{N:02d}) Launching experiment", f_log=f_log, p=False)

        collections = {}

        # Program secret seed
        #simpleserial_logsend(target, 'k', skseed, preamble=f"({idx+1:02d}/{N:02d})", f_log=f_log, p=False)

        # LAUNCH GLITCHES
        for i in range(M, desc='Queries'):
            # Resets target
            reset_target(scope)
            target.flush()
            f_log.flush()

            inp = b"\x00"*zeropad + randbytes(inplength)
            
            # Address of the W-OTS is the last 8 bits of the tree address
            address = (int.from_bytes(inp, byteorder='big') >> SPHINCS_XMSS_HEIGHT) & (2**SPHINCS_XMSS_HEIGHT - 1)
            
            now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
            log_info(f"{now}: [{i+1:04d}/{M}] Sending  ... {inp.hex()}, waiting {DURATION*(i/M)} sec ...", f_log=f_log, p=False)

            # 1. Send command
            target.simpleserial_write(cmd, inp)

            # 2. Wait a few seconds
            time.sleep(0.005 + DURATION*(i/(M+1)))

            # 3. Send glitch
            scope.glitch.manual_trigger()
            
            # 4. Wait remaining time
            time.sleep(DURATION*(1-(i/(M+1))) + 0.5)
            
            # 5. Check if anything is wrong
            ret = scope.capture()

            if ret:
                now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
                log_info(f"{now}: [{i+1:04d}/{M}] TIMED OUT!", f_log=f_log, p=False)
                reset_target(scope)
                target.flush()
            else:
                sig = read_sig(target, 67+8)

                now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
                if sig:
                    log_info(f"{now}: [{i+1:04d}/{M}] Received ... {' '.join([s.hex() for s in sig])}", f_log=f_log, p=False)
                    if address in collections:
                        collections[address] += [sig]
                    else:
                        collections[address] = [sig]
                else:
                    log_info(f"{now}: [{i+1:04d}/{M}] Received ... Nothing!", f_log=f_log, p=False)

        # Log findings
        now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        log_info(f"{now} ({idx+1:05d}/{N:05d}) Finished acquisition\n", f_log=f_log, p=False)

finally:
    if f_log:
        print(f"Closing {logfilename}...")
        f_log.close()
    #if target:
        #print(f"Closing target")
        #target.dis()
    #if scope:
        #print(f"Closing scope")
        #scope.dis()

# =============================================================================
# Experimental exploration 
# =============================================================================

collections = {'valid': [], 'faulty': [], 'reset': []}
inp = b"\x00"*32
exp_out = "3041f79cafb13ac4d419c3fe7f0a8dc9862833783a0b715ed88490509f2bb0bd"
TIMES = 1000

# Open log file
f_log = None
LOG_FOLDER = "log"

if logged:
    logfilename = datetime.datetime.now().strftime(os.path.join(LOG_FOLDER, f"%Y-%m-%d_%H-%M-%S_SPHINCSplus.txt"))
    f_log = open(logfilename, 'w')
    print(f"Opened {logfilename} !")

try:
    reset_target(scope)
    target.flush()
    # lext=7995 =~ 1 [ms]
    for lext in range(100, 2500, 100):
        scope.glitch.ext_offset = lext

        # Useless for voltage glitching
        for loff in range(-4, -4+1, 1):
            scope.glitch.offset = loff

            # Almost always INVALID after 23
            for lwid in range(18, 23, 1):
                scope.glitch.width = lwid

                for i in range(TIMES):
                    if scope.adc.state:
                        collections['reset'] += [(lext, loff, lwid)]
                        reset_target(scope)
                        target.flush()
                    now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
                    log_info(f"{now} lext={lext}, loff={loff}, lwid={lwid}: [{i+1:04d}/{TIMES}]", end=' ', f_log=f_log, p=False)

                    scope.arm()

                    target.simpleserial_write('a', inp)

                    ret = scope.capture()

                    val = target.simpleserial_read_witherrors('r', 32, glitch_timeout=10)

                    if ret:
                        log_info(f"TIMED OUT!", f_log=f_log, p=False)
                        collections['reset'] += [(lext, loff, lwid)]
                        reset_target(scope)
                        target.flush()
                    else:
                        if val['valid'] is False:
                            log_info(f"INVALID!", f_log=f_log, p=False)
                            collections['reset'] += [(lext, loff, lwid)]
                            reset_target(scope)
                            target.flush()
                        else:
                            if val['payload']:
                                payload = val['payload'].hex()
                                if payload == exp_out:
                                    collections['valid'] += [(lext, loff, lwid)]
                                    log_info(f"{payload} VALID", f_log=f_log, p=False)
                                else:
                                    collections['faulty'] += [(lext, loff, lwid)]
                                    log_info(f"{payload} FAULTY", f_log=f_log, p=False)
                            else:
                                collections['reset'] += [(lext, loff, lwid)]
                                print(f"Nothing...")
finally:
    if f_log:
        print(f"Closing {logfilename}...")
        f_log.close()