#!/usr/bin/env python3

import time
import random
import datetime
import os

from cwsetup import chipwhisperersetup, reset_target, randbytes, read_sig, log_info

# =============================================================================
# Constants and variables
# =============================================================================
# Log in a file and on console
LOG_BY_DEFAULT = False
LOG_FOLDER = "../logs"
PRINT_BY_DEFAULT = True

# Default constants
"""
    Make sure you compile it yourself by running the following command in the
    'simpleserial-sphincsplus' folder of YOUR ChipWhisperer folder (i.e., after
    copying the content of the 'chipwhisper' folder of THIS repository):

        make PLATFORM=CW308_STM32F4 CRYPTO_TARGET=SPHINCSplus
"""
#RECOMPILE = False
REFLASH = False

# Program seed
seed = "Preoccupied with a single leaf, you won't see the tree. Preoccupied with a single tree, you'll miss the entire forest."
random.seed(seed)

# SPHINCS+-256s parameter sets
SPHINCS_TOTAL_LAYERS = 8 # Number of layers
SPHINCS_XMSS_HEIGHT = 8  # Height of an XMSS tree
KEYLEN = 32     # Bytelength of a secret key
PKLEN = 32      # Bytelength of a public key
MSGLEN = 32     # Bytelength of the hash function
FORSMSGLEN = 39 # Bytelength of a digest

key = randbytes(KEYLEN) # Note: unused (it's skseed)
msg = randbytes(MSGLEN)

# SPHINCS+-256s key pair

# IMPORTANT NOTE: Since I wanted to have the fastest code possible (and also,
# since I'm lazy), I pre-programmed the following values directly in the file
# 'simpleserial-sphincsplus.c' rather than sending them with the command 'k'.
#
# CHANGING THESE VALUES WILL THEREFORE *NOT* HAVE AN EFFECT ON THE EXPERIMENTS!

pkseed = randbytes(MSGLEN)
skseed = randbytes(MSGLEN)
randadrs = randbytes(MSGLEN)
skprf = randbytes(MSGLEN)

forsmsg = randbytes(FORSMSGLEN) # Note: unused (from an unreported experiment)

# Resulting root (obtained from an independent execution of SPHINCSplus.py with above skseed, skprf, pkseed)
pkroot = int.to_bytes(0xfc5429b364889d213a26d5a69986560179dac9c6e20d55f424cee9339179dae8, byteorder="big", length=PKLEN)

# =============================================================================
# Open and configure ChipWhisperer
# =============================================================================

# Path to SPHINCSplus compiled code
fw_folder = ""
if REFLASH:
    fw_folder = input("Please enter path to 'simpleserial-sphincsplus' folder: ")
    if not fw_folder:
        print("Warning: no firmware path detected, skipping relfashing.")

# Connects to chipwhisperer and reflash if fw_folder is provided
print(f"Opening simpleserial-sphincsplus...")
(target, scope) = chipwhisperersetup(fw_folder)

# Increase clock frequency
# STM32F4:
#   see stm32f4_hal.c
# STM32F3:
#   see: https://forum.newae.com/t/cw1173-errortarget-did-not-ack/1757 (clk + baud)
#   see: https://forum.newae.com/t/stm32f3-clock-frequency-setup/1835/2 (wait_states)
scope.clock.clkgen_freq = 8E6 # Fixed at 8 [MHz]
target.baud = 101050
reset_target(scope)

time.sleep(0.05)
print(f"Reading target: {target.read()}")

# Glitch parameters
scope.glitch.clk_src = "clkgen" # set glitch input clock
scope.glitch.output = "glitch_only" # glitch_out = clk ^ glitch
scope.glitch.trigger_src = "manual" # glitch only when scope.glitch.manual_trigger() is called
scope.io.glitch_hp = True
scope.io.glitch_lp = True

# Found with experimental exploration (see bottom)
scope.glitch.ext_offset = 0
scope.glitch.offset = -4
scope.glitch.width = 20

#DURATION = int(elapsed_simpleserial(target, 'x', b'\x00'*8))
DURATION = 79

# =============================================================================
# Experiment #2 - Cached branches
# =============================================================================

def fill_cache(target, scope, cached, f_log=None):
    """
    Fill the cache in the target device to match with local state of the cache.

    @input target  ChipWhisperer's target (target = cw.target(scope))
    @input scope   Chipwhisperer's scope (scope = cw.scope())
    @input cached  Local state of the cache
    @input f_log   Log file
    """
    cmd = 'q' # API to cache ('q': fill_cache)
    now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    log_info(f"{now}: Filling cache ...", f_log=f_log, p=PRINT_BY_DEFAULT)
    for adrs in cached:
        filled = False
        inp = 6*b'\x00' + adrs + b'\x00'
        while not filled: # Will try until the address is cached
            try:
                elapsed_simpleserial(target, cmd, inp, timeout=1)
                time.sleep(0.005)
                filled = True
            except TimeoutError:
                now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
                log_info(f"{now}: TimeoutError when sending {adrs.hex()}! Resetting ...", f_log=f_log, p=PRINT_BY_DEFAULT)
                reset_target(scope) # Should have ideally found a way to restart from the beginning, but it always failed at the first address, so it was fine
                target.flush()
    now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    log_info(f"{now}: Cache filled ! [{', '.join([c.hex() for c in cached])}]", f_log=f_log, p=PRINT_BY_DEFAULT)

def run_exp2(target, scope, inplength, N, M, CACHE_SIZE, logged=False):
    """
    Run the second experiment reported in paper.

    @input target      ChipWhisperer's target (target = cw.target(scope))
    @input scope       Chipwhisperer's scope (scope = cw.scope())
    @input inplength   Bytelength of addresses sent to target
    @input N           Number of different experiments
    @input M           Number of signatures in an experiment
    @input CACHE_SIZE  Size of the cache
    @input logged      Log the results if True
    """
    # Pre-requisites
    cmd = 'z' # API to glitch ('z': sign_cached)
    zeropad = SPHINCS_TOTAL_LAYERS - inplength
    total_wots = 2**(SPHINCS_XMSS_HEIGHT*(inplength-1))

    # Open log file
    f_log = None
    if logged:
        logfilename = datetime.datetime.now().strftime(os.path.join(LOG_FOLDER, f"%Y-%m-%d_%H-%M-%S_SPHINCSplus.txt"))
        f_log = open(logfilename, 'w')
        print(f"Opened {logfilename}")

    try:
        # Start experimentation
        log_info(f"SPHINCSplus (256s, robust) glitch campaign launched", f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"N: {N}", f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"M: {M}", f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"="*80, f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"Clock speed: {scope.clock.clkgen_freq}", f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"Baud rate: {target.baud}", f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"="*80, f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"Glitch ext offset: {scope.glitch.ext_offset}", f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"Glitch clock offset: {scope.glitch.offset}", f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"Glitch width: {scope.glitch.width}", f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"Glitch source: {scope.glitch.clk_src}", f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"Glitch output: {scope.glitch.output}", f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"Glitch trigger source: {scope.glitch.trigger_src}", f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"="*80, f_log=f_log, p=PRINT_BY_DEFAULT)
        
        ### LAUNCH CAMPAIGN (cached) ###
        for idx in range(N):
            # Preamble
            now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
            log_info(f"{now} ({idx+1:02d}/{N:02d}) Launching experiment", f_log=f_log, p=PRINT_BY_DEFAULT)
            
            # Set up initial cache
            reset_target(scope)
            target.flush()
            cached = []
            #cached = [int.to_bytes(s, byteorder='big', length=inplength-1) for s in random.sample(range(total_wots), CACHE_SIZE)]
            #cache_idx = 0
            #fill_cache(target, scope, cached, f_log=f_log)

            collections = {}

            # Program secret seed
            #simpleserial_logsend(target, 'k', skseed, preamble=f"({idx+1:02d}/{N:02d})", f_log=f_log, p=PRINT_BY_DEFAULT)

            # LAUNCH GLITCHES
            for i in range(M):
                # Resets target
                #reset_target(scope)
                target.flush()
                if f_log:
                    f_log.flush()

                inp = b"\x00"*zeropad + randbytes(inplength)
                
                # Address of the W-OTS is the last 8 bits of the tree address
                address = (int.from_bytes(inp, byteorder='big') >> SPHINCS_XMSS_HEIGHT) & (2**SPHINCS_XMSS_HEIGHT - 1)
                
                now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
                log_info(f"{now}: [{i+1:04d}/{M}] Sending  ... {inp.hex()}, waiting {DURATION*(i/M)} sec ...", f_log=f_log, p=PRINT_BY_DEFAULT)

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
                    log_info(f"{now}: [{i+1:04d}/{M}] CACHE HIT (STATUS={val[-2]}, HIT PREDICTION={predicted})!", f_log=f_log, p=PRINT_BY_DEFAULT)
                    if not predicted: # Should be True, if not => refill cache
                        log_info(f"{now}: [{i+1:04d}/{M}] Cache mismatch, resetting ...", f_log=f_log, p=PRINT_BY_DEFAULT)
                        reset_target(scope)
                        target.flush()
                        fill_cache(target, scope, cached, f_log=f_log)
                    continue
                else:
                    now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
                    log_info(f"{now}: [{i+1:04d}/{M}] CACHE MISS (HIT PREDICTION={predicted})!", f_log=f_log, p=PRINT_BY_DEFAULT)
                    if predicted: # Should be False, if not => refill cache
                        log_info(f"{now}: [{i+1:04d}/{M}] Cache mismatch, resetting ...", f_log=f_log, p=PRINT_BY_DEFAULT)
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

                if ret: # In case of time out => refill cache
                    now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
                    log_info(f"{now}: [{i+1:04d}/{M}] TIMED OUT!", f_log=f_log, p=PRINT_BY_DEFAULT)
                    reset_target(scope)
                    target.flush()
                    fill_cache(target, scope, cached, f_log=f_log)
                else:
                    # 8. Read signature
                    sig = read_sig(target, 67+8)

                    now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
                    if sig: # Collect signature
                        log_info(f"{now}: [{i+1:04d}/{M}] Received ... {' '.join([s.hex() for s in sig])}", f_log=f_log, p=PRINT_BY_DEFAULT)
                        if address in collections:
                            collections[address] += [sig]
                        else:
                            collections[address] = [sig]
                    else: # In case nothing is received => refill cache
                        log_info(f"{now}: [{i+1:04d}/{M}] Received ... Nothing!", f_log=f_log, p=PRINT_BY_DEFAULT)
                        reset_target(scope)
                        target.flush()
                        fill_cache(target, scope, cached, f_log=f_log)

            # Log findings
            now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
            log_info(f"{now} ({idx+1:05d}/{N:05d}) Finished acquisition\n", f_log=f_log, p=PRINT_BY_DEFAULT)

    finally:
        if f_log:
            print(f"Closing {logfilename}...")
            f_log.close()

# =============================================================================
# Experiment #1 - Cached layers
# =============================================================================

def run_exp1(target, scope, inplength, N, M, logged=False):
    """
    Run the first experiment reported in paper.

    @input target      ChipWhisperer's target (target = cw.target(scope))
    @input scope       Chipwhisperer's scope (scope = cw.scope())
    @input inplength   Bytelength of addresses sent to target
    @input N           Number of different experiments
    @input M           Number of signatures in an experiment
    @input logged      Log the results if True
    """
    # Pre-requisites
    cmd = 'x' # API to glitch ('x': sign_straight)
    zeropad = SPHINCS_TOTAL_LAYERS - inplength
    total_wots = 2**(SPHINCS_XMSS_HEIGHT*(inplength-1))

    # Open log file
    f_log = None
    if logged:
        logfilename = datetime.datetime.now().strftime(os.path.join(LOG_FOLDER, f"%Y-%m-%d_%H-%M-%S_SPHINCSplus.txt"))
        f_log = open(logfilename, 'w')
        print(f"Opened {logfilename}")
        
    try:
        # Start experimentation
        log_info(f"SPHINCSplus (256s, robust) glitch campaign launched", f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"N: {N}", f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"M: {M}", f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"="*80, f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"Clock speed: {scope.clock.clkgen_freq}", f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"Baud rate: {target.baud}", f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"="*80, f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"Glitch ext offset: {scope.glitch.ext_offset}", f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"Glitch clock offset: {scope.glitch.offset}", f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"Glitch width: {scope.glitch.width}", f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"Glitch source: {scope.glitch.clk_src}", f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"Glitch output: {scope.glitch.output}", f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"Glitch trigger source: {scope.glitch.trigger_src}", f_log=f_log, p=PRINT_BY_DEFAULT)
        log_info(f"="*80, f_log=f_log, p=PRINT_BY_DEFAULT)

        ### LAUNCH CAMPAIGN (straight) ###
        for idx in range(N):
            # Preamble
            now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
            log_info(f"{now} ({idx+1:02d}/{N:02d}) Launching experiment", f_log=f_log, p=PRINT_BY_DEFAULT)

            collections = {}

            # Program secret seed
            #simpleserial_logsend(target, 'k', skseed, preamble=f"({idx+1:02d}/{N:02d})", f_log=f_log, p=PRINT_BY_DEFAULT)

            # LAUNCH GLITCHES
            for i in range(M):
                # Resets target
                reset_target(scope)
                target.flush()
                if f_log:
                    f_log.flush()

                inp = b"\x00"*zeropad + randbytes(inplength)
                
                # Address of the W-OTS is the last 8 bits of the tree address
                address = (int.from_bytes(inp, byteorder='big') >> SPHINCS_XMSS_HEIGHT) & (2**SPHINCS_XMSS_HEIGHT - 1)
                
                now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
                log_info(f"{now}: [{i+1:04d}/{M}] Sending  ... {inp.hex()}, waiting {DURATION*(i/M)} sec ...", f_log=f_log, p=PRINT_BY_DEFAULT)

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

                if ret: # In case of time out
                    now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
                    log_info(f"{now}: [{i+1:04d}/{M}] TIMED OUT!", f_log=f_log, p=PRINT_BY_DEFAULT)
                    reset_target(scope)
                    target.flush()
                else:
                    # 6. Read signature
                    sig = read_sig(target, 67+8)

                    now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
                    if sig: # Collect signature
                        log_info(f"{now}: [{i+1:04d}/{M}] Received ... {' '.join([s.hex() for s in sig])}", f_log=f_log, p=PRINT_BY_DEFAULT)
                        if address in collections:
                            collections[address] += [sig]
                        else:
                            collections[address] = [sig]
                    else: # In case nothing is received
                        log_info(f"{now}: [{i+1:04d}/{M}] Received ... Nothing!", f_log=f_log, p=PRINT_BY_DEFAULT)

            # Log findings
            now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
            log_info(f"{now} ({idx+1:05d}/{N:05d}) Finished acquisition\n", f_log=f_log, p=PRINT_BY_DEFAULT)

    finally:
        if f_log:
            print(f"Closing {logfilename}...")
            f_log.close()

# =============================================================================
# Experimental exploration
# =============================================================================

def run_exp_expl(logged=False):
    """
    Run an experiment that explores the glitches parameters to select the best
    ones.

    @input logged      Log the results if True
    """
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
                        log_info(f"{now} lext={lext}, loff={loff}, lwid={lwid}: [{i+1:04d}/{TIMES}]", end=' ', f_log=f_log, p=PRINT_BY_DEFAULT)

                        # Run glitch campaign
                        scope.arm()
                        target.simpleserial_write('a', inp)
                        ret = scope.capture()
                        val = target.simpleserial_read_witherrors('r', 32, glitch_timeout=10)

                        if ret:
                            log_info(f"TIMED OUT!", f_log=f_log, p=PRINT_BY_DEFAULT)
                            collections['reset'] += [(lext, loff, lwid)]
                            reset_target(scope)
                            target.flush()
                        else:
                            if val['valid'] is False:
                                log_info(f"INVALID!", f_log=f_log, p=PRINT_BY_DEFAULT)
                                collections['reset'] += [(lext, loff, lwid)]
                                reset_target(scope)
                                target.flush()
                            else:
                                if val['payload']:
                                    payload = val['payload'].hex()
                                    if payload == exp_out:
                                        collections['valid'] += [(lext, loff, lwid)]
                                        log_info(f"{payload} VALID", f_log=f_log, p=PRINT_BY_DEFAULT)
                                    else:
                                        collections['faulty'] += [(lext, loff, lwid)]
                                        log_info(f"{payload} FAULTY", f_log=f_log, p=PRINT_BY_DEFAULT)
                                else:
                                    collections['reset'] += [(lext, loff, lwid)]
                                    print(f"Nothing...")
    finally:
        if f_log:
            print(f"Closing {logfilename}...")
            f_log.close()

# =============================================================================
# Experiments execution
# =============================================================================

try:
    # Run experiment 2 (~4 days)
    run_exp2(target, scope, inplength=2, N=10, M=512, CACHE_SIZE=171, logged=LOG_BY_DEFAULT)

    # Run experiment 1 (~5 days)
    run_exp1(target, scope, inplength=3, N=5, M=1024, logged=LOG_BY_DEFAULT)

    #run_exp_expl(logged=LOG_BY_DEFAULT)

finally:
    target.dis()
    scope.dis()