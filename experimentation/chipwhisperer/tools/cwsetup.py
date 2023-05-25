import random
import time
import chipwhisperer as cw
import os

# Default options
CRYPTO_TARGET='SPHINCSplus'
PLATFORM='CW308_STM32F4'

def chipwhisperersetup(fw_folder="", CRYPTO_TARGET=CRYPTO_TARGET, SCOPETYPE='OPENADC', PLATFORM=PLATFORM):
    """
    Connect to the ChipWhisperer and flash the simpleserial-sphincsplus firmware
    if provided a firmware path.

    @input fw_folder      Firmware path to simpleserial-sphincsplus folder
                          (if empty, then no flashing will occur)
    @input CRYPTO_TARGET  Should be 'SPHINCSplus'
    @input SCOPETYPE      Should be 'OPENADC'
    @input PLATFORM       Should be 'CW308_STM32F4'
    @output target  ChipWhisperer's target (target = cw.target(scope))
    @output scope   Chipwhisperer's scope (scope = cw.scope())
    """
    # Sanity check to prevent accidental erasure of firmware
    fw_path = ""
    if fw_folder:
        fw_path = os.path.join(fw_folder, f"simpleserial-{CRYPTO_TARGET.lower()}-{PLATFORM}.hex")
        if not os.path.isfile(fw_path):
            raise ValueError(f"""{fw_path} is not an existing file!
    Either you did not provide the correct folder: {fw_folder},
    or you did not compile the firmware with the following command:

        make PLATFORM={PLATFORM} CRYPTO_TARGET={CRYPTO_TARGET}
""")

    # Try to connect to chipwhisperer
    try:
        scope = cw.scope()
        target = cw.target(scope)
    except IOError:
        print("INFO: Caught exception on reconnecting to target - attempting to reconnect to scope first.")
        print("INFO: This is a work-around when USB has died without Python knowing. Ignore errors above this line.")
        scope = cw.scope()
        target = cw.target(scope)

    print("INFO: Found ChipWhisperer😍")

    time.sleep(0.05)
    scope.default_setup()

    # Flash code on card
    if fw_path:
        if "STM" in PLATFORM or PLATFORM == "CWLITEARM" or PLATFORM == "CWNANO":
            prog = cw.programmers.STM32FProgrammer
        elif PLATFORM == "CW303" or PLATFORM == "CWLITEXMEGA":
            prog = cw.programmers.XMEGAProgrammer
        else:
            prog = None
        cw.program_target(scope, prog, fw_path)

    # The maximum number of samples is hardware-dependent: - cwlite: 24400 - cw1200: 96000
    # Note: can be reconfigured afterwards
    if PLATFORM == "CWNANO":
        scope.adc.samples = 800
    else:
        scope.adc.samples = 2000

    # Empty buffer
    target.read()

    return (target, scope)

def reset_target(scope, PLATFORM=PLATFORM):
    """
    Reset the target.

    @input scope     ChipWhisperer's scope (scope = cw.scope())
    @input PLATFORM  Should be 'CW308_STM32F4'
    """
    if PLATFORM == "CW303" or PLATFORM == "CWLITEXMEGA":
        scope.io.pdic = 'low'
        time.sleep(0.05)
        scope.io.pdic = 'high'
        time.sleep(0.05)
    else:
        scope.io.nrst = 'low'
        time.sleep(0.05)
        scope.io.nrst = 'high'
        time.sleep(0.05)

def randbytes(n):
    """
    Generate random bytes of provided byte length.

    @input n  Bytelength
    @output Random bytes of bytelength n
    """
    return int.to_bytes(random.randint(0, 2**(n*8)-1), byteorder="big", length=n)

def read_sig(target, l=75):
    """
    Read from the target a W-OTS+ signature involved in SPHINCS+.

    @input target  ChipWhisperer's target (target = cw.target(scope))
    @input l       Number of elements in a W-OTS+ signature (should be 75)
    @output sig  A W-OTS+ signature in a SPHINCS+ layer
    """
    target.simpleserial_write('r', int.to_bytes(0, byteorder="little", length=2))
    time.sleep(0.01)
    out = target.read()
    if len(out) != 32+4:
        return None
    else:
        sig = [out[:-4].encode('latin-1')]
        for i in range(1,l):
            target.simpleserial_write('r', int.to_bytes(i, byteorder="little", length=2))
            time.sleep(0.01)
            sig += [target.read()[:-4].encode('latin-1')]
    return sig

def log_info(info, f_log=None, end="\n", p=True):
    """
    Log information both on stdout and in logfile.

    @input info   The information to log (String)
    @input f_log  Logfile handler to write in
    @input end    End character (as with print)
    """
    if p:
        print(info, end=end)
    if f_log:
        f_log.write(info + end)