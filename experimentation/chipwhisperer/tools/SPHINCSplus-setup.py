#!/usr/bin/env python

try:
    REFLASH
except:
    REFLASH=False
    print(f"Warning: does not reflash by default!")

try:
    CRYPTO_TARGET
except:
    CRYPTO_TARGET='SPHINCSplus'
    print(f"Warning: using default CRYPTO_TARGET {CRYPTO_TARGET}")

try:
    PLATFORM
except:
    PLATFORM='CW308_STM32F4'
    print(f"Warning: using default PLATFORM {PLATFORM}")

try:
    CRYPTO_OPERATION
except:
    CRYPTO_OPERATION=''
    print(f"Warning: using default CRYPTO_OPERATION {CRYPTO_OPERATION}")

exec(open("../Setup_Generic.py").read())

scope.clock.clkgen_freq = 8E6
target.baud = 101050
reset_target(scope)

if REFLASH:
    fw_path = f'{FW_ROOT}/simpleserial-{CRYPTO_TARGET.lower()}-{PLATFORM}.hex'
    cw.program_target(scope, prog, fw_path)

target.read()

def read_sig(target, l=75):
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