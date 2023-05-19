# SPHINCS+ Fault Attack

This repository contains the software that accompanies the article ["On Protecting SPHINCS+ Against Fault Attacks"](https://tches.iacr.org/index.php/TCHES/article/view/10278) published in the Volume 2 of the 2023 edition of the *IACR Transactions on Cryptographic Hardware and Embedded Systems* (TCHES). https://tches.iacr.org/index.php/TCHES/article/view/10278, pp. 80-114. ISSN: 2569-2925. DOI: [10.46586/tches.v2023.i2.80-114](https://doi.org/10.46586/tches.v2023.i2.80-114).

## Repository structure

* [`attack/`](attack/): The fault attack script (still under development...).
* [`evaluation/`](evaluation/): Scripts used to derive the reported results in the paper (incl. the countermeasures analysis).
* [`experimentation/`](experimentation/): Code of the experimental validation reported in the paper.
* [`SPHINCSplus.py`](SPHINCSplus.py): Custom Python implementation of SPHINCS+-SHAKE256.

## Requirements

The python SPHINCS+ code was provided for Python 3.10.4.

See [`requirements.txt`](requirements.txt) for the list of specific list of pip packages. Install the requirements with the following command:

```bash
$ pip3 install -r requirements.txt
```

## Theoretical results reproduction

The following commands reproduce the theoretical results reported in the paper:

```bash
$ cd evaluation/
$ pip3 install -r requirements.txt
$ python3 analysis_uf.py # Table 2 (p. 95)
$ python3 analysis_fault.py # Tables 3, 4 (pp. 97-98)
$ python3 analysis_multifault.py # Tables 6, 7, 8 (pp. 99, 101) (careful, long runtime!)
$ python3 analysis_caching_layers.py # Tables 9, 10 (p. 103)
$ python3 analysis_caching_branches.py # Tables 11, 12, 13 (pp. 105-107)
```

## Experimental results reproduction

The following commands reproduce the experimetnal results reported in the paper:

```bash
$ cd experimentation/results/
$ python3 results_exp1.py # Tables 14, 15 (pp. 108-109) (careful, VERY long runtime!)
$ python3 results_exp2.py # Tables 16, 17 (p. 110) (careful, VERY long runtime!)
```

Latest outputs were logged in [`experimentation/chipwhisperer/logs`](experimentation/chipwhisperer/logs).

## Experiment reproduction

### Prerequisites

 * ChipWhisperer 5.6.1 version
 * The ChipWhisperer Level 2 Kit that notably includes
 	- 1x ChipWhisperer-Lite
 	- 1x CW308 UFO board
 	- 1x 20-pin ribbon
 	- 1x SMA cable
 	- 1x CW308 power supply (5.0V)
 	- 1x Micro-USB to USB-A cable
 * An STM32F4 Cortex-M4 target for UFO (NAE-CW308T-STM32F4)

### Setup

We refer to the official ChipWhisperer datasheets to find the mentioned pins:

* CW308 UFO: http://media.newae.com/datasheets/NAE-CW308-datasheet.pdf (visited on: 2023-05-16)
* ChipWhisperer-Lite: https://media.newae.com/datasheets/NAE-CW1173_datasheet.pdf (visited on: 2023-05-16)

The following setup is required to reproduce the experiments:

1. Connect ChipWhisperer-Lite's "Glitch Out" SMA port to CW308 UFO board's "J17" SMA port with SMA cable.
2. Connect ChipWhisperer-Lite's 20-pin port to CW308 UFO board's 20-pin port with the 20-pin ribbon.
3. Plug STM32F4 onto CW308 UFO (as a shield).
4. Plug power supply to CW308 UFO.
5. Connect ChipWhisperer-Lite's micro-USB port to computer with micro-USB cable.

### Reproducing the experiments

1. Install ChipWhisperer: https://chipwhisperer.readthedocs.io/en/latest/ (visited on: 2023-05-16).
2. Copy `experimentation/chipwhisperer` into `chipwhisperer/` installation folder

    **Note**: Some files may appear to be duplicate, especially in `hardware/victims/firmware/hal`. The reason is because the ChipWhisperer 5.6.1 version was not handling the clock frequency of the STM32F4 very well. As a result, the HAL code was modified in order for the STM32F4 to run at the maximum of 180 MHz.

3. In your `chipwhisperer/` installation folder, compile the simpleserial-sphincsplus with the following commands:

    ```bash
    $ cd hardware/victims/firmware/simpleserial-sphincsplus`
    $ make PLATFORM=CW308_STM32F4 CRYPTO_TARGET=SPHINCSplus
    ```

4. Back in the current repository, run the experiments with the following commands:

    ```bash
    $ cd experimentation/chipwhisperer/tools
    $ pip3 install -r requirements.txt
    $ python3 cwfaultexp.py
    ```

    There are a few options in the `cwfaultexp.py` script that you may consider using, namely:

    * `LOG_BY_DEFAULT=True`: Change it to `False` if you do not want the script to populate the `../logs` folder.
    * `REFLASH=False`: Change it to `True` if you want to flash your firmware on your target (the script will prompt the path to the compiled firmware).

    This script was initially meant to run in Jupyter, which you can simulate in a Python REPL by using the following command (after you mute the calls to `run_exp1()` and `run_exp2()`, as well as the `target.dis()` and `scope.dis()` at the end of the file):

    ```In [1]: exec(open("cwfaultexp.py").read())```