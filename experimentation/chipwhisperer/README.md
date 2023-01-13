# SPHINCS+ Fault Attack - ChipWhisperer Experiment

This folder includes all the source code that was used to flash SPHINCS+ on an STM32-F4 so it can be glitched with the ChipWhisperer framework.

## Folder structure

* [`hardware/`](hardware/): SPHINCS+ reference implementation adapted for ARM Cortex-M4, to be used with the ChipWhisperer framework.
* [`logs/`](logs/): Raw experiment results, analyzed in [`../results/`](../results/).
* [`tools/`](tools/): Scripts used to collect the faulty signatures from the ChipWhisperer hardware.