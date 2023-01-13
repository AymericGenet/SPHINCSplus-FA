# SPHINCS+ Fault Attack

This repository contains the software that accompanies the article *On Protecting SPHINCS+ Against Fault Attacks* published in the 2023 edition of the IACR Transactions on Cryptographic Hardware and Embedded Systems (TCHES), Volume 2.

## Repository structure

* [`attack/`](attack/): The fault attack script (under development...).
* [`evaluation/`](evaluation/): Scripts used to derive the reported results in the paper (incl. the countermeasures analysis).
* [`experimentation/`](experimentation/): Code of the experimental validation reported in the paper.
* [`SPHINCSplus.py`](SPHINCSplus.py): Custom Python implementation of SPHINCS+-SHAKE256.