# SPHINCS+ Fault Attack - Complexity Analysis

This folder regroups the scripts used to derive the various complexity necessary to attack SPHINCS+ with faulty signatures.

## File structure

* [`analysis_caching_branches.py`](analysis_caching_branches.py): Used to derive Table 11, Table 12, and Table 13 in the paper.
* [`analysis_caching_layers.py`](analysis_caching_layers.py): Used to derive Table 9, and Table 10 in the paper.
* [`analysis_fault.py`](analysis_fault.py): Used to derive Table 3 and Table 4 in the paper.
* [`analysis_multifault.py`](analysis_multifault.py): Used to derive Table 6, Table 7, and Table 8 in the paper.
* [`analysis_uf.py`](analysis_uf.py): Used to derive Table 2 in the paper.

The folder [`utils/`](utils/) regroups all the maths formulas.

## Requirements

The code was provided for Python 3.10.4.

See [`requirements.txt`](requirements.txt) for the list of specific list of pip packages.

```pip3 install -r requirements.txt```