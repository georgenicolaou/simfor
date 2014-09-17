# Nyuki SIMFor - SIM Card Forensics

## Introduction

Nyuki SimFor is is an open source application for Linux systems, designed to 
extract the file contents of a (U)SIM card for forensic investigations. It 
supports direct communication with USB-to-Serial bridge controllers that can be 
purchased at a cheap price. It uses the APDU protocol to communicate with the 
SIM card in order to discover and extract the necessary records.

### Features
* Partial extraction of known (U)SIM files.
* Full (Bruteforce) extraction of all present files (Could take a few hours). This is based on the idea implemented by another successful SIM card forensic tool called simbrush.
* Output to XML file
* Support for automated decoding of SIM card files.

## Dependencies
None

## Compiling and Running
```
make
./SIMFor --help
```

## Known Issues
SIMFor does not play well with pcscd so make sure you disable it before running.

## TODO
* Add definitions for SIM card files
* Decide about "make install"