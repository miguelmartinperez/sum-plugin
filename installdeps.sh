#!/bin/bash


# Similarity Unrelocated Module
if [ ! "$(ls -A sum)" ]; then
    sudo -u $SUDO_USER git clone --depth 1 --recurse-submodules --shallow-submodules https://github.com/reverseame/similarity-unrelocated-module.git sum
fi

# SUM dependencies
sh sum/installdeps.sh