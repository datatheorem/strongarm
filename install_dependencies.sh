#!/bin/bash

case `uname` in
    Darwin)
        # capstone
        brew update
        brew install capstone
        ;;
    Linux)
        add-apt-repository universe
        apt-get update
        # capstone
        apt-get install libcapstone3 -y
        ;;
    *)
          echo "Unsupported platform: `uname`" >&2
          exit 1
          ;;
esac
