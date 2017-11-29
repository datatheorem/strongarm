#!/bin/bash

case `uname` in
    Darwin)
        # capstone
        brew update
        brew install capstone
        ;;
    Linux)
        apt-get update -qq
        # capstone
        apt-get install libcapstone3 -y
        ;;
    *)
          echo "Unsupported platform: `uname`" >&2
          exit 1
          ;;
esac
