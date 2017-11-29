#!/bin/bash

case `uname` in
    Darwin)
        # capstone
        brew install capstone
        ;;
    Linux)
        # capstone
        sudo apt-get update
        sudo apt-get install libcapstone3 -y
        ;;
    *)
          echo "Unsupported platform: `uname`" >&2
          exit 1
          ;;
esac
