#!/bin/bash

case `uname` in
    Darwin)
        # capstone
        brew install capstone
        ;;
    Linux)
        # capstone
        apt-get install libcapstone3 -y
        ;;
    *)
          echo "Unsupported platform: `uname`" >&2
          exit 1
          ;;
esac

# Python dependencies
pip install -r requirements.txt --upgrade
