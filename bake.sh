#!/bin/bash

cd $(dirname $0)

ninja -C ./build "$@"
