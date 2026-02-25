#!/bin/bash

#Sample bash script to test my program

for i in {1..100}; do
  if (( i % 2 == 0 )); then
    curl http://google.com &
  else
    curl -X POST -d "name=test" http://google.com &
  fi
  sleep 0.5
done
