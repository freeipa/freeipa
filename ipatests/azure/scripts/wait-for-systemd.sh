#!/bin/bash -eux

for i in $(seq 35)
do
   systemctl is-active --quiet default.target && exit 0
   sleep 5
done

exit 1
