#!/bin/bash

# Command to execute
CMD="/bin/ls"

# Number of times to execute the command
COUNT=100

# Loop to execute the command COUNT times
for i in $(seq 1 $COUNT); do
  $CMD > /dev/null
done

echo "Executed $CMD $COUNT times"
