#!/bin/bash

# get workspace dir
# resolve links - $0 may be a softlink
PRG="$0"

while [ -h "$PRG" ]; do
  ls=`ls -ld "$PRG"`
  link=`expr "$ls" : '.*-> \(.*\)$'`
  if expr "$link" : '/.*' > /dev/null; then
    PRG="$link"
  else
    PRG=`dirname "$PRG"`/"$link"
  fi
done
# Get standard environment variables
PRG=`readlink -e $PRG`
SCRIPTS_DIR=`dirname "$PRG"`
WS_DIR=`dirname "$SCRIPTS_DIR"`

(
cd $WS_DIR
tar czf build/result.tar.gz * --exclude=.git --exclude=build
)
