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
echo "workspace is $WS_DIR"

$WS_DIR/venv/bin/python -m pytest --cov=$WS_DIR/nebula_sniffer --cov-report=term-missing --cov-report=xml --junitxml $WS_DIR/build/junit.xml $WS_DIR/test
mv $WS_DIR/coverage.xml $WS_DIR/build
