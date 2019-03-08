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

rm -rf "$WS_DIR/venv"
if [ ! -d "$WS_DIR/venv" ]; then
        virtualenv --no-site-packages $WS_DIR/venv
        $WS_DIR/venv/bin/pip install -i http://172.16.10.57:8081/simple --trusted-host 172.16.10.57 --upgrade pip==8.1.2-threathunter
        virtualenv --relocatable venv
fi
. $WS_DIR/venv/bin/activate
$WS_DIR/venv/bin/pip install -i http://pypi.douban.com/simple --extra-index-url=http://172.16.10.57:8081/simple --upgrade -r $WS_DIR/requirements.txt
