#!/bin/bash
#
# clamdchk
# (was botchk from eggdrop 1.6.15)
#
# Modified by Brian Bruns <bruns@2mbit.com for use with clamav
# $Id: botchk,v 1.6 2002/02/27 18:21:46 guppy Exp $
#
# To check clamd every 5 minutes, put the following line in your
# /etc/crontab:
#    */5 * * * *  root /path/to/clamdchk
# And if you don't want to get email from crontab when it starts your bot,
# put the following in your /etc/crontab:
#    */5 * * * *  root /path/to/clamdchk >/dev/null 2>&1
#

pidfile="/var/run/clamd.pid"
socketfile="/var/run/clamd.ctl"

if test -r $pidfile
then
  # there is a pid file -- is it current?
  clamdpid=`cat $pidfile`
  if `kill -CHLD $clamdpid >/dev/null 2>&1`
  then
    exit 0
  fi
  echo ""
  echo "Stale $pidfile file, erasing..."
  rm -f $pidfile
  rm -f $socketfile
  echo ""
  echo "Couldn't find clamd running, restarting clamd..."
  echo ""
    /etc/init.d/clamav-daemon start
    exit 0
else
  echo ""
  echo "Couldn't find clamd running, restarting clamd..."
  echo ""
    rm -f $socketfile
    /etc/init.d/clamav-daemon start
    exit 0

fi

exit 0
