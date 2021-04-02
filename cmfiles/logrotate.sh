#!/bin/sh

WORK_D=$(cd $(dirname $0)/; pwd)
VPP_AGENT_LOG_D=$(cd $WORK_D; cd ../var; pwd)

install() {
echo "$VPP_AGENT_LOG_D/*.log
{
        daily
        rotate 100
	minsize 10M
	dateext
        copytruncate
        missingok
        notifempty
        delaycompress
        compress
        postrotate
        endscript

}" > $WORK_D/vpp-agent.logrotate

mv -f $WORK_D/vpp-agent.logrotate  /etc/logrotate.d/vpp-agent
}

remove() {
	rm -rf /etc/logrotate.d/vpp-agent
}

help() {
	echo "$0 install|remove"
}

if [ "$1" = "install" ]; then
	install
elif [ "$1" = "remove" ]; then
	remove
else
	help
fi
