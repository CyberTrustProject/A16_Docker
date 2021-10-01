#!/bin/bash
interface=$(cat a16config.ini | grep -oP '(?<=INTERFACE = )[^ ]*')
timeout -s SIGKILL 10s tcpdump -i $interface -l -n  | grep -oE "(([0-9]{1,3}[\.]){3}[0-9]{1,3}[.\])[0-9]{1,5} > (([0-9]{1,3}[\.]){3}[0-9]{1,3}[.\])[0-9]{1,5}"
