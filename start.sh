#!/bin/bash
echo "npmGrafStats: v3.2.0"
echo "Startup: unified Python log processor"

if [ -z "$INFLUX_TOKEN" ] && [ ! -f "/data/influxdb-token.txt" ]; then
    echo 'No InfluxDB Token as variable or in influxdb-token.txt file found.'
    echo 'Please add the Token. Exiting now.'
    exit 1
fi

exec python -u /home/appuser/.config/NPMGRAF/log_processor.py
