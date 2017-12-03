# ipfixwatch

This tool reads json ouput from Logstash collecting Citrix Netscaler Appflow and combines the
HTTP request and response records into a single output.

Logstash output files must be named in the format \*_json.log
Currently output options are only a custom version of the Apache format:
**srcip - - \[datestr\] httpcmd httpuri httpver httpstatcode size httpreferer httpuseragent dsthost**

Code will run as a systemd service if desired.

Usage:
python watch.py /path/to/logstash/output/