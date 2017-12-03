#!/usr/bin/env python
import sys
import json
import time
import argparse

def reformat_date(indate):
    d = time.strptime(indate, '%Y-%m-%dT%H:%M:%S.%fZ')
    return time.strftime('%d/%b/%Y:%H:%M:%S +0000', d)

def format_log_line(line_json, args):
    datestr = reformat_date(line_json["@timestamp"])
    srcip = ""
    if "sourceIPv4Address" in line_json["netflow"]:
        srcip = line_json["netflow"]["sourceIPv4Address"]
    httpver = "HTTP/1.1" # bit of a fudge tbh
    httpstatcode = "418" # Honest, guv.
    size = "-" # I give up now
    if "netscalerHttpRspStatus" in line_json["netflow"]:
        # well, maybe
        httpstatcode = line_json["netflow"]["netscalerHttpRspStatus"]
    if "netscalerHttpRspLen" in line_json["netflow"]:    
        size = line_json["netflow"]["netscalerHttpRspLen"]
        
    httpuri = "-"
    httpcmd = "-"
    httpreferer = "-"
    httpuseragent = "-"
    dsthost = "-"

    # override blank values if item present
    httpuri = line_json["netflow"]["netscalerHttpReqUrl"]
    httpcmd = line_json["netflow"]["netscalerHttpReqMethod"]
    httpreferer = line_json["netflow"]["netscalerHttpReqReferer"]
    httpuseragent = line_json["netflow"]["netscalerHttpReqUserAgent"]
    dsthost = line_json["netflow"]["netscalerHttpDomainName"]

    line = '{0} - - [{1}] "{2} {3} {4}" {5} {6} "{7}" "{8}" {9}'.format(
        srcip, datestr, httpcmd, httpuri, httpver, httpstatcode, size, httpreferer, httpuseragent, dsthost)

    if "destinationIPv4Address" in line_json["netflow"] and args.with_dstip:
        line += " {0}".format(line_json["netflow"]["destinationIPv4Address"])

    return line

def write_to_log_file(line, outfile):
    outfile.write(line)

def write_error(error_string, args):
    t = time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    error_line = "{0} {1}".format(t, error_string)
    if args.errorfile:
        args.errorfile.write(error_line)
    else:
        sys.stderr.write(error_line)

def file_process_errors(input_file, error_json):
    return "Errors encountered processing input file {0}: {1}\n".format(input_file, json.dumps(error_json))

def output_line(line_json, args):
    formatted_line = format_log_line(line_json, args)
    if args.destfile:
        write_to_log_file("{0}\n".format(formatted_line), args.destfile)
    else:
        print(formatted_line)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("sourcefile", type=argparse.FileType('r'), help="Input file")
    parser.add_argument("-o", dest="destfile", type=argparse.FileType('a'), default=sys.stdout, help="Optional output file (defaults to stdout)")
    parser.add_argument("-e", dest="errorfile", type=argparse.FileType('a'), default=sys.stderr, help="Optional error file (defaults to stderr)")
    parser.add_argument("--with-host", dest="with_host", action="store_true", help="Include the destination hostname in the output")
    parser.add_argument("--with-dstip", dest="with_dstip", action="store_true", help="Include the destination IP address in the output")
    parser.add_argument("-b", dest="broken", action="store_true", help="Dump JSON output of broken lines")
    parser.add_argument("--output-broken", dest="breakfile", type=argparse.FileType('a'), default=sys.stderr, help="Store broken lines to file (defaults to stderr)")
    parser.add_argument("-f", dest="format", default="apache", help="Specify output format")

    p = parser.parse_args()

    write_error("Processing input file {0}\n".format(p.sourcefile.name), p)
    
    counters = { "Errors": {}, "Total": 0, "Successes": 0}
    for line in p.sourcefile:
        j = json.loads(line)
        # ensure line is a http request log
        if j["netflow"].get("netscalerHttpReqMethod"):
            # test to ensure the log hasn't been corrupted
            if j["netflow"]["netscalerHttpReqMethod"] not in ("GET","POST","OPTIONS","HEAD"):
                if "Invalid request method" not in counters["Errors"]:
                    counters["Errors"]["Invalid request method"] = 1
                else:
                    counters["Errors"]["Invalid request method"] += 1
                if p.broken:
                    p.breakfile.write("{0}\n".format(json.dumps(j)))
            else:
                counters["Successes"] += 1
                output_line(j, p)
        else:
            if "Request method not present" not in counters["Errors"]:
                counters["Errors"]["Request method not present"] = 1
            else:
                counters["Errors"]["Request method not present"] += 1
        
        counters["Total"] += 1
    
    write_error(file_process_errors(p.sourcefile.name, counters["Errors"]), p)
    write_error("Successfully output {0} lines to {1}.\n".format(counters["Successes"], p.destfile.name), p)
    write_error("Parsing completed on {0} lines, exiting.\n".format(counters["Total"]), p)


if __name__ == "__main__":
    main()
