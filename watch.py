#!/usr/bin/env python

import sys, time, os, logging, json, ipfixout, glob, argparse, datetime, traceback, collections, signal, Queue, sched, threading
from watchdog.observers import Observer
from watchdog.events import RegexMatchingEventHandler

logger = logging.getLogger(__name__)
q = Queue.Queue()
statstime = 60

class ObjectDict(dict):
    def __getattr__(self, name):
        return self.__getitem__(name)

def process_file(path, position, state, args):
    logger.debug("Start processing on {0} at position {1}".format(path, position))
    setattr(args, "with_srcip", True)
    setattr(args, "with_dstip", True)

    with open(path) as f:
        try:
            last_position = position
            outname = os.path.join(args.outpath, os.path.basename(f.name).split("_")[0] + "-netscaler_http_apache.txt")
            f.seek(position)
            loglines = f.readlines()
            last_position = f.tell()
            logger.debug("Read {0} lines from {1}".format(len(loglines), path))
            ex = 0
            wl = 0
            with open(outname, 'a') as o:
                for l in loglines:
                    try:
                        ljson = json.loads(l)
                        if "netscalerHttpReqMethod" in ljson["netflow"]:
                            if ljson["netflow"]["netscalerHttpReqMethod"] in ["POST", "GET", "HEAD", "OPTIONS"]:
                                if ljson["netflow"]["netscalerTransactionId"] in state["res"]:
                                    logger.debug("Transaction ID {0} found in response state, writing out".format(ljson["netflow"]["netscalerTransactionId"]))
                                    # if the response is already known, write immediately
                                    outline = ljson
                                    outline["netflow"]["netscalerHttpRspStatus"] = state["res"][ljson["netflow"]["netscalerTransactionId"]]["netflow"]["netscalerHttpRspStatus"]
                                    apacheline = ipfixout.format_log_line(outline, args)
                                    o.write(apacheline + os.linesep)
                                    wl += 1
                                    
                                    # remove from state tables
                                    del(state["res"][ljson["netflow"]["netscalerTransactionId"]])
                                elif ljson["netflow"]["netscalerTransactionId"] not in state["req"]:
                                    logger.debug("New Transaction ID {0} found, adding to table".format(ljson["netflow"]["netscalerTransactionId"]))
                                    # check size of state table, purge old data if full
                                    while len(state["req"]) > args.maxstate:
                                        outline = state["req"].popitem(last=False)[1]
                                        logger.debug("Max request state size reached, writing out Transaction ID {0}".format(ljson["netflow"]["netscalerTransactionId"]))
                                        # set placeholder response code and write to file
                                        outline["netflow"]["netscalerHttpRspStatus"] = 0
                                        apacheline = ipfixout.format_log_line(outline, args)
                                        o.write(apacheline + os.linesep)
                                        wl += 1
                                    # add new state line
                                    state["req"][ljson["netflow"]["netscalerTransactionId"]] = ljson
                                    logger.debug("req state size is {0}".format(len(state["req"])))
                        if "netscalerHttpRspStatus" in ljson["netflow"]:
                            if ljson["netflow"]["netscalerTransactionId"] in state["req"]:
                                logger.debug("Transaction ID {0} found in request state, writing out".format(ljson["netflow"]["netscalerTransactionId"]))
                                # if request is present in state table, write immediately
                                outline = state["req"][ljson["netflow"]["netscalerTransactionId"]]
                                #outline["netscalerHttpRspStatus"] = state["res"][ljson["netflow"]["netscalerTransactionId"]]["netscalerHttpRspStatus"]
                                outline["netflow"]["netscalerHttpRspStatus"] = ljson["netflow"]["netscalerHttpRspStatus"]
                                apacheline = ipfixout.format_log_line(outline, args)
                                o.write(apacheline + os.linesep)
                                wl += 1
                            
                                # remove from state tables
                                del(state["req"][ljson["netflow"]["netscalerTransactionId"]])
                            else:
                                # check size of state table, purge old data if full
                                while len(state["res"]) > args.maxstate * 5:
                                    logger.debug("Max response state size reached, purging oldest flow")
                                    state["res"].popitem(last=False)
                                state["res"][ljson["netflow"]["netscalerTransactionId"]] = ljson
                                logger.debug("res state size is {0}".format(len(state["res"])))
                            

                    except Exception as e:
                        exc_type, exc_value, exc_tb = sys.exc_info()
                        traceback.print_exception(exc_type, exc_value, exc_tb, limit=2, file=sys.stderr)
                        ex += 1
                        if 'outline' in locals():
                            sys.stderr.write(json.dumps(outline) + "\n")
            logger.debug("Exception on {0} lines".format(ex))
        except Exception as e:
            exc_type, exc_value, exc_tb = sys.exc_info()
            traceback.print_exception(exc_type, exc_value, exc_tb, limit=2, file=sys.stderr)
            logger.debug("Exception reached, skipping")
            pass
        finally:
            return {"filepos": last_position, "written": wl, "outname": outname}

def files_to_read(currentfpath):
    sdate = datetime.datetime.strptime("1970-01-01", "%Y-%m-%d")
    cdate = datetime.datetime.utcnow().replace(microsecond=0,second=0,minute=0)
    if currentfpath:
        basename = os.path.basename(currentfpath)
        sdate = datetime.datetime.strptime(basename.split("_")[0], "%Y-%m-%d.%H")
    allfiles = glob.glob("/var/log/logstash/*_json.log")
    allfiles.sort(key=os.path.getmtime)
    ftr = []
    for f in allfiles:
        fbasename = os.path.basename(f)
        fsdate = datetime.datetime.strptime(fbasename.split("_")[0], "%Y-%m-%d.%H")
        if fsdate >= sdate and fsdate <= cdate:
            ftr.append(f)

    return ftr
    
    

class NetscalerParse(RegexMatchingEventHandler):
    def __init__(self, *args, **kwargs):
        src_args = kwargs.pop("srcargs")
        super(self.__class__, self).__init__(*args, **kwargs)
        self.src_args = src_args
        self._last_position = getpos(src_args.posfile)["position"]
        self._last_event_path = ""
        self.state = {"req": collections.OrderedDict(), "res": collections.OrderedDict()}
        self._statefile = os.path.join(self.src_args.outpath, "ipfix.state")
        self.load_state()
        signal.signal(signal.SIGTERM, self.breakout)
        signal.signal(signal.SIGINT, self.breakout)
        self.exit_now = False

    def load_state(self):
        if (os.path.exists(self._statefile)):
            with open(self._statefile, 'r') as f:
                oldstate = json.load(f)
                for oldreqid, oldreq in oldstate["req"].items():
                    self.state["req"][oldreqid] = oldreq
                for oldresid, oldres in oldstate["res"].items():
                    self.state["res"][oldresid] = oldres
            logger.info("Loaded req[{0}] res[{1}] from state file".format(len(self.state["req"]), len(self.state["res"])))
            os.remove(self._statefile)

#    def on_created(self, event):
#        self._last_position = 0
#        self._last_event_path = event.src_path
#        posdata = {"path": event.src_path, "position": 0}
#        writepos(posdata, self.src_args.posfile) 

    # initialise session tracking array

    def on_modified(self, event):
        currenthour = datetime.datetime.utcnow().strftime("%Y-%m-%d.%H")
        currentfile = os.path.join(self.src_args.watchpath, currenthour + "_json.log")
        if event.src_path == currentfile:
            if self._last_position > os.path.getsize(event.src_path):
                logger.debug("Event file is smaller than last position - must be new file")
                self._last_position = 0
                logger.info("Now reading from file {0}".format(event.src_path))
            if self._last_event_path != event.src_path:
                logger.debug("Event file is different from previous event file")
                self._last_event_path = event.src_path
            logger.debug("Reading at position {0}".format(self._last_position))
            results = process_file(event.src_path, self._last_position, self.state, self.src_args)
            self._last_position = results["filepos"]
            if results["written"] > 0:
                writepos({"path": event.src_path, "position": self._last_position}, self.src_args.posfile)
            logger.debug("Wrote {0} lines to {1}".format(results["written"], results["outname"]))
            q.put({"rows written": results["written"], "state": {"req": len(self.state["req"]), "res": len(self.state["res"])}})

            self._last_event_path = event.src_path
        else:
            logger.debug("Event received on non current file - skipping {0}".format(event.src_path))

    def breakout(self, signum, frame):
        self.exit_now = True

    def flush_state(self):
        #dstr = datetime.datetime.utcnow().strftime("%Y-%m-%d.%H")
        #outname = os.path.join(self.src_args.outpath, dstr + "-netscaler_http_apache.txt")
        #wl = 0
        
        with open(self._statefile, 'w') as f:
            f.write(json.dumps(self.state))
            logger.info("State: req[{0}], res[{1}] written to {2}".format(len(self.state["req"]), len(self.state["res"]), self._statefile))
        #with open(outname, 'a') as o:
        #    for item, r in self.state["req"].iteritems():
        #        apacheline = ipfixout.format_log_line(r, self.src_args)
        #        o.write(apacheline + os.linesep)
        #        wl += 1
        #    logger.info("Wrote {0} lines to {1}".format(wl, outname))
        #    logger.debug("State flush complete")

def writepos(posdata, posfilepath):
    with open(posfilepath, 'w') as f:
        pos = json.dumps(posdata)
        f.write(pos)

def getpos(posfilepath):
    if os.path.exists(posfilepath):
        with open(posfilepath, 'r') as f:
            return json.load(f)
    else:
        return 0

class Monitor(object):
    def __init__(self, interval):
        self.scheduler = sched.scheduler(time.time, time.sleep)
        self.interval = interval
        self._running = False
        
    def periodic(self, action, actionargs = ()):
        if self._running:
            self.event = self.scheduler.enter(self.interval, 1, self.periodic, (action, actionargs))
            action(*actionargs)
            
    def start(self):
        self._running = True
        self.periodic(stats)
        self.scheduler.run()
        
    def stop(self):
        self._running = False
        if self.scheduler and self.event:
            self.scheduler.cancel(self.event)
        logger.info("Stopped monitoring")
    
def stats_scheduler():
    s = sched.scheduler(time.time, time.sleep)
    obj = s.enter(60, 1, stats, ())
    s.run()
    return obj
    
def stats():
    written = 0
    req = 0
    res = 0
    items = q.qsize()
    for i in range(items):
        val = q.get()
        written += val["rows written"]
        req += val["state"]["req"]
        res += val["state"]["res"]
    
    avgreq = 0
    avgres = 0
    
    if items > 0:
        avgreq = float(req) / items
        avgres = float(res) / items
        
    rate = float(written) / statstime
    ratestr = "{0:.2f}".format(rate)
    logger.info("{0} rows written, {1} messages/s average".format(written, ratestr))
    logger.info("Average queue size: req[{0}], res[{1}]".format(avgreq,avgres))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("watchpath", help="Path to watch for new files")
    parser.add_argument("--position-file", dest="posfile", default="/var/log/apache/track.pos", help="File to store position information in")
    parser.add_argument("-l", dest="loglevel", default="INFO")
    parser.add_argument("-o", dest="outpath", default="/var/log/apache/")
    parser.add_argument("--max-state", dest="maxstate", default=1000, type=int, help="Maximum HTTP request records to hold in memory before flushing out. \
Records with no matching response will have placeholder values in the output.")
    parser.add_argument("-t", dest="statstime", default=60, help="Output statistics to stderr every (n) seconds")

    fmt = '%(asctime)s - %(message)s'
    dfmt = '%Y-%m-%d %H:%M:%S'

    args = parser.parse_args()

    lvl = getattr(logging, args.loglevel)

    logging.getLogger("ipfixout").setLevel(lvl)
    logging.getLogger(__name__).setLevel(lvl)

    ch = logging.StreamHandler()
    ch.setLevel(lvl)
    formatter = logging.Formatter(fmt, datefmt=dfmt)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    logger.info("Starting preprocessing")
    
    # identify which files have not yet been processed
    ftr = []
    posdata = {"path": "", "position": 0}

    if not os.path.exists(args.posfile):
        ftr = files_to_read("")
    else:
        posdata = getpos(args.posfile)
        ftr = files_to_read(posdata["path"])

    logger.info("{0} files to process since last position update".format(len(ftr)))

    # initialise session tracking array
    reconstructor = {"req": collections.OrderedDict(), "res": collections.OrderedDict()}

    for oldfile in ftr:
        results = process_file(oldfile, posdata["position"], reconstructor, args)
        postdata = {"path": oldfile, "position": results["filepos"]}
        writepos(postdata, args.posfile)

    del(reconstructor)

    logger.info("Processed old data; proceeding to live")
    
    event_handler = NetscalerParse(regexes=[r'.*\_json.log'], srcargs=args)
    observer = Observer()
    observer.schedule(event_handler, args.watchpath, recursive=False)
    logger.info("Starting watcher")
    observer.start()
    
    statstime = int(args.statstime)
    ctr = Monitor(statstime)
    t = threading.Thread(target=ctr.start, name="stats")
    t.start()

    try:
        while True:
            time.sleep(1)
            if event_handler.exit_now:
                raise KeyboardInterrupt
    except KeyboardInterrupt:
        logger.error("Interrupt received")
        observer.stop()
        ctr.stop()
        logger.debug("Position: {0}".format(event_handler._last_position))
        event_handler.flush_state()
        
    observer.join()
    logger.info("Shutdown complete")
