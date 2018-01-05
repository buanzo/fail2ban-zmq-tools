import time
import sys
import os
import re
import threading
import queue
import zmq
import socket
import errno
import syslog
from stat import ST_SIZE

syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_AUTH)


# Example BA
# 2009-04-02 18:15:53,693 fail2ban.actions: WARNING [php-url-fopen] Ban 1.2.3.4
class Monitor(threading.Thread):
    def zmqRequester(self, flag, jail, action, attacker):
        if jail == 'fail2bancluster':
            return True  # ignore fail2bancluster bans
        syslog.syslog("Propagating: %s for %s in %s" % (action,
                                                        attacker,
                                                        jail))
        zmqReplyContext = zmq.Context()
        zmqReplySock = zmqReplyContext.socket(zmq.REQ)
        zmqReplySock.connect(self.zmqReplyServer)
        # TODO: sanitize jail names, action (Ban/Unban),
        # TODO: and attacker (IP address regex)
        # TODO: also sanitize hostname according to RFC 1123
        outmsg = ""
        if self.authenticate == "true":
            outmsg = '{}|'.format(self.authtoken)
        outmsg += self.hostname + "|" + jail + "|" + action + "|" + attacker
        zmqReplySock.send_string(outmsg)
        try:
            inmsg = zmqReplySock.recv_string()
        except zmq.error.ZMQError as e:
            if e.errno == errno.EINTR:
                inmsg = outmsg
                pass
            else:
                syslog.syslog("Unhandled or unknown exception")
                raise
        except Exception:
            inmsg = outmsg  # we are being shutdown, fake a good answer
            pass
        if outmsg == inmsg:
            return True
        return False

    def notifier(self):
        sys.stdout.flush()
        flag = 'ok'
        while flag != 'stop':
            try:
                flag, jail, action, attacker = self.dq.get()
            except Exception:
                pass  # TODO: fix
            sys.stdout.flush()
            if flag == 'stop':
                # self.zmqRequester(flag,"BYEBYE","BYEBYE","BYEBYE")
                break
            self.zmqRequester(flag, jail, action, attacker)
            self.dq.task_done()
        syslog.syslog("Notifier exiting loop")
        sys.stdout.flush()

    def __init__(self, monitorconfig=None, num_worker_threads=1):
        threading.Thread.__init__(self)
        self._stopevent = threading.Event()
        self.monitorconfig = monitorconfig
        self.hostname = socket.gethostname()
        # I call it "ReplyServer" because it is a
        # zeromq REQUEST/REPLY type of socket
        self.zmqReplyServer = self.monitorconfig['zmqreplyserver']
        self.logfilename = self.monitorconfig['fail2banlogpath']
        self.authenticate = self.monitorconfig['auth']
        self.authtoken = self.monitorconfig['authtoken']
        # TODO: re-implement HELLOHELLO message to Publisher
        # self.zmqRequester('ok','HELLOHELLO','HELLOHELLO','HELLOHELLO')
        self.logfile = open(self.logfilename, 'r')
        # Prepare regex
        self.regex = re.compile(".*\[(.*)\]\ (Ban|Un[bB]an)\ (.*)")
        # Create queue for notifier
        self.dq = queue.Queue()
        self.ntPool = []
        for i in range(num_worker_threads):
            # http://code.activestate.com/recipes/302746/
            t = threading.Thread(target=self.notifier)
            t.setDaemon(True)
            t.start()
            self.ntPool.append(t)

    def run(self):
        # Find the size of the file and move to the end
        st_results = os.stat(self.logfilename)
        st_size = st_results[6]
        self.logfile.seek(st_size)

        while not self._stopevent.isSet():
            where = self.logfile.tell()
            line = self.logfile.readline()
            if not line:
                # logfile truncated or rotated. we got to reset.
                if os.stat(self.logfilename)[ST_SIZE] < where:
                    syslog.syslog("fail2ban-zmq-cluster Monitor: fail2ban \
                                   logfile rotation detected.")
                    self.logfile.close()
                    self.logfile = open(self.logfilename, 'r')
                    where = self.logfile.tell()
                else:
                    time.sleep(1)
                    self.logfile.seek(where)
            else:
                # match the line. attempt to extract jail\
                # (postfix, apache-badbots, etc), action (Ban/UnBan) and IP
                logdata = self.regex.match(line)
                if logdata is not None:
                    jail = logdata.group(1)
                    action = logdata.group(2)
                    attacker = logdata.group(3)
                    self.dq.put(["ok", jail, action, attacker])
                    sys.stdout.flush()
                    # self.zmqRequester('BYEBYE','BYEBYE','BYEBYE','BYEBYE')
        sys.stdout.flush()

    def join(self, timeout=None):
        """ Stop the thread
        """
        sys.stdout.flush()
        for i in range(len(self.ntPool)):
            self.dq.put(["stop", 0, 0, 0])
            sys.stdout.flush()
        sys.stdout.flush()
        while self.ntPool:
            time.sleep(1)
            sys.stdout.flush()
            for index, the_thread in enumerate(self.ntPool):
                if the_thread.isAlive():
                    continue
                else:
                    del self.ntPool[index]
                    break
        self._stopevent.set()
        threading.Thread.join(self, timeout)


if __name__ == "__main__":
    from configparsing import ConfigParsing
    monitorconfig = ConfigParsing().Section(section='monitor')
    monitoreo = Monitor(monitorconfig=monitorconfig)
