#!/usr/bin/env python3
# for configuration, please refer to fail2ban-cluster.conf
import zmq
import sys
import time
import signal
import syslog

from configparsing import ConfigParsing
from daemon import daemon
from publisher import Publisher

global publisherconfig
publisherconfig = ConfigParsing().Section(section='publisher')

syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_AUTH)


class f2bPublisherDaemon(daemon):
    def __sigTERMhandler(self, signum, frame):
        syslog.syslog("fail2ban-zmq-tools Publisher: Caught signal %d.\
                       Initiating shutdown..." % signum)
        self.quit()

    def run(self):
        syslog.syslog("fail2ban-zmq-tools Publisher starting")
        signal.signal(signal.SIGTERM, self.__sigTERMhandler)
        signal.signal(signal.SIGINT, self.__sigTERMhandler)
        self.publisher = Publisher(publisherconfig=publisherconfig)
        self.publisher.start()
        syslog.syslog("fail2ban-zmq-tools Publisher running.\
                       Main process waiting for termination signal.\
                       Threads working.")
        signal.pause()
        syslog.syslog("fail2ban-zmq-tools Publisher exiting.")

    def quit(self):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        syslog.syslog("fail2ban-zmq-tools Publisher: Stopping threads...")
        self.publisher.join()
        syslog.syslog("fail2ban-zmq-tools Publisher says Bye")


if __name__ == "__main__":
    pidfile = publisherconfig['pidfile']
    Daemon = f2bPublisherDaemon(pidfile)
    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            Daemon.start()
        elif 'stop' == sys.argv[1]:
            Daemon.stop()
        elif 'restart' == sys.argv[1]:
            Daemon.restart()
        else:
            print("Unknown command")
            sys.exit(2)
        sys.exit(0)
    else:
        print("Usage: %s start|stop|restart" % sys.argv[0])
        sys.exit(2)
