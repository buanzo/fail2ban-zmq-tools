#!/usr/bin/python3
import sys, time, signal, syslog
from configparsing import ConfigParsing
from daemon import daemon
from monitor import Monitor

global monitorconfig
monitorconfig=ConfigParsing().Section(section='monitor')

syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_AUTH)

class f2bcDaemon(daemon):
        def __sigTERMhandler(self, signum, frame):
                syslog.syslog ("Caught signal %d. Initiating shutdown..." % signum)
                self.quit()
                                        
        def run(self):
                syslog.syslog ('fail2ban-zmq-tools Monitor starting.')
                signal.signal(signal.SIGTERM, self.__sigTERMhandler)
                signal.signal(signal.SIGINT, self.__sigTERMhandler)
                self.monitor = Monitor(monitorconfig=monitorconfig)
                syslog.syslog ('fail2ban-zmq-tools Monitor running. Main process waiting for termination signal. Threads working.')
                self.monitor.start()
                signal.pause()
                syslog.syslog ('fail2ban-zmq-tools Monitor exiting.')

        def quit(self):
                syslog.syslog("fail2ban-zmq-tools Monitor received signal to quit.")
                signal.signal(signal.SIGTERM,signal.SIG_IGN)
                self.monitor.join()
		
if __name__ == "__main__":
        pidfile=monitorconfig['pidfile']
        Daemon = f2bcDaemon(pidfile)
        if len(sys.argv) == 2:
                if 'start' == sys.argv[1]:
                        Daemon.start()
                elif 'stop' == sys.argv[1]:
                        Daemon.stop()
                elif 'restart' == sys.argv[1]:
                        Daemon.restart()
                else:
                        print ("Unknown command")
                        sys.exit(2)
                sys.exit(0)
        else:
                syslog.syslog ("usage: %s start|stop|restart" % sys.argv[0])
                sys.exit(2)
