#!/usr/bin/python3
# for configuration, please refer to fail2ban-cluster.conf
import zmq,sys,time,signal,syslog
from configparsing import ConfigParsing
from daemon import daemon
from subscriber import Subscriber

global subscriberconfig
subscriberconfig=ConfigParsing().Section(section='subscriber')

syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_AUTH)

class f2bSubscriberDaemon(daemon):
	def __sigTERMhandler(self,signum,frame):
		syslog.syslog("fail2ban-zmq-tools Subscriber: Caught signal %d. Initiating shutdown..." % signum)
		self.quit()

	def run(self):
		syslog.syslog("fail2ban-zmq-tools Subscriber starting")
		signal.signal(signal.SIGTERM,self.__sigTERMhandler)
		signal.signal(signal.SIGINT,self.__sigTERMhandler)
		self.subscriber = Subscriber(subscriberconfig=subscriberconfig)
		self.subscriber.start()
		syslog.syslog("fail2ban-zmq-tools Subscriber running. Main process waiting for termination signal. Threads working.")
		signal.pause()
		syslog.syslog("fail2ban-zmq-tools Subscriber exiting.")
		
	def quit(self):
		signal.signal(signal.SIGTERM,signal.SIG_IGN)
		syslog.syslog("fail2ban-zmq-tools Subscriber: Stopping threads...")
		self.subscriber.join()

if __name__ == "__main__":
	pidfile=subscriberconfig['pidfile']
	Daemon = f2bSubscriberDaemon(pidfile)
	if len(sys.argv)==2:
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
			
