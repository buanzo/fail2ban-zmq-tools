import time,sys,os,re,threading,queue,zmq,socket,syslog

from util import f2bcUtils

syslog.openlog(logoption=syslog.LOG_PID,facility=syslog.LOG_AUTH)

class Subscriber(threading.Thread):
	def __init__(self,subscriberconfig=None,num_worker_threads=1):
		threading.Thread.__init__(self)
		self._stopevent=threading.Event()
		self.subscriberconfig=subscriberconfig
		self.zmqPublisher=self.subscriberconfig['zmqpublisherurl']
		self.publisheraction=self.subscriberconfig['subscriberaction']
		self.hostname = socket.gethostname() # we want to ignore our own messages.
		
	def run(self):
		self.zmqSubscriberContext=zmq.Context()
		self.zmqSubscriberSock=self.zmqSubscriberContext.socket(zmq.SUB)
# TODO: fix prefix handling
#		self.zmqSubscriberSock.setsockopt_string(zmq.SUBSCRIBE,self.subscriberconfig['zmqprefixfilter'].strip('"'))
		self.zmqSubscriberSock.setsockopt_string(zmq.SUBSCRIBE,"")
		self.zmqSubscriberSock.connect(self.zmqPublisher)
		# Wait for messages, when one is received, process it
		while not self._stopevent.isSet():
			message = self.zmqSubscriberSock.recv_string()
			# TODO: INPUT CHECK HERE - apply regex and such against message parts (jail, ip, etc)
			# TODO: act according to publisheraction [see fail2ban-cluster.conf]
			msg=message.split('|')
			Hostname=msg[0]
			Jail=msg[1]
			Action=msg[2]
			Attacker=msg[3]
			# Run a series of tests on incoming messages
			if not f2bcUtils.is_valid_hostname(Hostname):
				syslog.syslog("fail2ban-zmq-tools Subscriber: Invalid hostname in incoming message.")
				continue
			# If hostname matches our hostname, output warning, using different syntax to avoid
			# triggering the fail2bancluster jail filter.
			if Hostname==self.hostname:
				syslog.syslog("fail2ban-zmq-tools Subscriber: Got equal hostname broadcast. Our hostname is %s" % self.hostname)
				continue
			# Only accepted ban or unban actions
			if not f2bcUtils.is_valid_action(Action):
				syslog.syslog("fail2ban-zmq-tools Subscriber: Unknown action received in broadcasted message.")
				continue
			# Only accept valid IPv4 IP addresses for attacker
			if not f2bcUtils.valid_ipv4(Attacker):
				syslog.syslog("fail2ban-zmq-tools Subscriber: Invalid attacker IP received in broadcasted message.")
				continue
			# Jailnames must only contain chars a-z,A-Z,-_
			# TODO: verify fail2ban jailname constraints
			if not f2bcUtils.valid_jailname(Jail):
				syslog.syslog("fail2ban-zmq-tools Subscriber: Invalid jail name received in broadcasted message.")
				continue
			# TODO add debug level output for an invalid message
			syslog.syslog("fail2ban-zmq-tools Subscriber: Got broadcast message: %s" % message)
		syslog.syslog("fail2ban-zmq-tools Subscriber: thread exiting...")
	
	def join(self,timeout=None):
		self._stopevent.set()
		threading.Thread.join(self,timeout)

if __name__ == "__main__":
	subscribing=Subscriber()

