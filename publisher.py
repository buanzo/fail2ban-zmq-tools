#!/usr/bin/env python3
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
from pprint import pprint
from util import f2bcUtils

syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_AUTH)


class Publisher(threading.Thread):
    def __init__(self, publisherconfig=None, num_worker_threads=1):
        threading.Thread.__init__(self)
        self._stopevent = threading.Event()
        self.publisherconfig = publisherconfig
        self.zmqBroadcasterBindUrl = self.publisherconfig['broadcasterbindurl']
        self.zmqReplyBindUrl = self.publisherconfig['replybindurl']
        self.authenticate = self.publisherconfig['auth']
        self.authtoken = self.publisherconfig['authtoken']
        syslog.syslog("fail2ban-zmq-tools Publisher: initialization complete")

    def run(self):
        self.zmqPublisherContext = zmq.Context()
        self.zmqPublisherSock = self.zmqPublisherContext.socket(zmq.PUB)
        self.zmqPublisherSock.bind(self.zmqBroadcasterBindUrl)

        self.zmqReplyContext = zmq.Context()
        self.zmqReplySock = self.zmqReplyContext.socket(zmq.REP)
        self.zmqReplySock.bind(self.zmqReplyBindUrl)

        # http://api.zeromq.org/3-2:zmq-setsockopt
        self.zmqReplySock.setsockopt(zmq.MAXMSGSIZE, 64)
        # 1s timeout for recv()
        self.zmqReplySock.setsockopt(zmq.RCVTIMEO, 1000)
        # Wait for messages, when one is received, process it
        while not self._stopevent.isSet():
            message = None
            try:
                message = self.zmqReplySock.recv_string()
            except zmq.error.ZMQError as e:
                if e == errno.EAGAIN:
                    pass  # Nothing to see, move along
            if not message:
                continue

            # Send it back to Requester (monitor instance), but first run
            # some tests.  Failed tests trigger a NAK response, and then a
            # while().continue Check if splitted message has less than 4 or
            # more than 5 slices

            if len(message.split('|')) < 4 or len(message.split('|')) > 5:
                self.zmqReplySock.send_string("NAK")
                syslog.syslog("fail2ban-zmq-tools Publisher: \
                               invalid message. Replying NAK.")
                continue
            # and if incoming token matches our defined token
            if self.authenticate == "true" and  message.split('|')[0] != self.authtoken:
                self.zmqReplySock.send_string("NAK")
                syslog.syslog("fail2ban-zmq-tools Publisher: \
                               invalid token. Replying NAK.")
                continue

            # remove authentication data from to-be-propagated message
            if self.authenticate == "true":
                newmsg = message.split('|')
                message = '|'.join(newmsg[1:])

            # Now test hostname,jail,action and attacker
            newmsg = message.split('|')
            Hostname = newmsg[0]
            Jail = newmsg[1]
            Action = newmsg[2]
            Attacker = newmsg[3]

            if not f2bcUtils.is_valid_hostname(Hostname):
                self.zmqReplySock.send_string("NAK")
                syslog.syslog("fail2ban-zmq-tools Publisher: \
                               invalid hostname in incoming message. \
                               Replying NAK.")
                continue
            if not f2bcUtils.is_valid_action(Action):
                self.zmqReplySock.send_string("NAK")
                syslog.syslog("fail2ban-zmq-tools Publisher: \
                               Unknown action received in message. \
                               Replying NAK.")
                continue
            if not f2bcUtils.valid_ipv4(Attacker):
                self.zmqReplySock.send_string("NAK")
                syslog.syslog("fail2ban-zmq-tools Publisher: \
                               Invalid attacker IP received in message.\
                               Replying NAK.")
                continue
            if not f2bcUtils.valid_jailname(Jail):
                self.zmqReplySock.send_string("NAK")
                syslog.syslog("fail2ban-zmq-tools Publisher: \
                               Invalid jailname received in message. \
                               Replying NAK.")
                continue

            # If we got here, all tests were positive.  we can make an OK
            # reply and then we can propagate the message, which now lacks
            # authentication information
            self.zmqReplySock.send_string(message)
            syslog.syslog("fail2ban-zmq-tools Publisher: \
                           Propagating %s for %s/%s from %s" % (Action,
                                                                Attacker,
                                                                Jail,
                                                                Hostname))
            self.zmqPublisherSock.send_string(message)
        # TODO: add loglevels
        syslog.syslog("fail2ban-zmq-tools Publisher: thread exiting...")
        sys.stdout.flush()

    def join(self, timeout=None):
        # Stop the thread
        self._stopevent.set()
        threading.Thread.join(self, timeout)


if __name__ == "__main__":
    publishing = Publisher()
