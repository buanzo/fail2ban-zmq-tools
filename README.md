Fail2ban-zmq-tools
------------------

Author: Arturo 'Buanzo' Busleiman <buanzo@buanzo.com.ar>

This is a very simple fail2ban clustering solution that works ad-hoc to
a running fail2ban instance. It consists of three modules: publisher,
subscriber, monitor.

The monitor needs access to fail2ban.log to, ehem, monitor fail2ban.log for
Ban/UnBan messages, which it will forward to Publisher.

Publisher gets messages, and re-distributes it to the Subscribers.

Hence, for your cluster, you need n monitors, n subscribers, but ONE
publisher.

Docker support is barely getting into the project as of 201801.

This is a set of python scripts to be run in parallel to an existing
fail2ban installation to allow multiple instances of fail2ban running in
different servers to 'cluster up', and share blocked IP addresses, for
proactive protection, by means of zeromq message queuing system.

DESIGN:
=======

There are three individual Processes: Monitor, Publisher and Subscriber.
There is ONE central configuration file, with appropiate sections for each
process. You do not need to run all processes, just the ones you want. Keep
reading.

-------------------------------------------
fail2ban-zmq-tools Cluster Subscriber
(started by ./fail2ban-subscriber.py start)
-------------------------------------------

The Subscriber receives messages from the Publisher, and depending on the
subscriberaction configuration option, does one thing or another with the
message. The idea is that the fail2ban instance that is local to the subscriber
will take this message and ban/unban accordingly.

NOTE: You *do not* need to run a Publisher instance (or have access tokens for another
Publisher, just like mine, which is the default one) if you only want to
subscribe to a Publisher.

----------------------------------------
fail2ban-zmq-tools Cluster Monitor
(started by ./fail2ban-monitor.py start)
----------------------------------------

This script monitors /var/log/fail2ban.log (you can change the fail2ban log
location by editing the fail2ban-cluster.conf file). When it detects a new
ban or unban, it transfers this information to the Publisher processes, by
means of a zeromq (www.zeromq.org) REQUEST/REPLY socket.


------------------------------------------
fail2ban-zmq-tools Cluster Publisher
(started by ./fail2ban-publisher.py start)
------------------------------------------

The Publisher receives messages using the aforementioned protocol. When it
gets a message, it replies back with the same message (as a simple ACK),
then broadcasts it to all the connected Subscribers.





NOTE: This software is an adaptation of fail2ban-cluster, a piece of
software I never fully released publicly. The fail2ban-cluster.conf general
configuration file is named in memoriam of that project :)

The "banip" fail2ban-client command was part of that original idea.

