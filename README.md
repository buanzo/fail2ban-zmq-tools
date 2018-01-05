Fail2ban-zmq-tools
------------------

This is a very simple fail2ban clustering solution that works ad-hoc to
a running fail2ban instance. It consists of three modules: publisher,
subscriber, monitor.

The monitor needs access to fail2ban.log to, ehem, monitor fail2ban.log for
Ban/UnBan messages, which it will forward to Publisher.

Publisher gets messages, and re-distributes it to the Subscribers.

Hence, for your cluster, you need n monitors, n subscribers, but ONE
publisher.

Docker support is barely getting into the project as of 201801.

