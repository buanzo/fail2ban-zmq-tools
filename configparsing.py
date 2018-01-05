from configparser import SafeConfigParser


class ConfigParsing():
    # This class returns an associative key=value
    # array for the specified section
    # from the indicated config file. defaults to fail2ban-cluster.conf
    def __init__(self, configfile='fail2ban-cluster.conf'):
        self.validsections = ['general', 'monitor', 'subscriber', 'publisher']
        self.parser = SafeConfigParser()
        try:
            self.parser.read(configfile)
        except Exception:
            raise ValueError('configuration file does not exist')

    def Section(self, section=None):
        if section is None:
            raise ValueError('no section specified')
        dict1 = {}
        if section not in self.validsections:
            raise ValueError('requested section is invalid or inexistant')
        options = self.parser.options(section)
        for option in options:
            try:
                dict1[option] = self.parser.get(section, option)
            except Exception:
                dict1[option] = None
                # TODO: add stderr error, must check daemon.py
        return dict1
