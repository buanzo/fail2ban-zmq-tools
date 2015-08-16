from configparser import SafeConfigParser

# This class returns an associative key=value array for the specified section
# from the indicated config file. defaults to fail2ban-cluster.conf
class ConfigParsing():
  def __init__(self,configfile='fail2ban-cluster.conf'):
    self.validsections=['general','monitor','subscriber','publisher']
    self.parser=SafeConfigParser()
    try:
      self.parser.read(configfile)
    except:
      raise ValueError('configuration file does not exist')
    #print('CONFIGPARSING.INIT.OPTIONS=',self.parser.options(self.section))

  def Section(self,section=None):
    if section==None: raise ValueError('no section specified')
    dict1={}
    if not section in self.validsections:
      raise ValueError('requested section is invalid or inexistant')
    options = self.parser.options(section)
    for option in options:
      try:
        dict1[option]=self.parser.get(section,option)
      except:
        dict1[option]=None
        #TODO: add stderr error, must check daemon.py
    return dict1

    
    