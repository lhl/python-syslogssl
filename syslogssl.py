#!/usr/bin/env python


import codecs
from datetime import datetime
import logging
import logging.handlers
import pytz
import ssl
import socket
import tzlocal


class NewLineFraming:

  def frame( self, message ):
    return message + '\n'


class OctetCountingFraming:

  def frame( self, message ):
    length = len( message )
    frame = str( length ) + " " + message
    return frame


class RFC5424Header:

    def format_header(self, syslog, record, priority, message):
        created_at_local_notz = datetime.fromtimestamp(record.created)
        local_tz = tzlocal.get_localzone()
        created_at_local = local_tz.localize(created_at_local_notz)
        created_at_utc = created_at_local.astimezone(pytz.utc)
        when = created_at_utc.isoformat()[0:-6] + "Z"

        if syslog.process_name is None:
            name = record.processName
        else:
            name = syslog.process_name

        return priority + "1 " + when + " " + syslog.hostname + " " + name + " " + str(
            record.process) + " - - " + message


class TraditionalHeader:

    def format_header(self, syslog, record, priority, message):
        return priority + message


class SSLSysLogHandler(logging.handlers.SysLogHandler):

  # We need to paste all this in because __init__ bitches otherwise
  # This all comes from logging.handlers.SysLogHandler

  LOG_EMERG     = 0       #  system is unusable
  LOG_ALERT     = 1       #  action must be taken immediately
  LOG_CRIT      = 2       #  critical conditions
  LOG_ERR       = 3       #  error conditions
  LOG_WARNING   = 4       #  warning conditions
  LOG_NOTICE    = 5       #  normal but significant condition
  LOG_INFO      = 6       #  informational
  LOG_DEBUG     = 7       #  debug-level messages

  #  facility codes
  LOG_KERN      = 0       #  kernel messages
  LOG_USER      = 1       #  random user-level messages
  LOG_MAIL      = 2       #  mail system
  LOG_DAEMON    = 3       #  system daemons
  LOG_AUTH      = 4       #  security/authorization messages
  LOG_SYSLOG    = 5       #  messages generated internally by syslogd
  LOG_LPR       = 6       #  line printer subsystem
  LOG_NEWS      = 7       #  network news subsystem
  LOG_UUCP      = 8       #  UUCP subsystem
  LOG_CRON      = 9       #  clock daemon
  LOG_AUTHPRIV  = 10      #  security/authorization messages (private)
  LOG_FTP       = 11      #  FTP daemon

  #  other codes through 15 reserved for system use
  LOG_LOCAL0    = 16      #  reserved for local use
  LOG_LOCAL1    = 17      #  reserved for local use
  LOG_LOCAL2    = 18      #  reserved for local use
  LOG_LOCAL3    = 19      #  reserved for local use
  LOG_LOCAL4    = 20      #  reserved for local use
  LOG_LOCAL5    = 21      #  reserved for local use
  LOG_LOCAL6    = 22      #  reserved for local use
  LOG_LOCAL7    = 23      #  reserved for local use

  priority_names = {
      "alert":    LOG_ALERT,
      "crit":     LOG_CRIT,
      "critical": LOG_CRIT,
      "debug":    LOG_DEBUG,
      "emerg":    LOG_EMERG,
      "err":      LOG_ERR,
      "error":    LOG_ERR,        #  DEPRECATED
      "info":     LOG_INFO,
      "notice":   LOG_NOTICE,
      "panic":    LOG_EMERG,      #  DEPRECATED
      "warn":     LOG_WARNING,    #  DEPRECATED
      "warning":  LOG_WARNING,
      }

  facility_names = {
      "auth":     LOG_AUTH,
      "authpriv": LOG_AUTHPRIV,
      "cron":     LOG_CRON,
      "daemon":   LOG_DAEMON,
      "ftp":      LOG_FTP,
      "kern":     LOG_KERN,
      "lpr":      LOG_LPR,
      "mail":     LOG_MAIL,
      "news":     LOG_NEWS,
      "security": LOG_AUTH,       #  DEPRECATED
      "syslog":   LOG_SYSLOG,
      "user":     LOG_USER,
      "uucp":     LOG_UUCP,
      "local0":   LOG_LOCAL0,
      "local1":   LOG_LOCAL1,
      "local2":   LOG_LOCAL2,
      "local3":   LOG_LOCAL3,
      "local4":   LOG_LOCAL4,
      "local5":   LOG_LOCAL5,
      "local6":   LOG_LOCAL6,
      "local7":   LOG_LOCAL7,
      }

  #The map below appears to be trivially lowercasing the key. However,
  #there's more to it than meets the eye - in some locales, lowercasing
  #gives unexpected results. See SF #1524081: in the Turkish locale,
  #"INFO".lower() != "info"
  priority_map = {
      "DEBUG" : "debug",
      "INFO" : "info",
      "WARNING" : "warning",
      "ERROR" : "error",
      "CRITICAL" : "critical"
  }

  framing_strategy = NewLineFraming()
  header_format = TraditionalHeader()

  # Host name to attach to the records
  hostname = socket.gethostname()

  # Overrides the process name from the record
  process_name = None

  # Allow retrying
  allows_retries = False


  def __init__(self, address, certs=None,
               facility=LOG_USER):
    logging.Handler.__init__(self)

    self.address = address
    self.certs = certs
    self.facility = facility

    self.unixsocket = 0
    self.socket = None

  def _connect(self):
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

      if self.certs:
          self.socket = ssl.wrap_socket(s,
                                        ca_certs=self.certs,
                                        cert_reqs=ssl.CERT_REQUIRED)
      else:
          self.socket = ssl.wrap_socket(s, cert_reqs=ssl.CERT_NONE)
      self.socket.connect(address)

  def _retry(self, record):
      if self.is_retrying and self.allows_retries:
          return True

      self.is_retrying = True
      if self.socket is not None:
          try:
            self.socket.close()
          except:
              pass # Sometimes sockets are already closed
          finally:
              self.socket = None

      self._connect()
      self.emit(self, record)
      self.is_retrying = False
      return False

  def close(self):
    self.socket.close()
    logging.Handler.close(self)


  def emit(self, record):
    if self.socket is None:
        self._connect()

    msg = self.format(record)
    prio = '<%d>' % self.encodePriority(self.facility,
                                        self.mapPriority(record.levelname))
    if type(msg) is unicode:
      msg = msg.encode('utf-8')
      if codecs:
        msg = codecs.BOM_UTF8 + msg

    full_message = self.header_format.format_header( self, record, prio, msg )
    framed_message = self.framing_strategy.frame( full_message )
    try:
      self.socket.write( framed_message )
    except(KeyboardInterrupt, SystemExit):
      raise
    except ssl.SSLError as problem:
      if self._rety():
          raise
    except:
      self.handleError(record)


### Example Usage ###

if __name__ == '__main__':
  def test_handler( handler, message ):
      logger.addHandler( handler )
      logger.info( message )
      logger.removeHandler( handler )

  import os
  host = os.getenv( 'SYSLOG_HOST', 'logs.papertrailapp.com' )
  port = int( os.getenv( 'SYSLOG_PORT', '514' ) ) # default, you'll want to change this
  address = (host, port)

  # We don't want this to hang
  socket.setdefaulttimeout(.5)

  logger = logging.getLogger()
  logger.setLevel(logging.INFO)

  # Test original format
  original_wire =  SSLSysLogHandler(address=address, certs='syslog.papertrail.crt')
  test_handler( original_wire, "Default usage" )

  # Test RFC5424 wire format
  rfc5424 = SSLSysLogHandler( address=address, certs='syslog.papertrail.crt' )
  rfc5424.framing_strategy = OctetCountingFraming()
  rfc5424.header_format = RFC5424Header()
  test_handler( rfc5424, "RFC5424 frame" )

