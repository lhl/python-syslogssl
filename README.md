python-syslogssl
================

Extends logging.handlers.SysLogHandler to create a logging handler with SSL 
support.

I built this as a pretty trivial extension to the SysLogHandler as I wanted to
use Python logging with TCP (to track delivery) to https://papertrailapp.com/, 
but they only support TCP w/ SSL enabled.

This is a pretty straightforward to use, sample usage is included w/ the module,
but here we go:

```python
import logging
import socket
from   syslogssl import SSLSysLogHandler

host = 'logs.papertrailapp.com'
port = 514 # default, you'll want to change this to your port
address = (host, port)

# We don't want this to hang
socket.setdefaulttimeout(5.0)

logger = logging.getLogger()
logger.setLevel(logging.INFO)
syslog =  SSLSysLogHandler(address=address, certs='syslog.papertrail.crt')
logger.addHandler(syslog)

logger.info('testing SSLSysLogHandler')
```

I've included the syslog.papertrail.crt for convenience, but you may want to
double-check it for security.  Note, if you don't include certs, the code will
make an ssl.CERT_NONE connection, which works w/ papertrailapp.

I haven't tested this code with anything else, and it's provided AS IS under
an MIT License.  Specifically:

```
Copyright (c) 2012 Leonard Lin

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```
