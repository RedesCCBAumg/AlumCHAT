import sleekxmpp, sys # This is a library that calls a previously installed version of sleekxmpp in python
import logging #The login module of this library allows us to track an event within a software. For example, log an error message.
import getpass #This module allows in this case to request a password from the user without reflecting it on the screen.
from optparse import OptionParser #The OptParse module makes it easy to write command line tools.

from sleekxmpp.exceptions import IqError, IqTimeout # can generate IqError and IqTimeout exceptions
# MAIN CLASS
if __name__ == '__main__':
    optp = OptionParser() # Setup the command line arguments

    # Output verbosity options.
    optp.add_option('-q', '--quiet', help='set logging to ERROR',
                    action='store_const', dest='loglevel',
                    const=logging.ERROR, default=logging.INFO)
    optp.add_option('-d', '--debug', help='set logging to DEBUG',
                    action='store_const', dest='loglevel',
                    const=logging.DEBUG, default=logging.INFO)
    optp.add_option('-v', '--verbose', help='set logging to COMM',
                    action='store_const', dest='loglevel',
                    const=5, default=logging.INFO)

    # The Jabber ID or "JID" has the functionality to identify it on the Jabber network.
    optp.add_option("-j", "--jid", dest="jid",
                    help="JID to use")
    optp.add_option("-p", "--password", dest="password",
                    help="password to use")
    optp.add_option("-t", "--to", dest="to",
                    help="JID to send the message to")
    optp.add_option("-m", "--message", dest="message",
                    help="message to send")

    opts, args = optp.parse_args()

    # The connection is validated
    logging.basicConfig(level=opts.loglevel,
                        format='%(levelname)-8s %(message)s')
    # The entry of the parameters to be used is requested
    if opts.jid is None:
        opts.jid = raw_input("Username: ")
    if opts.password is None:
        opts.password = getpass.getpass("Password: ")
    if opts.to is None:
        opts.to = raw_input("Send To: ")
    if opts.message is None:
        opts.message = raw_input("Message: ")
    #The data entered is captured
    usuario = opts.jid
    password = opts.password
    #The connection to the server is made
xmpp = sleekxmpp.ClientXMPP(usuario, password)
xmpp.connect()
xmpp.process(block=False)
   #Message sending module
def chat_send():
    while True:
        mensaje = str(raw_input('> '))   #Message is captured
        if mensaje == 'exit': # To finish writing the message, exit is defined
            break
        xmpp.send_message(mto=opts.to, mbody=mensaje)   #Send Message
    xmpp.disconnect()   #In this point the conection is out.
    sys.exit(1)	   #Out program


def message(msg):
    if msg['type'] in ('chat', 'normal'):    #Message Reception
        print '%s %s' % (msg['body'], msg['from'].bare)   #The name and message that is being received is captured and displayed
try:
    xmpp.send_presence()
    xmpp.get_roster()   #Obtenemos el roster si el usuario existe
    xmpp.register_plugin('xep_0030')  # The server is linked
    xmpp.register_plugin('xep_0004')  # date form
    xmpp.register_plugin('xep_0060')  # Entry
    xmpp.register_plugin('xep_0199') #Application level pings are sent through XML streams, pings can be sent from one client to a server, from one server to another, or end to end.
except IqError as err: # The error is contemplated
    print 'Error %s' % err.iq['error']['condition']
    xmpp.disconnect() #If so, it disconnects
    sys.exit(1)
except IqTimeout:  #A waiting error is contemplated in the connection
    print 'El servidor no responde. Tal vez el usuario no exista'
    xmpp.disconnect()
    sys.exit(1)

print 'Conectado %s' % usuario #The logged in user is shown
xmpp._start_thread('chat_send', chat_send)   #Command to send message
xmpp.add_event_handler('message', message)   #Command to receive the messages
