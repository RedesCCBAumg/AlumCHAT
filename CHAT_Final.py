import sleekxmpp # This is a library that calls a previously installed version of sleekxmpp in python
import sys
import getpass #This module allows in this case to request a password from the user without reflecting it on the screen.
import logging #The login module of this library allows us to track an event within a software. For example, log an error message.

from optparse import OptionParser #The OptParse module makes it easy to write command line tools.
from sleekxmpp.exceptions import IqError, IqTimeout # can generate IqError and IqTimeout exceptions

if sys.version_info < (3, 0):
    from sleekxmpp.util.misc_ops import setdefaultencoding
    setdefaultencoding('utf8')
else:
    raw_input = input

#CHAT LOGIN
if __name__ == '__main__':
    optp = OptionParser() # Setup the command line arguments
    optp.add_option('-q', '--quiet', help='set logging to ERROR', # Output verbosity options.
                    action='store_const', dest='loglevel',
                    const=logging.ERROR, default=logging.INFO)
    optp.add_option('-d', '--debug', help='set logging to DEBUG',
                    action='store_const', dest='loglevel',
                    const=logging.DEBUG, default=logging.INFO)
    optp.add_option('-v', '--verbose', help='set logging to COMM',
                    action='store_const', dest='loglevel',
                    const=5, default=logging.INFO)
    optp.add_option("-j", "--jid", dest="jid",  # The Jabber ID or "JID" has the functionality to identify it on the Jabber network.
                    help="JID to use")
    optp.add_option("-p", "--password", dest="password",
                    help="password to use")

    opts, args = optp.parse_args()
    logging.basicConfig(level=opts.loglevel,  # The module is used for the account login.Setup logging
                        format='%(levelname)-8s %(message)s')
    # At this point both the user and the password are requested
    if opts.jid is None:
        opts.jid = raw_input("USERNAME : ")
    if opts.password is None:
        opts.password = getpass.getpass("PASSWORD : ")

#CLASS TO REGISTER A USER
class Menu():  # In this part a small menu with the options is shown on the screen
    """Funcion que Muestra el Menu"""
    print """    *****************
        CHAT MENU
    *****************
    ------------
    1) User Register
    2) Delete User
    3) Exit"""

# USER REGISTRATION CLASS
class Chat():
        global xmpp
        Menu()
        opc = int(input("Select Option\n")) #It asks on screen to say an option
        while (opc > 0 and opc < 5): #It is parameterized to be greater than 0 and less than 5
            if (opc == 1): #If number 1 is set, a code block is activated

                class RegisterUser(sleekxmpp.ClientXMPP):

                    def __init__(self, jid, password):
                        sleekxmpp.ClientXMPP.__init__(self, jid, password)

                        self.add_event_handler("session_start", self.start, threaded=True)

                        self.add_event_handler("register", self.register, threaded=True)

                    def start(self, event):

                        # Process the session_start event.

                        self.send_presence()
                        self.get_roster()

                        # We're only concerned about registering
                        self.disconnect()

                    def register(self, iq):

                        resp = self.Iq()
                        resp['type'] = 'set'
                        resp['register']['username'] = self.boundjid.user
                        resp['register']['password'] = self.password

                        try:
                            resp.send(now=True) #Account details are requested to register
                            logging.info("La cuenta creada es %s!" % self.boundjid)
                        except IqError as e:
                            logging.error("No se pudo registrar la cuenta: %s" %
                                          e.iq['error']['text'])
                            self.disconnect()
                        except IqTimeout: #If the account cannot be registered, show the following
                            logging.error("El servidor no responde.")
                            self.disconnect()

                if __name__ == '__main__':
                    optp = OptionParser()
                    # Control of the use of words that can be entered
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

                    opts, args = optp.parse_args()

                    # Setup logging.
                    logging.basicConfig(level=opts.loglevel,
                                        format='%(levelname)-8s %(message)s')
                    # Proceso de captura de datos
                    if opts.jid is None:
                        opts.jid = raw_input("Username: ")
                    if opts.password is None:
                        opts.password = getpass.getpass("Password: ")

                    # User and add-ons are registered
                    xmpp = RegisterUser(opts.jid, opts.password)
                    xmpp.register_plugin('xep_0030')  # The server is linked
                    xmpp.register_plugin('xep_0004')  # Data forms
                    xmpp.register_plugin('xep_0066')  # Irrelevant data
                    xmpp.register_plugin('xep_0077')  # Data register
                    xmpp['xep_0077'].force_registration = True # Affidative registration validation
                    #Possible states are contained
                    if xmpp.connect():
                        xmpp.process(block=True)
                        print("Done")
                    else:
                        print("Unable to connect.")

                    opc = int(input("Select Option\n"))
            # Si se ingresa el numero 2 se activa la siguente tarea.
            elif (opc == 2):
                if __name__ == '__main__':

                    optp = OptionParser()
                    # Control of the use of words that can be entered
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
                    opts, args = optp.parse_args()
                        #User load
                    logging.basicConfig(level=opts.loglevel,
                                        format='%(levelname)-8s %(message)s')
                    if opts.jid is None:
                        opts.jid = raw_input("Username: ") #Account parameters to be deleted are requested
                    if opts.password is None:
                        opts.password = getpass.getpass("Password: ")

                usuario = opts.jid
                password = opts.password
                #It connects to the server and executes the removal
                xmpp = sleekxmpp.ClientXMPP(usuario, password)
                xmpp.connect()
                xmpp.process(block=False)
                xmpp.register_plugin('xep_0077')
                try:
                    xmpp.plugin['xep_0077'].cancel_registration(ifrom=xmpp.boundjid.full)  # The operation is successfully removed and show
                    print 'Cuenta eliminada %s' % xmpp.boundjid
                except IqError as e: #The error is contemplated and shown if it occurs
                    print 'Error: %s' % e.iq['error']['text']
                    xmpp.disconnect()
                    sys.exit(1)
                except IqTimeout: #If the server does not respond, it is indicated
                    print 'El servidor no responde'
                    xmpp.disconnect()
                    #The last option upon entering 3 exits the program
                opc = int(input("Select Option\n"))

            elif (opc == 3):
                sys.exit(1)