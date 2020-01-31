#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# title           : misrcon.py
# description     : Sends commands to Miscreated RCON
# author          : Chris Snow - (aka Spafbi)
# python_version  : 3.5.3
# ==============================================================================
import hashlib
import socket
import time
import xmlrpc.client


class MiscreatedRCON:
    """
    A simple class which may be used for sending commands to a Miscreated RCON.
    I've tried to allow for single commands, multiple commands, and automatic
    retries.
    """

    def __init__(self, **kwargs):
        """
        Args:
            host (str): a FQDN or IP address
            port (int): The RCON listener port
            password (str): The RCON password
        Returns:
            None: But only when one of the required dictionary values is
                  missing
        """

        # assign class variables based on
        self.ip = kwargs.get('host', None)
        self.port = kwargs.get('port', None)
        self.password = kwargs.get('password', None)
        self.server = None

        """
        We can't connect to the server if any of these are false, so return
        None
        """
        if None in (self.ip, self.port, self.password):
            return None

        # assemble the RCON server URL
        server_url = 'http://{0}:{1}/rpc2'.format(self.ip, int(self.port))

        # start the connection
        self.server = xmlrpc.client.ServerProxy(
            server_url, transport=SpecialTransport(), allow_none=True)

    def challenge_rcon(self, **kwargs):
        """
        Authenticate with a Miscreated RCON
        Args:
            retry (int): The number of iterations to attempt
        Returns:
            None: If we couldn't authenticate with the server at all - usually
                  due to a bad password.
            True: If authentication is successful
            Fale: If authentication failed for some other reason - timeout or
                  the RCON interface is already in use elsewhere.
        """
        # attempt to successfully challenge the server
        # make attemps up to 'retry' value
        retry = kwargs.get('retry', 10)
        challege_accepted = 0
        authentication = None
        while challege_accepted < retry:
            """
            attempt to authenticate with the uptime and the password md5
            with : between
            """
            socket.setdefaulttimeout(5)
            try:
                challenge = self.server.challenge()
            except:
                challenge = None
                challege_accepted += 1
                # add a small wait before retry in case RCON is busy
                time.sleep(0.25)
            socket.setdefaulttimeout(None)
            challege_accepted = 10
            authentication = "{0}:{1}".format(challenge, self.password)

        # check to see if we are authorized
        if None in (authentication, challenge):
            return None

        # Check for the proper return from the authentication attempt
        md5 = hashlib.md5(authentication.encode('utf-8')).hexdigest()

        # This forces a 5 second timeout for socket connections
        socket.setdefaulttimeout(5)
        this_auth = self.server.authenticate(md5)
        # Restore default timeout for socket connections
        socket.setdefaulttimeout(None)

        if this_auth == 'authorized':
            return True
        else:
            if 'Illegal Command' not in this_auth:
                '''The following message is displayed on the command line, but
                   is not otherwise handled'''
                print('Authentication failed: {}'.format(this_auth))
            return False

    def multi_rcon(self, **kwargs):
        """
        Send multiple commands to a Miscreated RCON server.
        Args:
            commands (list): A list of commands to be executed
            retry (int): The number of iterations to attempt until successful
        Returns:
            dictionary:
                success (bool): Only false if the commands passed is not a list
                returned (dict): Commands as keys; results as values.
        """
        commands = kwargs.get('commands', None)
        retry = kwargs.get('retry', 10)

        result = dict()
        result['success'] = None
        result['returned'] = dict()
        # test to make sure 'commands' is a list
        if type(commands) is not list:
            result['returned'][0] = 'List not passed for commands'
            result['success'] = False
            return result
        for command in commands:
            result['returned'][command] = self.send_command(command=command,
                                                            retry=retry)
            result['success'] = True
        return result

    def send_command(self, **kwargs):
        """
        Send a command to a Miscreated RCON server
        Args:
            command (str): A command to be executed
            retry (int): The number of iterations to attempt until successful
        Returns:
            dictionary:
                success (bool): Whether or not the command was sent
                                successfully
                returned (str): Value returned from RCON
        """
        command = kwargs.get('command', None)
        retry = kwargs.get('retry', 10)

        status = dict()

        if command is None:
            status['success'] = False
            status['returned'] = 'No command was passed'
            return status

        status['success'] = None
        status['returned'] = dict()
        cmd_list = command.split(' ')
        cmd = cmd_list.pop(0)  # first thing sent is always a command
        # we popped out the 0 before so the rest are the command params
        params = ' '.join(cmd_list) if cmd_list else ''
        success = False
        authenticated = False
        auth_attempt = 0
        cmd_result = None
        challenge = None
        # Try to execute the command until it's successful or exceeds attempts
        while not success:
            if not int(authenticated):  # Time to authenticate (maybe again)
                try:
                    challenge = self.challenge_rcon(retry=retry)
                except OSError as e_error:
                    if 'timed out' in str(e_error):
                        authenticated = False
                if challenge is False:
                    auth_attempt += 1
                    if auth_attempt > 3:
                        status['success'] = False
                        status['returned'] = 'Could not authenticate with RCON'
                        return status
                    time.sleep(0.25)

            if params:
                try:
                    # This forces a 5 second timeout for socket connections
                    socket.setdefaulttimeout(5)
                    cmd_result = self.server.__getattr__(cmd)(params).strip()

                    # Restore default timeout for socket connections
                    socket.setdefaulttimeout(None)
                except OSError as except_e:
                    if 'timed out' in str(except_e):
                        authenticated = False
            else:
                try:
                    # This forces a 5 second timeout for socket connections
                    socket.setdefaulttimeout(5)
                    cmd_result = self.server.__getattr__(cmd)().strip()

                    # Restore default timeout for socket connections
                    socket.setdefaulttimeout(None)
                except OSError as except_e:
                    authenticated = False

            if cmd_result in ('[Whitelist] Invalid command: challenge', None):
                success = False
            else:
                success = True

        bad_results_11 = ('[Whitelist]')

        if cmd_result[:11] in bad_results_11:
            status['success'] = False
        else:
            status['success'] = success

        status['returned'] = cmd_result

        return status


class SpecialTransport(xmlrpc.client.Transport):
    """
    Summary: XMLRPC client transport used for chatting with a Miscreated RCON.

    Description: This is a very simple client for communicating with a
                 Miscreated server using RCON.
    """

    user_agent = 'spafbi-misrcon'

    def send_content(self, connection, request_body):
        """
        Summary: Method used to send content.

        Description: This method sends content to an Miscreated RCON.
        """
        connection.putheader("Connection", "keep-alive")
        connection.putheader("Content-Type", "text/xml")
        connection.putheader("Content-Length", str(len(request_body)))
        connection.endheaders()
        if request_body:
            connection.send(request_body)


def main():
    """
    Summary: Default method if this modules is run as __main__.

    Description: This is the default method utilized for handling of
                 command-line usage of this application.
    """
    import argparse
    from os.path import basename

    # Just grabbing this script's filename
    prog = basename(__file__)
    description = """Spafbi's RCON module and command-line utility:\r
                     {0} may be used as either a Python 3 module, or as a
                     standalone command-line utility.""".format(prog)

    # Set up argparse to help people use this as a CLI utility
    parser = argparse.ArgumentParser(prog=prog, description=description)

    parser.add_argument('-s', '--server', type=str, required=False,
                        help="""Either a FQDN or IP address of the game server
                             - defaults to localhost""", default="127.0.0.1")
    parser.add_argument('-r', '--rcon-port', type=int, required=False,
                        help="""RCON port: Will be overriden if a game port is
                             specified - defaults to 64094""", default=64094)
    parser.add_argument('-g', '--game-port', type=int, required=False,
                        help="""Game port: Optional - If specified the RCON
                                port will be calculated from this value -
                                defaults to 64090""", default=64090)
    parser.add_argument('-p', '--password', type=str, required=True,
                        help="""The RCON password : This is a required
                                argumment""")
    parser.add_argument('-c', '--command', metavar='"COMMAND"', type=str,
                        required=False,
                        help="""An RCON command: Commands containing spaces or
                                special characters will need to be in quotes or
                                otherwise properly escaped.
                                Server status will be returned if no command is
                                specified.""", default="status")

    # Parse our arguments!
    args = parser.parse_args()

    '''If a non-default game port is specified then calculate the proper RCON
       listener port'''
    if args.game_port == 64090:
        port = args.rcon_port
    else:
        port = args.game_port + 4

    # Set up RCON class
    this_rcon = MiscreatedRCON(host=args.server,
                               password=args.password,
                               port=port)
    try:
        result = this_rcon.send_command(command=args.command)
    except:
        result = {"success": False,
                  "returned": None}

    if result['success']:
        print(result['returned'])
        exit(0)
    else:
        print("Oops - something went wrong")
        exit(1)


if __name__ == '__main__':
    main()
