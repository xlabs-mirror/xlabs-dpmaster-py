from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from server.MasterServer import XLabsMasterServer
    from server.ApiServer import XLabsMasterServerAPI

class Console:
    master_server: XLabsMasterServer
    api: XLabsMasterServerAPI
    def __init__(self, master_server: XLabsMasterServer, api: XLabsMasterServerAPI):
        self.master_server = master_server
        self.api = api

    def quit(self):
        self.master_server.stop()
        self.api.stop()
        exit()

    def help(self):
        print('Available commands:')
        print('  help: List all available commands')
        print('  api <endpoint_name> <arg1> <arg2> ...: Call a Flask endpoint with the given arguments')
        print('  quit: Exit the console')

    def call_endpoint(self, endpoint_name, *args):
        endpoint_func = self.api.app.view_functions.get(endpoint_name)
        if endpoint_func is None:
            print(f'Error: Endpoint "{endpoint_name}" not found')
        else:
            with self.api.app.test_request_context():
                endpoint_func(*args)

    def run(self):
        print('Type "help" to see available commands')
        while True:
            user_input = input('> ')
            parts = user_input.split()
            command = parts[0]
            args = parts[1:]

            if command == 'quit':
                self.quit()
                break
            elif command == 'help':
                self.help()
            elif command == 'api':
                if len(args) == 0:
                    print('Error: No endpoint name provided')
                else:
                    endpoint_name = args[0]
                    endpoint_args = args[1:]
                    self.call_endpoint(endpoint_name, *endpoint_args)
            else:
                print(f'Error: Unknown command "{command}"')