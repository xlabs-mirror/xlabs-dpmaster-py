#!/usr/bin/env python3

from MasterServer import XLabsMasterServer
from ApiServer import XLabsMasterServerAPI
from Console import Console

# Usage:
master_server = XLabsMasterServer()
api_server = XLabsMasterServerAPI(master_server)
master_server.run_threaded()
api_server.run_threaded()
console = Console(master_server, api_server)
console.run()