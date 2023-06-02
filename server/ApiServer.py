from __future__ import annotations
from pprint import pprint
from threading import Thread
from flask import Flask, jsonify
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from MasterServer import XLabsMasterServer

class XLabsMasterServerAPI:
    app: Flask
    master_server: XLabsMasterServer
    thread: Thread
    def __init__(self, master_server:XLabsMasterServer):

        self.app = Flask(__name__)
        self.master_server = master_server

        @self.app.route('/servers', methods=['GET'])
        def get_servers():
            server_list = self.master_server.get_server_list()
            servers = [{'domain': server.domain, 'ip': str(server.ip), 'port': server.port} for server in server_list]
            return jsonify(servers)

        @self.app.route('/master/start')
        def start_master_server():
            if not self.master_server.running:
                self.master_server.run_threaded()
                return jsonify({'message': 'UDP server started.'}), 200
            else:
                return jsonify({'message': 'UDP server is already running.'}), 400

        @self.app.route('/master/stop')
        def stop_master_server():
            if self.master_server.running:
                self.master_server.stop()
                return jsonify({'message': 'UDP server stopped.'}), 200
            else:
                return jsonify({'message': 'UDP server is not running.'}), 400

        @self.app.route('/master/restart')
        def restart_master_server(self):
            self.stop_master_server()
            self.start_master_server()
            return jsonify({'message': 'UDP server restarted.'}), 200

    def run_threaded(self):
        self.thread = Thread(target=self.run)
        self.thread.start()

    def run(self):
        # Start the Flask server
        self.app.run()

    def stop(self):
        try:
            self.running = False
            if self.thread: self.thread = None
            return True, None
        except Exception as ex:
            pprint(ex)
            return False, ex