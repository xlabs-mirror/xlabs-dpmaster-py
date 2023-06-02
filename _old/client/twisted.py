from twisted.internet import reactor, protocol

class DpmasterClient(protocol.Protocol):
    def connectionMade(self):
        print("Connected to server")
        self.transport.write(b"list\r\n")
        print("Sent command: list")

    def dataReceived(self, data):
        response = data.decode().strip()
        print("Received response:")
        print(response)

    def connectionLost(self, reason):
        print("Connection lost:", reason.getErrorMessage())
        reactor.callLater(0, reactor.stop)

class DpmasterClientFactory(protocol.ClientFactory):
    def buildProtocol(self, addr):
        return DpmasterClient()

    def clientConnectionFailed(self, connector, reason):
        print("Connection failed:", reason.getErrorMessage())
        reactor.callLater(0, reactor.stop)

    def clientConnectionLost(self, connector, reason):
        print("Connection lost:", reason.getErrorMessage())
        reactor.callLater(0, reactor.stop)

def stop():
    reactor.removeAll()
    reactor.iterate()
    reactor.stop()

if __name__ == '__main__':
    host = 'localhost'  # Replace with the server's IP or hostname
    port = 20810  # Replace with the server's port

    factory = DpmasterClientFactory()
    reactor.connectTCP(host, port, factory)
    print("Connecting to server...")
    reactor.run()
    stop()