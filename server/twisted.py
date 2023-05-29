from twisted.internet import reactor, protocol

class DpmasterServer(protocol.Protocol):
    def connectionMade(self):
        print("Client connected:", self.transport.getPeer())

    def dataReceived(self, data):
        command = data.decode().strip()
        print("Received command:", command)
        if command == "list":
            servers = self.factory.getServerList()
            response = "\n".join(servers)
            self.transport.write(response.encode() + b"\r\n")

    def connectionLost(self, reason):
        print("Client disconnected:", self.transport.getPeer())

class DpmasterServerFactory(protocol.Factory):
    def __init__(self):
        self.clients = []

    def buildProtocol(self, addr):
        protocol = DpmasterServer()
        protocol.factory = self
        return protocol

    def getServerList(self):
        # Replace this with your implementation to fetch the server list
        return ["Server 1", "Server 2", "Server 3"]

if __name__ == '__main__':
    factory = DpmasterServerFactory()
    port = 20810
    reactor.listenTCP(port, factory)
    print("Dpmaster server started at port",port)
    reactor.run()
