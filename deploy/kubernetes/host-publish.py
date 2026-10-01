"""Publish a NodePort onto this container's listen port.

The minikube node address is on a container network. This process runs on that
network and is published to the host, so the browser can open the Service
without kubectl port-forward.
"""

import os
import socket
import threading

listen_port = int(os.environ.get("LISTEN_PORT", "8085"))
node_ip = os.environ["NODE_IP"]
node_port = int(os.environ["NODE_PORT"])


def _pump(source, destination):
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            destination.sendall(data)
    except OSError:
        pass
    finally:
        for sock, how in (
            (source, socket.SHUT_RD),
            (destination, socket.SHUT_WR),
        ):
            try:
                sock.shutdown(how)
            except OSError:
                pass


def _handle(client):
    try:
        remote = socket.create_connection((node_ip, node_port), timeout=10)
    except OSError:
        client.close()
        return
    remote.settimeout(None)
    client.settimeout(None)
    reverse = threading.Thread(target=_pump, args=(remote, client), daemon=True)
    reverse.start()
    _pump(client, remote)
    client.close()
    remote.close()


server = socket.create_server(("0.0.0.0", listen_port), reuse_port=False)
while True:
    connection, _address = server.accept()
    threading.Thread(target=_handle, args=(connection,), daemon=True).start()
