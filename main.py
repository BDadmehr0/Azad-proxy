from proxy_server import ProxyServer


def main():
    server = ProxyServer(host="127.0.0.1", port=4500)
    server.run()


if __name__ == "__main__":
    main()
