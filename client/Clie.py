import socket, ssl, time
class client_ssl():
    def send_hello(self):
        while True:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssl_s = ssl.wrap_socket(s, cert_reqs=ssl.CERT_REQUIRED, ca_certs="certt.pem")
            ssl_s.connect(("127.0.0.1", 10002))
            try:
                print("客户端：")
                msg = input()
                msg = msg.encode(encoding="utf-8")
                ssl_s.send(msg)
                if msg == b"NULL":
                    a=100000
                    for i in range (100000):
                        a=a-1
                    ssl_s.shutdown(socket.SHUT_WR)
                    ssl_s.close()
                    time.sleep(10)
                    break
                data = ssl_s.recv(1024).decode("utf-8")
                print("服务端：")
                print(data)
            finally:
                ssl_s.close()

if __name__ == "__main__":
    client=client_ssl()
    client.send_hello()