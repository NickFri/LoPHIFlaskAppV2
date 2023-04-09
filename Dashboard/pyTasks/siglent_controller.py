import Dashboard.service
from Dashboard import socket, time

# remote_ip = Dashboard.service.SiglentIP  # should match the instrument’s IP address
port = 5024  # the port number of the instrument service


def SocketConnect():
    try:
        # create an AF_INET, STREAM socket (TCP)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error:
        print('Failed to create socket.')
        Dashboard.service.SiglentIP = ""
    try:
        # Connect to remote server
        s.connect((Dashboard.service.SiglentIP, port))
    except socket.error:
        print('failed to connect to ip ' + Dashboard.service.SiglentIP)
        Dashboard.service.SiglentIP = ""
    return s


def SocketSend(Sock, cmd):
    try:
        # Send cmd string
        Sock.sendall(cmd)
        Sock.sendall(b'\n')
        time.sleep(0.4)
    except socket.error:
        # Send failed
        print('Send failed')
        Dashboard.service.SiglentIP = ""
    # reply = Sock.recv(4096)
    # return reply


def SocketClose(Sock):
    Sock.close()
    time.sleep(0.4)


#################################
# The idea might be to user input
# ch1/ch2 and to turn on/off
#################################


def ON():
    try:
        s = SocketConnect()
        SocketSend(s, b'C2:OUTP ON')  # Set CH1 ON
        SocketSend(s, b'C1:OUTP ON')  # test
        SocketClose(s)  # Close socket
        return 'Query complete.'
    except Exception as error:
        return error.__str__()


def OFF():
    try:
        s = SocketConnect()
        SocketSend(s, b'C2:OUTP OFF')
        SocketSend(s, b'C1:OUTP OFF')
        SocketClose(s)  # Close socket
        return 'Query complete.'
    except Exception as error:
        return error.__str__()


Invert = 0


def INVERT():
    global Invert
    try:
        s = SocketConnect()
        if Invert == 0:
            SocketSend(s, b'C1:INVT ON')
            Invert = 1
        else:
            SocketSend(s, b'C1:INVT OFF')
            Invert = 0
        SocketClose(s)  # Close socket
        return 'Query complete.'
    except Exception as error:
        return error.__str__()


def SQR():
    # frequency has to change
    try:
        s = SocketConnect()
        SocketSend(s, b'C1:BSWV WVTP,SQUARE')
        SocketSend(s, b'C1:INVT ON')
        SocketSend(s, b'C2:BSWV WVTP,SQUARE')
        SocketClose(s)  # Close socket
        return 'Query complete.'
    except Exception as error:
        return error.__str__()
