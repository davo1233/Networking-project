"""
    Python 3
    Usage: python3 TCPClient3.py localhost 12000
    coding: utf-8
    
    Author: Wei Song (Tutor for COMP3331/9331)
"""
from socket import *
import sys,os
from threading import Thread

# Server would be running on the same host as Client
if len(sys.argv) != 3:
    print("\n===== Error usage, python3 TCPClient3.py SERVER_IP SERVER_PORT ======\n");
    exit(0)
serverHost = sys.argv[1]
serverPort = int(sys.argv[2])
serverAddress = (serverHost, serverPort)

# define a socket for the client side, it would be used to communicate with the server
clientSocket = socket(AF_INET, SOCK_STREAM)

# build connection with the server and send message to it
clientSocket.connect(serverAddress)


def recv():
    while True:
        receivedMessage = clientSocket.recv(1024).decode()
        print(f'received: {receivedMessage}')
        header = ''
        if len(receivedMessage.split()) > 0:
            header = receivedMessage.split()[0]
        singleArgument = receivedMessage.split(' ', 1)
        doubleArgument = receivedMessage.split(' ', 2)
        # parse the message received from server and take corresponding actions
        if header == "message":
            if singleArgument[1] == 'invalid_user':
                print('Error. Invalid User.')
            elif singleArgument[1] == 'blocked_user':
                print('The following user has blocked you.')
            else:
                finalMsg = doubleArgument[2]
                user = doubleArgument[1]
                print(f'{user}: {finalMsg}')
        elif header == 'whoelse':
            print(len(singleArgument))
            if len(singleArgument) > 1:
                print(f'Who else is online: {singleArgument[1]}')
            else:
                pass
        elif header == 'new_acct':
            print('Welcome!')
        elif header == 'block':
            block_user(doubleArgument)
        elif header == 'unblock':
            unblock_user(doubleArgument)
        elif header == 'presence':
            print('User ' + singleArgument[1])
        elif header == 'whoelsesince':
            whoelsesince(singleArgument)
        elif header == 'logout':
            print('You have been logged out.')
            clientSocket.close()
            os._exit(0)
        elif header == 'broadcast':
            if singleArgument[1] == 'block':
                print('Your message could not be delivered to some recipients.')
            print(singleArgument[1])
        elif header == 'startprivate':
            if singleArgument[1] == 'self':
                print('Error. Cannot start P2P messaging with yourself')
            elif singleArgument[1] == 'block':
                print('User has blocked you.')
            elif singleArgument[1] == 'offline':
                print('User is offline.')
            elif singleArgument[1] == 'not_exist':
                print('User does not exist.')
            elif singleArgument[1] == 'valid':
                response = input(f'{singleArgument[1]} would like to private message, either y or n: ')
                clientSocket.sendall(response.encode())
                recvResp = clientSocket.recv(1024).decode()
                recvResp = recvResp.split()
                if recvResp[0] == 'yes':
                    p2p_thread = Thread(target=p2p_thread)
                    p2p_thread.daemon = True
                    p2p_thread.start()
                elif recvResp[0] == 'no':
                    print('The user rejected your private connection.')
        else:
            print("Command is invalid.")


def p2p_thread():
    p2pSocket = socket(AF_INET, SOCK_STREAM)
    host = '127.0.0.1 '
    port = 0
    p2pAddress = ('127.0.0.1', 0)
    addr = host + str(port)
    clientSocket.sendall(addr.encode())
    p2pSocket.bind(p2pAddress)
    p2pSocket.listen()
    p2pSock,p2pAddr = p2pSocket.accept()
    while True:
        receivedMessage = p2pSock.recv(1024).decode()
        header = receivedMessage.split()[0]
        singleArgument = receivedMessage.split(' ', 1)
        doubleArgument = receivedMessage.split(' ', 2)
        clientSocket.settimeout(doubleArgument[2])
        if header == 'private':
            msg = 'private ' + doubleArgument[2]
            p2pSocket.send(msg.encode())
        elif header == 'stopprivate':
            p2pSocket.close()
            sys.exit()


def block_user(argument):
    if argument[1] == 'invalid_self':
        print('Error. Cannot block self.')
    elif argument[1] == 'invalid_user':
        print('Error. User does not exist.')
    elif argument[1] == 'valid_user':
        print(f'{argument[2]} is blocked.')


def unblock_user(argument):
    if argument[1] == 'invalid_user':
        print('Error. The user does not exist.')
    elif argument[1] == 'unblocked_user':
        print(f'Error. {argument[2]} was not blocked.')
    else:
        print(f'{argument[1]} has been unblocked.')


def whoelsesince(argument):
    if argument[1] == 'empty':
        print('There were no users logged in within the period.')
    elif argument[1] == 'invalid':
        print('Enter the seconds.')
    else:
        print(f'{argument[1]}')


recv_thread = Thread(target=recv)

notLoggedIn = True
while notLoggedIn:
    try:
        # send the credentials of the user to the server
        message = 'login'
        clientSocket.send(message.encode())
        username = input("Enter username: ")
        clientSocket.send(username.encode())
        user_resp = clientSocket.recv(1024).decode()
        if user_resp == 'valid_user':
            # check password of the user
            attempt = 2
            # when the user is in the credentials section enter password
            while True:
                password = input('Enter password: ')
                password = 'password ' + password
                clientSocket.send(password.encode())
                pass_resp = clientSocket.recv(1024).decode()
                if pass_resp == 'valid_pass':
                    notLoggedIn = False
                    print('Welcome!')
                    recv_thread.daemon = True
                    recv_thread.start()
                    break
                elif pass_resp == 'invalid_pass':
                    print(f'Incorrect password. You have {attempt} attempt(s) left.')
                    attempt -= 1
                elif pass_resp.split()[0] == 'block':
                    print(f'You have been blocked from logging in for {pass_resp.split()[1]} seconds.')
                    clientSocket.close()
                    sys.exit()
        elif user_resp == 'blocked':
            print('Your username has been blocked. Please login later.')
            clientSocket.close()
            sys.exit()
        elif user_resp == 'logged_in':
            print('You are already logged in at another location. Please logout and try again.')
            clientSocket.close()
            sys.exit()
        elif user_resp == 'no_user':
            message = 'new_account'
            clientSocket.send(message.encode())
            new_pass = input("This is a new user. Enter a password: ")
            clientSocket.send(new_pass.encode())
            recv_thread.daemon = True
            recv_thread.start()
            break

    except timeout:
        clientSocket.close()
        sys.exit()
        break

while True:
    # receive response from the server
    sendMsg = input("")
    clientSocket.send(sendMsg.encode())


# close the socket
clientSocket.close()
