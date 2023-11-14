"""
    Sample code for Multi-Threaded Server
    Python 3
    Usage: python3 TCPserver3.py localhost 12000
    coding: utf-8
    
    Author: Wei Song (Tutor for COMP3331/9331)
"""
import socket
import threading
from socket import *
from time import *
from threading import Thread
import sys, select

# acquire server host and port from command line parameter
if len(sys.argv) != 4:
    print("\n===== Error usage, python3 TCPServer3.py SERVER_PORT BLOCK_DURATION TIMEOUT ======\n");
    exit(0);
serverHost = "127.0.0.1"
serverPort = int(sys.argv[1])
serverBlockDuration = int(sys.argv[2])
serverTimeout = int(sys.argv[3])
serverAddress = (serverHost, serverPort)

# define socket for the server side and bind address
serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.bind(serverAddress)
blockDurationList = {}
blockList = {}
onlineClients = {}
offlineMessages = {}
credentials = {}
loginHistory = {}

"""
    Define multi-thread class for client
    This class would be used to define the instance for each connection from each client
    For example, client-1 makes a connection request to the server, the server will call
    class (ClientThread) to define a thread for client-1, and when client-2 make a connection
    request to the server, the server will call class (ClientThread) again and create a thread
    for client-2. Each client will be runing in a separate therad, which is the multi-threading
"""


# used to process the credentials file
def parse_credentials():
    with open('credentials.txt') as f:
        lines = f.readlines()
    for line in lines:
        key, value = line.split()
        credentials[key] = value


def send_offline_message():
    for user in offlineMessages.keys():
        for recipient, msg in offlineMessages[user]:
            if recipient in onlineClients.keys():
                (recvClientAddr, recvClientSock) = onlineClients[recipient]
                sentMsg = 'message ' + msg
                recvClientSock.sendall(sentMsg.encode())
                offlineMessages[user].remove((recipient, msg))


def remove_locked_out_users():
    for k in list(blockDurationList.keys()):
        if time() >= blockDurationList.get(k):
            del blockDurationList[k]


def is_float(value):
    try:
        float(value)
        return True
    except:
        return False


parse_credentials()
loginHistory['startServer'] = time()


class ClientThread(Thread):
    def __init__(self, clientAddress, clientSocket):
        Thread.__init__(self)
        self.clientAddress = clientAddress
        self.clientSocket = clientSocket
        self.clientAlive = False
        self.username = ''
        self.logout_message = 'logout'
        self.login_attempt = 0
        print("===== New connection created for: ", clientAddress)
        self.clientAlive = True

    def run(self):

        clientSocket.settimeout(serverTimeout)
        while self.clientAlive:
            try:
                # handle messages from the client
                message = self.clientSocket.recv(1024).decode()
                message = message.split()
                remove_locked_out_users()
                if message[0] == 'login':
                    print("[recv] New login request")
                    self.process_user()
                elif message[0] == 'password':
                    if self.login_attempt <= 2:
                        self.process_password(message[1])
                elif message[0] == 'new_account':
                    self.add_user()
                elif message[0] == 'whoelse':
                    whoelse = 'whoelse'
                    if onlineClients.keys() is None:
                        whoelse = 'whoelse empty'
                        self.clientSocket.send(whoelse.encode())
                        return
                    for key in onlineClients.keys():
                        hasBlockedUser = False
                        if blockList.get(key) is not None:
                            for i in blockList[key]:
                                if i == self.username:
                                    hasBlockedUser = True
                                    break
                        if not hasBlockedUser and key != self.username:
                            whoelse = 'whoelse ' + '\n'.join(key)
                    self.clientSocket.send(whoelse.encode())
                elif message[0] == 'whoelsesince':
                    seconds = message[1]
                    if not is_float(seconds):
                        msg = 'whoelsesince invalid'
                        self.clientSocket.sendall(msg.encode())
                    else:
                        self.whoelsesince(seconds)
                elif message[0] == 'broadcast':
                    self.message_broadcasts(message[1:])
                elif message[0] == 'message':
                    self.message(message)
                elif message[0] == self.logout_message:
                    self.clientAlive = False
                    del onlineClients[self.username]
                    message = self.logout_message
                    self.clientSocket.send(message.encode())
                    self.presence_broadcasts(self.logout_message)
                elif message[0] == 'block':
                    blocked_user = message[1]
                    self.blacklist(blocked_user)
                elif message[0] == 'unblock':
                    unblocked_user = message[1]
                    self.reverseBlacklist(unblocked_user)
                elif message[0] == 'startprivate':
                    self.start_private(message[1])
                else:
                    message = 'invalid_command'
                    self.clientSocket.send(message.encode())
                send_offline_message()
            except timeout:
                print('The user has been kicked')
                self.clientAlive = False
                msg = 'logout ' + self.username
                self.clientSocket.sendall(msg.encode())
                self.clientSocket.close()
                if onlineClients.keys() is not None:
                    del onlineClients[self.username]

    # used to process the login details
    def process_user(self):
        user_data = self.clientSocket.recv(1024).decode()
        # when the user is in the credentials file and not stopped from logging in login
        if user_data in credentials.keys() and user_data not in blockDurationList \
                and user_data not in onlineClients.keys():
            user_message = 'valid_user'
            self.clientSocket.send(user_message.encode())
            self.username = user_data
        # if blocked stop user from logging in
        elif user_data in blockDurationList:
            user_message = 'blocked'
            self.clientSocket.send(user_message.encode())
        # if user is logged in from another client tell client they are logged in
        elif user_data in onlineClients.keys():
            user_message = 'logged_in'
            self.clientSocket.send(user_message.encode())
        # if the user does not exist run this block of code
        else:
            user_message = 'no_user'
            self.username = user_data
            self.clientSocket.send(user_message.encode())

    # process the passwords of the user
    def process_password(self, pass_data):
        # if password matches the user login
        if pass_data == credentials[self.username]:
            onlineClients[self.username] = (self.clientAddress, self.clientSocket)
            loginHistory[self.username] = time()
            pass_message = 'valid_pass'
            self.clientSocket.send(pass_message.encode())
            self.presence_broadcasts('login')
        # if the user fails to login run this block of code
        elif self.login_attempt < 2:
            self.login_attempt += 1
            pass_message = 'invalid_pass'
            self.clientSocket.send(pass_message.encode())
        # if the user attempts to login the 3rd time and fails the client exits
        elif self.login_attempt == 2:
            header = 'block'
            duration = str(serverBlockDuration)
            block = header + ' ' + duration
            self.clientSocket.send(block.encode())
            self.block_duration()
            self.clientSocket.close()

    # if user does not exist in the credentials then add a new user
    def add_user(self):
        new_pass_data = self.clientSocket.recv(1024).decode()
        new_credential = self.username + ' ' + new_pass_data
        f = open("credentials.txt", "a")
        f.write('\n' + new_credential)
        f.close()
        credentials[self.username] = new_pass_data
        onlineClients[self.username] = (self.clientAddress, self.clientSocket)
        loginHistory[self.username] = time()
        message = 'new_acct'
        self.clientSocket.send(message.encode())

    # blocks the user from logging in again based on the duration set at the start
    def block_duration(self):
        blockDurationList[self.username] = time() + serverBlockDuration

    # send messages from the client that wants to send to the target client
    def message(self, message):
        # if the user has been blocked return user is blocked
        if blockList.get(self.username) is not None:
            for blocked_user in blockList.get(self.username):
                if message[1] == blocked_user:
                    msg = 'message blocked_user'
                    self.clientSocket.sendall(msg.encode())
        # if the receiving client is offline then run the offline_messages function
        elif message[1] in credentials.keys() and message[1] not in onlineClients.keys():
            self.offline_messages(message)
        # if the receiving client is online send the message to the client
        elif message[1] in onlineClients.keys():
            recvClientAddr, recvClientSock = onlineClients.get(message[1])
            message[1] = self.username
            msgClient = ' '.join(message)
            recvClientSock.send(msgClient.encode())
        # if the user does not exist in the credentials dictionary
        # return invalid user message to the sending client
        elif message[1] not in credentials.keys():
            message = 'message invalid_user'
            self.clientSocket.sendall(message.encode())

    # stores offline messages sent by sent client to the receiving client
    def offline_messages(self, message):
        target_user = message[1]
        offlineMessage = ' '.join(message[2:])
        if target_user not in onlineClients.keys() and target_user in credentials.keys() \
                and offlineMessages.get(self.username) is not None:
            offlineMessages[self.username].append((target_user, offlineMessage))
        else:
            offlineMessages[self.username] = [(target_user, offlineMessage)]

    # broadcast clients based on whether they are logging in or out
    def presence_broadcasts(self, presence_type):
        for user in onlineClients.keys():
            if presence_type == 'login' and self.username != user:
                (addr, sock) = onlineClients.get(user)
                msg = 'presence ' + self.username + ' has logged in.'
                sock.sendall(msg.encode())
            elif presence_type == 'logout' and self.username != user:
                (addr, sock) = onlineClients.get(user)
                msg = 'presence ' + self.username + ' has logged out.'
                sock.send(msg.encode())

    # broadcast messages sent by the client to everyone
    def message_broadcasts(self, message):
        message = 'broadcast ' + self.username + ': ' + ' '.join(message)
        hasBlockedUsers = False
        for user, client in onlineClients.items():
            canSend = True
            (addr, sock) = client
            if user != self.username:
                if user in blockList.keys():
                    blockedList = blockList.get(user)
                    for i in blockedList:
                        if i == self.username:
                            hasBlockedUsers = True
                            canSend = False
                if canSend:
                    sock.sendall(message.encode())
        if hasBlockedUsers:
            msg = 'broadcast block'
            self.clientSocket.sendall(msg.encode())

    def whoelsesince(self, seconds):
        whoLoggedIn = ['whoelsesince']
        # shows who has been online since the start of the server
        if time() <= loginHistory['startServer'] + float(seconds):
            for user in loginHistory.keys():
                if user != 'startServer':
                    hasBlockedUser = False
                    if blockList.get(user) is not None:
                        for i in blockList[user]:
                            if i == self.username:
                                hasBlockedUser = True
                                break
                    if user != self.username and hasBlockedUser is False:
                        print(f'login history user {user}')
                        whoLoggedIn.append(user + '\n')
            whoLoggedIn = ' '.join(whoLoggedIn)
            self.clientSocket.sendall(whoLoggedIn.encode())
            if len(whoLoggedIn) == 12:
                msg = 'whoelsesince ' + 'empty'
                self.clientSocket.sendall(msg.encode())
            return
        for user in loginHistory.keys():
            if time() <= loginHistory[user] + float(seconds):
                if user != 'startServer':
                    hasBlockedUser = False
                    if blockList.get(user) is not None:
                        for i in blockList[user]:
                            if i == self.username:
                                hasBlockedUser = True
                                break
                    if user != self.username and hasBlockedUser is False:
                        whoLoggedIn.append(user + '\n')
        whoLoggedIn = ' '.join(whoLoggedIn)
        if len(whoLoggedIn) == 12:
            msg = 'whoelsesince ' + 'empty'
            self.clientSocket.sendall(msg.encode())
        else:
            self.clientSocket.sendall(whoLoggedIn.encode())

    def blacklist(self, blocked_user):
        if blocked_user in credentials.keys() and blocked_user != self.username:
            if blockList.get(self.username) is not None and blocked_user not in blockList.get(self.username):
                blockList[self.username].append(blocked_user)
                msg = 'block valid_user ' + blocked_user
                self.clientSocket.sendall(msg.encode())
            elif blocked_user in credentials.keys():
                blockList[self.username] = [blocked_user]
                msg = 'block valid_user ' + blocked_user
                self.clientSocket.sendall(msg.encode())
        elif self.username == blocked_user:
            msg = 'block invalid_self'
            self.clientSocket.sendall(msg.encode())
        else:
            msg = 'block invalid_user'
            self.clientSocket.sendall(msg.encode())
        print(blockList)

    def reverseBlacklist(self, blocked_user):
        userBlockList = blockList.get(self.username)
        if userBlockList is not None:
            for item in userBlockList:
                if item == blocked_user:
                    userBlockList.remove(item)
                    msg = 'unblock ' + blocked_user
                    self.clientSocket.sendall(msg.encode())
                    return
            if blocked_user in credentials.keys():
                msg = 'unblock unblocked_user ' + blocked_user
                self.clientSocket.sendall(msg.encode())
            else:
                msg = 'unblock invalid_user'
                self.clientSocket.sendall(msg.encode())

    def start_private(self, user):
        if user not in credentials.keys():
            msg = 'startprivate not_exist'
        elif blockList.get(user) is not None:
            for i in blockList[user]:
                if i == self.username:
                    msg = 'startprivate block'
                    self.clientSocket.sendall(msg.encode())
                    break
        elif user == self.username:
            msg = 'startprivate self'
            self.clientSocket.sendall(msg.encode())
        elif user not in onlineClients.keys():
            msg = 'startprivate offline'
            self.clientSocket.sendall(msg.encode())
        elif user in onlineClients.keys():
            (clientAddr, clientSock) = onlineClients[user]
            msg = 'startprivate valid ' + str(serverTimeout)
            self.clientSocket.sendall(msg.encode())
            recvClientResp = clientSock.recv(1024).decode()
            if recvClientResp == 'y':
                p2pAddr = clientSock.recv(1024)
                address = p2pAddr.split(' ')
                addr = (address[0],address[1])
                self.clientSocket.connect(addr)
                confirmMsg = 'yes ' + clientAddr
                self.clientSocket.sendall(confirmMsg.encode())
            elif recvClientResp == 'n':
                confirmMsg = 'no ' + user
                self.clientSocket.sendall(confirmMsg.encode())


print("\n===== Server is running =====")

print("===== Waiting for connection request from clients...=====")

while True:
    serverSocket.listen()
    clientSocket, clientAddress = serverSocket.accept()
    clientThread = ClientThread(clientAddress, clientSocket)
    clientThread.start()
