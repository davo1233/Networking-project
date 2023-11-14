# Chat Application Readme

## Overview

This repository contains a simple client-server chat application implemented in Python 3.7. The application allows users to log in, send messages, and establish peer-to-peer connections.

## Client

### Login Process

The client's login process requires users to navigate through two nested while loops for username and password verification. New users trigger a block of code that facilitates server-side user addition.

### Message Handling

Upon successful login, a new thread is spawned to receive messages. The message format is determined by the first element when splitting the message string.

### Running the Client

```bash
python3.7 TCPClient3.py
```
# Features

- **Login**: Two-step verification process.
- **Message Reception**: New threads handle incoming messages, with parsing based on specified formats.
- **P2P Connection**: Clients can request connections to others, running on a separate thread.
- **Logout**: Typing `exit` triggers the `logout()` function.

# Server

## Message Parsing

The server parses messages by splitting them into sections, with the first element used to identify the command. Dictionaries manage different storage types (e.g., user data, blocked users). Online clients are stored as tuples for effective socket management.

## Running the Server

```bash
python3.7 TCPServer3.py
```

## Data Structures

- **User Data**: Dictionaries store user information.
- **Blocked Users**: Lists under each key store blocked users.
- **Online Clients**: Tuples store socket information.

## Design Considerations

- **Tradeoffs**: No checks for empty strings; extensive use of while loops may impact performance.
- **P2P Issues**: The P2P system is under development and may not function as intended.

