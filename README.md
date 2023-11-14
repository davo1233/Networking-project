Chat Application Readme
This repository contains a simple client-server chat application implemented in Python 3.7. The application allows users to log in, send messages, and establish peer-to-peer connections.

Client
The client-side implementation involves a two-step login process, where users need to verify their credentials through nested while loops. New users trigger a code block that adds them to the server. After successful login, a new thread is created to receive messages. The message format is determined by the first element in the list resulting from the split() function.

Running the Client
To run the client, execute the following command:

bash
Copy code
python3.7 client.py
Functionality
Login: Users need to go through a two-step verification process.
Message Reception: New threads are created for message reception, and message parsing depends on the specified format.
P2P Connection: Users can send requests to connect to other clients. This runs on a separate thread.
Logout: The exit command triggers the logout() function.
Server
The server-side implementation also parses messages using the first element as a command. Dictionaries are used for each storage type (e.g., user data, blocked users). Online clients are stored as tuples for efficient socket management. The P2P system is currently under development and requires further refinement.

Running the Server
To run the server, execute the following command:

bash
Copy code
python3.7 server.py
Data Structures
User Data: Dictionaries store user information.
Blocked Users: Lists under each key store blocked users.
Online Clients: Tuples store socket information.
Design Considerations
Tradeoffs: No checks for empty strings, and extensive use of while loops may impact performance.
P2P Issues: The P2P system is still in development and may not function as intended.
Future Improvements
Enhance P2P Functionality: Address issues with the P2P system for seamless communication between clients.
Optimize Performance: Consider optimizing the code for better efficiency.
Error Handling: Implement checks for empty strings and enhance error handling.
Feel free to contribute to the development and improvement of this simple chat application!
