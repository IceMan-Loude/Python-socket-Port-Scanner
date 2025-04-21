"""
Simple Socket Server
This script creates a basic socket server that listens for connections,
accepts messages from clients, and sends responses back.

Author: [Your Name]
Date: April 20, 2025
"""

import socket
import threading
import sys
import time

# Server configuration
HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)
BUFFER_SIZE = 1024  # Maximum size of received data
MAX_CONNECTIONS = 5  # Maximum number of queued connections


def handle_client(client_socket, address):
    """
    Handle communication with a connected client.
    
    Args:
        client_socket: The socket object connected to the client
        address: The address (IP, port) of the connected client
    """
    print(f"[*] Connection established with {address[0]}:{address[1]}")
    
    try:
        # Send welcome message
        welcome_msg = "Welcome to the server! Type 'exit' to disconnect."
        client_socket.send(welcome_msg.encode('utf-8'))
        
        while True:
            # Receive data from client
            data = client_socket.recv(BUFFER_SIZE)
            
            # If no data or client sends 'exit', break the loop
            if not data or data.decode('utf-8').strip().lower() == 'exit':
                print(f"[*] Client {address[0]}:{address[1]} disconnected.")
                break
                
            # Process received message
            message = data.decode('utf-8')
            print(f"[*] Received from {address[0]}:{address[1]}: {message}")
            
            # Prepare and send response
            response = f"Server received: {message}"
            client_socket.send(response.encode('utf-8'))
            
    except ConnectionResetError:
        print(f"[!] Connection with {address[0]}:{address[1]} was reset by the client.")
    except Exception as e:
        print(f"[!] Error handling client {address[0]}:{address[1]}: {e}")
    finally:
        # Clean up the connection
        client_socket.close()


def start_server():
    """
    Initialize the server socket, listen for and accept client connections.
    Each client connection is handled in a separate thread.
    """
    # Create server socket
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Allow port reuse (helps with binding to recently closed sockets)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Bind socket to host and port
        server.bind((HOST, PORT))
        
        # Start listening for connections
        server.listen(MAX_CONNECTIONS)
        print(f"[*] Server listening on {HOST}:{PORT}")
        
        try:
            while True:
                # Accept client connection
                client_socket, address = server.accept()
                
                # Start a new thread to handle the client
                client_handler = threading.Thread(
                    target=handle_client,
                    args=(client_socket, address)
                )
                client_handler.daemon = True
                client_handler.start()
                print(f"[*] Active connections: {threading.active_count() - 1}")
                
        except KeyboardInterrupt:
            print("\n[*] Shutting down server...")
        finally:
            # Clean up the server socket
            server.close()
            
    except socket.error as e:
        print(f"[!] Socket error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        print("\n[*] Server shutdown initiated by user...")
        time.sleep(1)
        print("[*] Server shutdown complete.")
        sys.exit(0)