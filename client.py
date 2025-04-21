"""
Simple Socket Client
This script creates a client that connects to a socket server,
sends messages, and receives responses.

"""

import socket
import sys
import time

# Client configuration
HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server
BUFFER_SIZE = 1024  # Maximum size of received data
TIMEOUT = 5         # Socket timeout in seconds


def connect_to_server():
    """
    Create a socket and connect to the server.
    
    Returns:
        socket object if connection successful, None otherwise
    """
    try:
        # Create socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set timeout for operations
        client_socket.settimeout(TIMEOUT)
        
        # Connect to server
        print(f"[*] Attempting to connect to {HOST}:{PORT}...")
        client_socket.connect((HOST, PORT))
        print(f"[*] Connected to {HOST}:{PORT}")
        
        return client_socket
        
    except ConnectionRefusedError:
        print(f"[!] Connection refused. Make sure the server is running at {HOST}:{PORT}.")
        return None
    except socket.timeout:
        print(f"[!] Connection timed out. Server at {HOST}:{PORT} is not responding.")
        return None
    except socket.error as e:
        print(f"[!] Socket error: {e}")
        return None
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
        return None


def communicate_with_server(client_socket):
    """
    Handle communication with the server.
    
    Args:
        client_socket: Socket object connected to the server
    """
    try:
        # Receive welcome message
        data = client_socket.recv(BUFFER_SIZE)
        print(f"[*] Server says: {data.decode('utf-8')}")
        
        # Main communication loop
        while True:
            # Get message from user
            message = input("[*] Enter message to send (or 'exit' to quit): ")
            
            # Send message to server
            client_socket.send(message.encode('utf-8'))
            
            # Check if user wants to exit
            if message.lower() == 'exit':
                print("[*] Disconnecting from server...")
                break
                
            # Wait for response
            try:
                response = client_socket.recv(BUFFER_SIZE)
                if not response:
                    print("[!] Server closed the connection.")
                    break
                print(f"[*] Server response: {response.decode('utf-8')}")
            except socket.timeout:
                print("[!] Timeout waiting for server response.")
                break
                
    except ConnectionResetError:
        print("[!] Connection was reset by the server.")
    except socket.error as e:
        print(f"[!] Socket error during communication: {e}")
    except Exception as e:
        print(f"[!] An unexpected error occurred during communication: {e}")
    finally:
        # Clean up the connection
        client_socket.close()
        print("[*] Connection closed")


def main():
    """
    Main function to run the client.
    """
    try:
        # Connect to server
        client_socket = connect_to_server()
        
        # If connection successful, communicate with server
        if client_socket:
            communicate_with_server(client_socket)
        
    except KeyboardInterrupt:
        print("\n[*] Client shutdown initiated by user...")
        sys.exit(0)


if __name__ == "__main__":
    main()