import socket
import os
import threading
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import zipfile # For zipping/unzipping folders
import shutil  # For removing directories

# --- Configuration ---
PORT = 12345
BUFFER_SIZE = 4096 # How much data to receive at a time
MAX_CONNECTIONS = 5 # Max concurrent connections for the server

class FileTransferApp:
    def __init__(self, master):
        self.master = master
        master.title("ShareIt")
        master.geometry("500x450") # Increased height for new buttons
        master.resizable(False, False)

        self.server_thread = None
        self.client_thread = None
        self.selected_item_path = "" # Path to the file or folder selected for sending
        self.item_to_send_type = None # 'file' or 'folder'

        # Main Frame
        self.main_frame = tk.Frame(master, padx=20, pady=20)
        self.main_frame.pack(expand=True)

        self.title_label = tk.Label(self.main_frame, text="ShareIt", font=("Arial", 28, "bold"))
        self.title_label.pack(pady=20)

        self.server_button = tk.Button(self.main_frame, text="Start Server (Send Files/Folders)", command=self.show_server_ui,
                                       font=("Arial", 14), width=30, height=2, bg="#4CAF50", fg="white", relief=tk.RAISED, bd=3,
                                       activebackground="#45a049", activeforeground="white")
        self.server_button.pack(pady=10)

        self.client_button = tk.Button(self.main_frame, text="Start Client (Receive Files/Folders)", command=self.show_client_ui,
                                       font=("Arial", 14), width=30, height=2, bg="#2196F3", fg="white", relief=tk.RAISED, bd=3,
                                       activebackground="#0b7dda", activeforeground="white")
        self.client_button.pack(pady=10)

        # Server UI Frame
        self.server_frame = tk.Frame(master, padx=20, pady=20)
        self.server_ip_label = tk.Label(self.server_frame, text="", font=("Arial", 12))
        self.server_ip_label.pack(pady=10)

        self.file_select_button = tk.Button(self.server_frame, text="Select File to Send", command=lambda: self.select_item_to_send('file'), font=("Arial", 12))
        self.file_select_button.pack(pady=5)

        self.folder_select_button = tk.Button(self.server_frame, text="Select Folder to Send", command=lambda: self.select_item_to_send('folder'), font=("Arial", 12))
        self.folder_select_button.pack(pady=5)

        self.selected_item_label = tk.Label(self.server_frame, text="No item selected", font=("Arial", 10), wraplength=400)
        self.selected_item_label.pack(pady=5)

        self.server_status_label = tk.Label(self.server_frame, text="Waiting for connection...", font=("Arial", 12))
        self.server_status_label.pack(pady=10)
        self.server_progress_bar = ttk.Progressbar(self.server_frame, orient="horizontal", length=300, mode="determinate")
        self.server_progress_bar.pack(pady=10)
        self.server_back_button = tk.Button(self.server_frame, text="Back to Main", command=self.show_main_ui)
        self.server_back_button.pack(pady=20)

        # Client UI Frame
        self.client_frame = tk.Frame(master, padx=20, pady=20)
        self.ip_entry_label = tk.Label(self.client_frame, text="Server IP Address:", font=("Arial", 12))
        self.ip_entry_label.pack(pady=10)
        self.server_ip_entry = tk.Entry(self.client_frame, width=30, font=("Arial", 12))
        self.server_ip_entry.pack(pady=5)
        self.connect_button = tk.Button(self.client_frame, text="Connect and Receive", command=self.start_client_thread, font=("Arial", 12))
        self.connect_button.pack(pady=10)
        self.client_status_label = tk.Label(self.client_frame, text="Enter server IP and connect...", font=("Arial", 12))
        self.client_status_label.pack(pady=10)
        self.client_progress_bar = ttk.Progressbar(self.client_frame, orient="horizontal", length=300, mode="determinate")
        self.client_progress_bar.pack(pady=10)
        self.client_back_button = tk.Button(self.client_frame, text="Back to Main", command=self.show_main_ui)
        self.client_back_button.pack(pady=20)

        master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def show_main_ui(self):
        self.server_frame.pack_forget()
        self.client_frame.pack_forget()
        self.main_frame.pack(expand=True)

    def show_server_ui(self):
        self.main_frame.pack_forget()
        self.client_frame.pack_forget()
        self.server_frame.pack(expand=True)
        self.server_ip_label.config(text=f"Your IP: {self.get_local_ip()}\nListening on Port: {PORT}")
        self.server_status_label.config(text="Waiting for connection...")
        self.server_progress_bar['value'] = 0
        self.selected_item_path = ""
        self.item_to_send_type = None
        self.selected_item_label.config(text="No item selected")
        self.start_server_thread()

    def show_client_ui(self):
        self.main_frame.pack_forget()
        self.server_frame.pack_forget()
        self.client_frame.pack(expand=True)
        self.client_status_label.config(text="Enter server IP and connect...")
        self.client_progress_bar['value'] = 0

    def get_local_ip(self):
        """
        Attempts to get the local IP address of the machine.
        This works by connecting to an external server (which doesn't actually send data)
        and then checking the IP of the local end of the socket.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1' # Fallback to localhost if no network connection
        finally:
            s.close()
        return IP

    def select_item_to_send(self, item_type):
        """Prompts user to select a file or a folder."""
        if item_type == 'file':
            path = filedialog.askopenfilename()
        elif item_type == 'folder':
            path = filedialog.askdirectory()
        else:
            return

        if path:
            self.selected_item_path = path
            self.item_to_send_type = item_type
            self.selected_item_label.config(text=f"Selected {item_type}: {os.path.basename(path)}")
        else:
            self.selected_item_path = ""
            self.item_to_send_type = None
            self.selected_item_label.config(text="No item selected")

    def start_server_thread(self):
        if self.server_thread and self.server_thread.is_alive():
            self.server_status_label.config(text="Server already running...")
            return

        def server_task():
            SERVER_HOST = self.get_local_ip()
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            try:
                server_socket.bind((SERVER_HOST, PORT))
                server_socket.listen(MAX_CONNECTIONS)
                self.master.after(0, self.server_status_label.config, {"text": f"Server listening on {SERVER_HOST}:{PORT}\nWaiting for connection..."})

                while True:
                    client_socket, client_address = server_socket.accept()
                    self.master.after(0, self.server_status_label.config, {"text": f"Accepted connection from {client_address[0]}:{client_address[1]}"})

                    if not self.selected_item_path or not os.path.exists(self.selected_item_path):
                        self.master.after(0, self.server_status_label.config, {"text": "Please select a file or folder to send before client connects."})
                        client_socket.sendall(b"ERROR:NO_ITEM_SELECTED_ON_SERVER")
                        client_socket.close()
                        continue

                    # Start a new thread to handle item sending for this client
                    send_thread = threading.Thread(target=self._send_item, args=(client_socket, self.selected_item_path, self.item_to_send_type))
                    send_thread.start()
            except OSError as e:
                if e.errno == 98: # Address already in use
                    self.master.after(0, self.server_status_label.config, {"text": f"Error: Address {SERVER_HOST}:{PORT} already in use. Choose another port or restart."})
                else:
                    self.master.after(0, self.server_status_label.config, {"text": f"Server error: {e}"})
            except Exception as e:
                self.master.after(0, self.server_status_label.config, {"text": f"Server experienced an error: {e}"})
            finally:
                server_socket.close()
                self.master.after(0, self.server_status_label.config, {"text": "Server stopped."})

        self.server_thread = threading.Thread(target=server_task)
        self.server_thread.daemon = True # Allows the thread to exit with the main program
        self.server_thread.start()


    def _send_item(self, client_socket, item_path, item_type):
        """Sends a file or a zipped folder to the connected client."""
        temp_zip_path = None
        try:
            if not os.path.exists(item_path):
                self.master.after(0, self.server_status_label.config, {"text": f"Error: Item not found - {item_path}"})
                client_socket.sendall(b"ERROR:ITEM_NOT_FOUND")
                client_socket.close()
                return

            original_item_name = os.path.basename(item_path)
            send_path = item_path
            send_type_prefix = item_type.upper() # 'FILE' or 'FOLDER'
            display_name = original_item_name

            if item_type == 'folder':
                self.master.after(0, self.server_status_label.config, {"text": f"Zipping folder '{original_item_name}'..."})
                # Create a temporary zip file
                temp_zip_name = f"{original_item_name}.zip"
                temp_zip_path = os.path.join(os.path.dirname(item_path) or os.getcwd(), temp_zip_name)
                # Ensure the path is unique enough to avoid conflicts
                i = 0
                while os.path.exists(temp_zip_path):
                    i += 1
                    temp_zip_name = f"{original_item_name}_{i}.zip"
                    temp_zip_path = os.path.join(os.path.dirname(item_path) or os.getcwd(), temp_zip_name)

                # Create zip archive
                shutil.make_archive(os.path.splitext(temp_zip_path)[0], 'zip', item_path)
                send_path = temp_zip_path
                display_name = temp_zip_name # Client will receive this name for the zip
                self.master.after(0, self.server_status_label.config, {"text": f"Finished zipping '{original_item_name}'. Sending..."})


            item_size = os.path.getsize(send_path)
            header = f"{send_type_prefix}|{display_name}|{item_size}"
            client_socket.sendall(header.encode('utf-8'))

            ack = client_socket.recv(BUFFER_SIZE).decode('utf-8')
            if ack != "READY":
                self.master.after(0, self.server_status_label.config, {"text": f"Client not ready to receive {item_type} data. Aborting."})
                client_socket.close()
                return

            with open(send_path, "rb") as f:
                bytes_sent = 0
                while bytes_sent < item_size:
                    bytes_read = f.read(BUFFER_SIZE)
                    if not bytes_read:
                        break # End of file
                    client_socket.sendall(bytes_read)
                    bytes_sent += len(bytes_read)
                    progress = (bytes_sent / item_size) * 100
                    self.master.after(0, self.server_progress_bar.config, {"value": progress})
                    self.master.after(0, self.server_status_label.config, {"text": f"Sending {item_type}: {original_item_name} ({progress:.2f}%)"})
                self.master.after(0, self.server_status_label.config, {"text": f"Successfully sent '{original_item_name}'"})
                self.master.after(0, self.server_progress_bar.config, {"value": 100})

        except ConnectionResetError:
            self.master.after(0, self.server_status_label.config, {"text": f"Client disconnected unexpectedly while sending '{original_item_name}'."})
        except BrokenPipeError:
            self.master.after(0, self.server_status_label.config, {"text": f"Client pipe broken while sending '{original_item_name}'."})
        except Exception as e:
            self.master.after(0, self.server_status_label.config, {"text": f"Error sending {item_type} '{original_item_name}': {e}"})
        finally:
            client_socket.close()
            # Clean up temporary zip file if created
            if temp_zip_path and os.path.exists(temp_zip_path):
                os.remove(temp_zip_path)
                self.master.after(0, self.server_status_label.config, {"text": "Temporary zip cleaned up."})

            # Reset UI after sending
            self.master.after(0, self.selected_item_label.config, {"text": "No item selected"})
            self.selected_item_path = ""
            self.item_to_send_type = None
            self.master.after(0, self.server_status_label.config, {"text": "Waiting for next connection..."})
            self.master.after(0, self.server_progress_bar.config, {"value": 0})


    def start_client_thread(self):
        server_ip = self.server_ip_entry.get()
        if not server_ip:
            messagebox.showwarning("Input Error", "Please enter the server IP address.")
            return

        if self.client_thread and self.client_thread.is_alive():
            messagebox.showinfo("Info", "Client is already attempting to connect or receive.")
            return

        def client_task():
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                self.master.after(0, self.client_status_label.config, {"text": f"Connecting to {server_ip}:{PORT}..."})
                client_socket.connect((server_ip, PORT))
                self.master.after(0, self.client_status_label.config, {"text": "Connected to server. Waiting for item info..."})

                # Receive header: ITEM_TYPE|ITEM_NAME|ITEM_SIZE
                header = client_socket.recv(BUFFER_SIZE).decode('utf-8')
                if header.startswith("ERROR:"):
                    self.master.after(0, self.client_status_label.config, {"text": f"Server error: {header}"})
                    client_socket.close()
                    return

                item_type_prefix, item_name, item_size_str = header.split('|', 2)
                item_size = int(item_size_str)
                item_type = item_type_prefix.lower() # 'file' or 'folder'

                self.master.after(0, self.client_status_label.config, {"text": f"Receiving {item_type}: '{item_name}' ({item_size} bytes)"})

                # Send acknowledgement to server that client is ready
                client_socket.sendall(b"READY")

                received_bytes = 0
                # Save item in the same directory as the executable or script
                save_path = os.path.join(os.getcwd(), item_name)
                with open(save_path, "wb") as f:
                    while received_bytes < item_size:
                        bytes_to_read = min(BUFFER_SIZE, item_size - received_bytes)
                        bytes_read = client_socket.recv(bytes_to_read)
                        if not bytes_read:
                            self.master.after(0, self.client_status_label.config, {"text": "Connection closed unexpectedly before item transfer complete."})
                            break
                        f.write(bytes_read)
                        received_bytes += len(bytes_read)
                        progress = (received_bytes / item_size) * 100
                        self.master.after(0, self.client_progress_bar.config, {"value": progress})
                        self.master.after(0, self.client_status_label.config, {"text": f"Receiving {item_type}: {item_name} ({progress:.2f}%)"})

                self.master.after(0, self.client_status_label.config, {"text": f"Successfully received '{item_name}'."})
                self.master.after(0, self.client_progress_bar.config, {"value": 100})

                # If it's a folder, unzip it
                if item_type == 'folder':
                    self.master.after(0, self.client_status_label.config, {"text": f"Unzipping '{item_name}'..."})
                    target_folder_name = os.path.splitext(item_name)[0] # Remove .zip extension
                    target_folder_path = os.path.join(os.getcwd(), target_folder_name)
                    try:
                        with zipfile.ZipFile(save_path, 'r') as zip_ref:
                            zip_ref.extractall(target_folder_path)
                        self.master.after(0, self.client_status_label.config, {"text": f"Successfully unzipped '{item_name}' to '{target_folder_name}'"})
                        os.remove(save_path) # Clean up the received zip file
                    except zipfile.BadZipFile:
                        self.master.after(0, self.client_status_label.config, {"text": f"Error: Received file is not a valid zip archive."})
                    except Exception as e:
                        self.master.after(0, self.client_status_label.config, {"text": f"Error unzipping '{item_name}': {e}"})

            except ConnectionRefusedError:
                self.master.after(0, self.client_status_label.config, {"text": f"Error: Connection refused. Is the server running on {server_ip}:{PORT}?"})
            except socket.timeout:
                self.master.after(0, self.client_status_label.config, {"text": "Error: Connection timed out."})
            except Exception as e:
                self.master.after(0, self.client_status_label.config, {"text": f"Error receiving item: {e}"})
            finally:
                client_socket.close()
                self.master.after(0, self.client_status_label.config, {"text": "Client disconnected."})
                self.master.after(0, self.client_progress_bar.config, {"value": 0})


        self.client_thread = threading.Thread(target=client_task)
        self.client_thread.daemon = True # Allows the thread to exit with the main program
        self.client_thread.start()

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit the application?"):
            self.master.destroy()
            sys.exit(0) # Ensure all threads are terminated

if __name__ == "__main__":
    root = tk.Tk()
    app = FileTransferApp(root)
    root.mainloop()

