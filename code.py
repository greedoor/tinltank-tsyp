import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import shutil
import time

# Placeholders for model and scanning function
model = None  # Assume this is loaded with the deep learning model
def scan_file(file_path):
    # Placeholder scan function to simulate scanning
    print(f"Scanning file: {file_path}")
    prediction = model.predict([extract_features(file_path)])
    if prediction >= 0.5:
        quarantine_file(file_path)
        return "Malicious"
    return "Clean"

def extract_features(file_path):
    # Dummy feature extraction for demonstration purposes
    return [0]  # Replace with real features

def quarantine_file(file_path):
    quarantine_path = "/path/to/quarantine/folder"  # Replace with actual path
    shutil.move(file_path, quarantine_path)
    print(f"File {file_path} moved to quarantine.")

# Real-time File Monitoring Handler
class RealTimeHandler(FileSystemEventHandler):
    def __init__(self, display_callback):
        super().__init__()
        self.display_callback = display_callback

    def on_created(self, event):
        status = scan_file(event.src_path)
        self.display_callback(event.src_path, status)

    def on_modified(self, event):
        status = scan_file(event.src_path)
        self.display_callback(event.src_path, status)

# GUI Application
class AntivirusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AI-Powered Antivirus App")
        self.root.geometry("600x500")
        self.root.configure(bg="#2c3e50")
        self.monitoring = False

        # Style Configuration
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", font=("Arial", 12), foreground="black")
        style.configure("TLabel", font=("Arial", 12), background="#2c3e50", foreground="white")
        
        # Header Frame
        header = tk.Frame(root, bg="#34495e", height=50)
        header.pack(fill="x", pady=(0, 10))
        header_label = tk.Label(header, text="Antivirus App with Deep Learning", bg="#34495e", fg="white", font=("Arial Bold", 16))
        header_label.pack(pady=10)

        # Directory Selection Frame
        dir_frame = tk.Frame(root, bg="#2c3e50")
        dir_frame.pack(pady=10)
        
        dir_label = ttk.Label(dir_frame, text="Directory to Monitor:")
        dir_label.grid(row=0, column=0, padx=5, pady=5)
        
        self.dir_path = tk.StringVar()
        self.dir_entry = ttk.Entry(dir_frame, textvariable=self.dir_path, width=40)
        self.dir_entry.grid(row=0, column=1, padx=5, pady=5)
        
        self.select_button = ttk.Button(dir_frame, text="Browse", command=self.select_directory)
        self.select_button.grid(row=0, column=2, padx=5, pady=5)

        # Start/Stop Monitoring Button
        self.monitor_button = ttk.Button(root, text="Start Monitoring", command=self.toggle_monitoring, width=20)
        self.monitor_button.pack(pady=15)

        # Status Display Frame
        status_frame = tk.LabelFrame(root, text="Scanning Status", bg="#2c3e50", fg="white", font=("Arial", 12), labelanchor="n")
        status_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        self.status_text = tk.Text(status_frame, wrap="word", font=("Arial", 10), bg="#34495e", fg="white", borderwidth=0, relief="sunken")
        self.status_text.pack(fill="both", expand=True, padx=10, pady=10)

        # Footer
        footer = tk.Frame(root, bg="#34495e", height=40)
        footer.pack(fill="x", pady=(10, 0))
        footer_label = tk.Label(footer, text="© 2024 AI Antivirus", bg="#34495e", fg="white", font=("Arial", 10))
        footer_label.pack()

    def select_directory(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.dir_path.set(folder_selected)

    def toggle_monitoring(self):
        if not self.monitoring:
            if not self.dir_path.get():
                messagebox.showwarning("Warning", "Please select a directory to monitor.")
                return
            self.monitoring = True
            self.monitor_button.config(text="Stop Monitoring")
            self.start_monitoring()
        else:
            self.monitoring = False
            self.monitor_button.config(text="Start Monitoring")
            self.stop_monitoring()

    def start_monitoring(self):
        path = self.dir_path.get()
        self.handler = RealTimeHandler(self.update_status)
        self.observer = Observer()
        self.observer.schedule(self.handler, path, recursive=True)
        self.observer.start()
        
    def stop_monitoring(self):
        self.observer.stop()
        self.observer.join()

    def update_status(self, file_path, status):
        self.status_text.insert(tk.END, f"Scanned: {file_path} - Status: {status}\n")
        self.status_text.see(tk.END)

# Running the Application
root = tk.Tk()
app = AntivirusApp(root)
root.mainloop()