import tkinter as tk
from tkinter import messagebox, scrolledtext
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from gvm.errors import GvmError
import time

class OpenVASScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("OpenVAS Scanner")
        self.root.geometry("600x400")

        self.create_widgets()

    def create_widgets(self):
        # Target IP entry
        tk.Label(self.root, text="Target IP:").pack(pady=5)
        self.target_entry = tk.Entry(self.root, width=40)
        self.target_entry.pack(pady=5)

        # Scan button
        self.scan_button = tk.Button(self.root, text="Scan", command=self.scan_target)
        self.scan_button.pack(pady=10)

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = tk.Progressbar(self.root, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, padx=20, pady=5)

        # Result display
        self.result_text = scrolledtext.ScrolledText(self.root, height=15)
        self.result_text.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

    def scan_target(self):
        target_ip = self.target_entry.get()
        if not target_ip:
            messagebox.showerror("Error", "Please enter a target IP")
            return

        self.scan_button.config(state=tk.DISABLED)
        self.result_text.delete(1.0, tk.END)
        self.progress_var.set(0)

        try:
            connection = TLSConnection(hostname='your_openvas_server', port=9390)
            transform = EtreeTransform()
            
            with Gmp(connection, transform=transform) as gmp:
                gmp.authenticate('your_username', 'your_password')
                
                self.update_progress("Creating target...", 10)
                target_id = gmp.create_target(name=f'Target: {target_ip}', hosts=[target_ip]).get('id')
                
                self.update_progress("Creating task...", 20)
                task_id = gmp.create_task(name=f'Scan Task: {target_ip}', 
                                          config_id='daba56c8-73ec-11df-a475-002264764cea', 
                                          target_id=target_id).get('id')
                
                self.update_progress("Starting scan...", 30)
                gmp.start_task(task_id)
                
                self.monitor_task_progress(gmp, task_id)

        except GvmError as e:
            self.update_result(f"Error: {str(e)}")
        except Exception as e:
            self.update_result(f"Unexpected error: {str(e)}")
        finally:
            self.scan_button.config(state=tk.NORMAL)

    def monitor_task_progress(self, gmp, task_id):
        while True:
            status = gmp.get_task(task_id).find('status').text
            progress = int(gmp.get_task(task_id).find('progress').text)
            
            self.update_progress(f"Scanning... {status}", 30 + progress * 0.5)
            
            if status == "Done":
                break
            time.sleep(5)

        self.update_progress("Fetching results...", 90)
        report_id = gmp.get_task(task_id).find('last_report/report').get('id')
        results = gmp.get_results(filter=f"report_id={report_id}")

        self.display_results(results)
        self.update_progress("Scan completed", 100)

    def display_results(self, results):
        for result in results.findall('result'):
            severity = result.find('severity').text
            name = result.find('name').text
            host = result.find('host').text
            self.update_result(f"Host: {host}, Severity: {severity}, Vulnerability: {name}\n")

    def update_progress(self, message, value):
        self.progress_var.set(value)
        self.update_result(f"{message}\n")
        self.root.update_idletasks()

    def update_result(self, message):
        self.result_text.insert(tk.END, message)
        self.result_text.see(tk.END)
        self.root.update_idletasks()

if __name__ == "__main__":
    root = tk.Tk()
    app = OpenVASScanner(root)
    root.mainloop()
