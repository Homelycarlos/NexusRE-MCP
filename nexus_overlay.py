import sys
import json
import time
import threading
import tkinter as tk
import socket

# This is a standalone overlay script that runs alongside the MCP server.
# It listens on a UDP port for drawing commands from the AI and renders them
# as a transparent, click-through overlay on the Windows desktop.

class OverlayApp:
    def __init__(self):
        self.root = tk.Tk()
        
        # Make the window transparent and click-through
        self.root.attributes('-alpha', 1.0)
        self.root.attributes('-transparentcolor', 'black')
        self.root.attributes('-topmost', True)
        self.root.overrideredirect(True)
        
        # Cover the whole screen
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        self.root.geometry(f"{screen_width}x{screen_height}+0+0")
        self.root.configure(bg='black')
        
        self.canvas = tk.Canvas(self.root, width=screen_width, height=screen_height, bg='black', highlightthickness=0)
        self.canvas.pack()
        
        # Windows API to make it click-through (WS_EX_LAYERED | WS_EX_TRANSPARENT)
        try:
            import win32gui
            import win32con
            hwnd = self.root.winfo_id()
            ex_style = win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE)
            win32gui.SetWindowLong(hwnd, win32con.GWL_EXSTYLE, ex_style | win32con.WS_EX_LAYERED | win32con.WS_EX_TRANSPARENT)
        except Exception as e:
            print(f"Win32 API click-through failed: {e}")

        self.draw_commands = []
        self.lock = threading.Lock()
        
        # Start UDP listener for commands
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 10111))
        
        self.listener_thread = threading.Thread(target=self.udp_listener, daemon=True)
        self.listener_thread.start()
        
        self.update_render()
        
    def udp_listener(self):
        while True:
            try:
                data, _ = self.sock.recvfrom(65535)
                cmds = json.loads(data.decode('utf-8'))
                with self.lock:
                    self.draw_commands = cmds
            except Exception as e:
                print(f"UDP Error: {e}")
                
    def update_render(self):
        self.canvas.delete("all")
        
        with self.lock:
            for cmd in self.draw_commands:
                try:
                    ctype = cmd.get("type")
                    color = cmd.get("color", "red")
                    if ctype == "rect":
                        x, y, w, h = cmd["x"], cmd["y"], cmd["w"], cmd["h"]
                        self.canvas.create_rectangle(x, y, x+w, y+h, outline=color, width=2)
                        if "text" in cmd:
                            self.canvas.create_text(x, y-10, text=cmd["text"], fill=color, font=("Consolas", 12, "bold"), anchor="sw")
                    elif ctype == "text":
                        x, y = cmd["x"], cmd["y"]
                        self.canvas.create_text(x, y, text=cmd["text"], fill=color, font=("Consolas", 14, "bold"), anchor="nw")
                    elif ctype == "line":
                        x1, y1, x2, y2 = cmd["x1"], cmd["y1"], cmd["x2"], cmd["y2"]
                        self.canvas.create_line(x1, y1, x2, y2, fill=color, width=2)
                except Exception as e:
                    pass
                    
        # Refresh at 60 FPS
        self.root.after(16, self.update_render)

if __name__ == "__main__":
    app = OverlayApp()
    app.root.mainloop()
