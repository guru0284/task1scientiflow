import tkinter as tk
from tkinter import messagebox
from tkinter import font
import subprocess

class ModernLoginApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Scientiflow-cli GUI Login")
        self.geometry("400x380")
        self.configure(bg="#181A1B")
        self.resizable(False, False)
        self.custom_font = font.Font(family="Segoe UI", size=12)
        self.logo_font = font.Font(family="Segoe UI", size=18, weight="bold")
        self.is_logged_in = False
        self.create_login_frame()

    def create_login_frame(self):
        self.clear_widgets()
        frame = tk.Frame(self, bg="#23272A", bd=0, relief="flat")
        frame.place(relx=0.5, rely=0.5, anchor="center", width=340, height=320)

        tk.Label(frame, text="Scientiflow-cli Login", bg="#23272A", fg="#00FFAA",
                 font=self.logo_font).pack(pady=(18, 8))

        tk.Label(frame, text="Username", bg="#23272A", fg="#CCCCCC",
                 font=self.custom_font).pack(anchor="w", padx=30, pady=(10, 0))
        self.username_entry = tk.Entry(frame, font=self.custom_font, bg="#2C2F33", fg="#00FFAA", insertbackground="#00FFAA", relief="flat")
        self.username_entry.pack(fill="x", padx=30, pady=(0, 12))

        tk.Label(frame, text="Password", bg="#23272A", fg="#CCCCCC",
                 font=self.custom_font).pack(anchor="w", padx=30, pady=(0, 0))
        pw_frame = tk.Frame(frame, bg="#23272A")
        pw_frame.pack(fill="x", padx=30, pady=(0, 12))
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(pw_frame, textvariable=self.password_var, font=self.custom_font,
                                       bg="#2C2F33", fg="#00FFAA", insertbackground="#00FFAA",
                                       relief="flat", show="*")
        self.password_entry.pack(side="left", fill="x", expand=True)
        self.show_pw = False
        self.toggle_btn = tk.Button(pw_frame, text="Show", font=("Segoe UI", 9),
                                    bg="#23272A", fg="#00FFAA", bd=0, relief="flat",
                                    activebackground="#23272A",
                                    command=self.toggle_password)
        self.toggle_btn.pack(side="right", padx=(6, 0))

        self.status_label = tk.Label(frame, text="", bg="#23272A", fg="#FF5555", font=("Segoe UI", 10))
        self.status_label.pack(pady=(2, 2))

        login_btn = tk.Button(frame, text="Login", font=self.custom_font, bg="#00FFAA", fg="#181A1B",
                              activebackground="#00CC88", relief="flat", height=2, width=16,
                              command=self.handle_login)
        login_btn.pack(pady=(8, 0))

    def create_logout_frame(self):
        self.clear_widgets()
        frame = tk.Frame(self, bg="#23272A", bd=0, relief="flat")
        frame.place(relx=0.5, rely=0.5, anchor="center", width=340, height=220)

        tk.Label(frame, text="Welcome!", bg="#23272A", fg="#00FFAA",
                 font=self.logo_font).pack(pady=(30, 8))

        tk.Label(frame, text="You are logged in to Scientiflow-cli.",
                 bg="#23272A", fg="#CCCCCC", font=self.custom_font).pack(pady=(0, 18))

        logout_btn = tk.Button(frame, text="Logout", font=self.custom_font, bg="#00FFAA", fg="#181A1B",
                               activebackground="#00CC88", relief="flat", height=2, width=16,
                               command=self.handle_logout)
        logout_btn.pack(pady=(0, 8))

        self.status_label = tk.Label(frame, text="", bg="#23272A", fg="#FF5555", font=("Segoe UI", 10))
        self.status_label.pack()

    def clear_widgets(self):
        for widget in self.winfo_children():
            widget.destroy()

    def toggle_password(self):
        if self.show_pw:
            self.password_entry.config(show="*")
            self.toggle_btn.config(text="Show")
        else:
            self.password_entry.config(show="")
            self.toggle_btn.config(text="Hide")
        self.show_pw = not self.show_pw

    def handle_login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            self.status_label.config(text="Please enter both username and password.", fg="#FF5555")
            return
        self.status_label.config(text="Logging in...", fg="#00FFAA")
        self.update_idletasks()
        try:
            # Attempt login via scientiflow-cli
            result = subprocess.run(
                ["scientiflow-cli", "login", "--username", username, "--password", password],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                self.is_logged_in = True
                self.create_logout_frame()
            else:
                err_msg = result.stderr.strip() or "Login failed. Please check your credentials."
                self.status_label.config(text=err_msg, fg="#FF5555")
        except Exception as e:
            self.status_label.config(text=f"Error: {e}", fg="#FF5555")

    def handle_logout(self):
        self.status_label.config(text="Logging out...", fg="#00FFAA")
        self.update_idletasks()
        try:
            result = subprocess.run(
                ["scientiflow-cli", "logout"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                self.is_logged_in = False
                messagebox.showinfo("Logout", "You have been logged out.")
                self.create_login_frame()
            else:
                err_msg = result.stderr.strip() or "Logout failed."
                self.status_label.config(text=err_msg, fg="#FF5555")
        except Exception as e:
            self.status_label.config(text=f"Error: {e}", fg="#FF5555")

if __name__ == "__main__":
    app = ModernLoginApp()
    app.mainloop()
