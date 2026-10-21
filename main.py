import tkinter as tk
from ui.app_gui import SecurityAuditGUI


def main():
  root = tk.Tk()
  app = SecurityAuditGUI(root)
  root.mainloop()


if __name__ == "__main__":
  main()