import tkinter as tk
from tkinter import ttk, messagebox
import requests
from bitcoin import random_key, privtopub, pubtoaddr

# Public API URLs
BLOCKSTREAM_API = "https://blockstream.info/api"

# Generate a new Bitcoin address (Mainnet)
def generate_new_address():
    private_key = random_key()
    public_key = privtopub(private_key)
    bitcoin_address = pubtoaddr(public_key)
    return bitcoin_address, private_key

# Check the balance of a Bitcoin address
def check_balance(address):
    url = f"{BLOCKSTREAM_API}/address/{address}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        balance = data.get('chain_stats', {}).get('funded_txo_sum', 0) - data.get('chain_stats', {}).get('spent_txo_sum', 0)
        return balance / 1e8  # Convert satoshis to BTC
    else:
        raise Exception(f"Failed to fetch balance: HTTP {response.status_code} - {response.text}")

# Display the last 5 transactions of a Bitcoin address
def get_last_transactions(address):
    url = f"{BLOCKSTREAM_API}/address/{address}/txs"
    response = requests.get(url)
    if response.status_code == 200:
        transactions = response.json()
        if transactions:
            transactions = transactions[:5]
            return [
                {
                    "txid": tx["txid"],
                    "amount": sum([vout["value"] for vout in tx["vout"]]) / 1e8,  # in BTC
                    "confirmed": tx.get("status", {}).get("confirmed", False)
                }
                for tx in transactions
            ]
        else:
            return []
    else:
        raise Exception(f"Failed to fetch transactions: HTTP {response.status_code} - {response.text}")

# Function to copy text to clipboard
def copy_to_clipboard(text):
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()
    messagebox.showinfo("Copied", "Address copied to clipboard!")

# Generate Address Section
def generate_address():
    try:
        address, private_key = generate_new_address()
        address_output.config(state="normal")
        private_key_output.config(state="normal")
        address_output.delete("1.0", tk.END)
        private_key_output.delete("1.0", tk.END)
        address_output.insert(tk.END, address)
        private_key_output.insert(tk.END, private_key)
        address_output.config(state="disabled")
        private_key_output.config(state="disabled")
        copy_button.config(state=tk.NORMAL, command=lambda: copy_to_clipboard(address))
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Check Balance Section
def check_balance_action():
    address = address_input.get().strip()
    if not address:
        messagebox.showerror("Error", "Please enter a Bitcoin address.")
        return
    try:
        balance = check_balance(address)
        balance_label.config(text=f"Balance: {balance} BTC")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Get Last Transactions Section
def get_transactions_action():
    address = address_input.get().strip()
    if not address:
        messagebox.showerror("Error", "Please enter a Bitcoin address.")
        return
    try:
        transactions = get_last_transactions(address)
        tx_listbox.delete(*tx_listbox.get_children())
        if transactions:
            for tx in transactions:
                tx_listbox.insert("", "end", values=(tx["txid"], tx["amount"], tx["confirmed"]))
        else:
            messagebox.showinfo("Info", "No transactions found for this address.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Create GUI
root = tk.Tk()
root.title("Bitcoin Wallet")
root.geometry("800x600")
root.resizable(False, False)

# Colors and Styles
PRIMARY_COLOR = "#2E3B4E"
SECONDARY_COLOR = "#475B75"
ACCENT_COLOR = "#FFD700"
TEXT_COLOR = "#FFFFFF"

root.config(bg=PRIMARY_COLOR)
style = ttk.Style()
style.configure("TFrame", background=PRIMARY_COLOR)
style.configure("TLabel", background=PRIMARY_COLOR, foreground=TEXT_COLOR, font=("Arial", 12))
style.configure("TButton", background=ACCENT_COLOR, foreground=PRIMARY_COLOR, font=("Arial", 12), padding=5)
style.configure("Treeview", font=("Arial", 10), rowheight=25, fieldbackground=SECONDARY_COLOR)
style.configure("Treeview.Heading", background=ACCENT_COLOR, foreground=PRIMARY_COLOR, font=("Arial", 12))

# Main Frame
frame = ttk.Frame(root, padding="10")
frame.pack(fill=tk.BOTH, expand=True)

# Generate Address Section
ttk.Label(frame, text="Generate New Bitcoin Address", font=("Arial", 16, "bold")).pack(pady=10)
generate_frame = ttk.Frame(frame, padding="10")
generate_frame.pack(fill=tk.X)
ttk.Button(generate_frame, text="Generate Address", command=generate_address).grid(row=0, column=0, padx=10)
address_output = tk.Text(generate_frame, height=2, width=60, state="disabled", wrap=tk.WORD, bg=SECONDARY_COLOR, fg=TEXT_COLOR)
address_output.grid(row=1, column=0, padx=10, pady=5, sticky="ew")
private_key_output = tk.Text(generate_frame, height=2, width=60, state="disabled", wrap=tk.WORD, bg=SECONDARY_COLOR, fg=TEXT_COLOR)
private_key_output.grid(row=2, column=0, padx=10, pady=5, sticky="ew")
copy_button = ttk.Button(generate_frame, text="Copy Address", state=tk.DISABLED)
copy_button.grid(row=3, column=0, pady=5)

# Balance and Transactions Section
ttk.Label(frame, text="Check Balance and Transactions", font=("Arial", 16, "bold")).pack(pady=10)
action_frame = ttk.Frame(frame, padding="10")
action_frame.pack(fill=tk.X)
address_input = ttk.Entry(action_frame, width=60)
address_input.grid(row=0, column=0, padx=10, pady=5)
ttk.Button(action_frame, text="Check Balance", command=check_balance_action).grid(row=0, column=1, padx=10)
ttk.Button(action_frame, text="Get Last 5 Transactions", command=get_transactions_action).grid(row=0, column=2, padx=10)

balance_label = ttk.Label(frame, text="Balance: N/A", font=("Arial", 14))
balance_label.pack(pady=10)

# Transactions List
tx_frame = ttk.Frame(frame, padding="10")
tx_frame.pack(fill=tk.BOTH, expand=True)
columns = ("TxID", "Amount (BTC)", "Confirmed")
tx_listbox = ttk.Treeview(tx_frame, columns=columns, show="headings", height=8)
for col in columns:
    tx_listbox.heading(col, text=col)
    tx_listbox.column(col, width=200, anchor="center")
tx_listbox.pack(fill=tk.BOTH, expand=True)

# Run the GUI
root.mainloop()
