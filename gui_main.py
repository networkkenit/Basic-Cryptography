import tkinter as tk
import os
from tkinter import ttk, messagebox

from caesar_cipher import caesar_encrypt, caesar_decrypt
from aes_encryption import aes_encrypt, aes_decrypt
from rsa_encryption import generate_keys, rsa_encrypt, rsa_decrypt

# Khởi tạo khóa RSA
private_key, public_key = generate_keys()

# Đường dẫn thư mục chứa file
DATA_DIR = "sample_data"

# Hàm đọc nội dung từ plain.txt
def load_plain_text():
    try:
        with open(os.path.join(DATA_DIR, "plain.txt"), "r", encoding="utf-8") as f:
            content = f.read()
            input_text.delete("1.0", tk.END)
            input_text.insert(tk.END, content)
            messagebox.showinfo("Thành công", "Đã đọc dữ liệu từ plain.txt")
    except Exception as e:
        messagebox.showerror("Lỗi", f"Không đọc được plain.txt:\n{str(e)}")

# Hàm xử lý mã hóa/giải mã
def process(mode):
    algo = algo_choice.get()
    text = input_text.get("1.0", tk.END).strip()
    key = key_entry.get().strip()
    
    if not text:
        messagebox.showwarning("Cảnh báo", "Vui lòng nhập nội dung hoặc đọc từ plain.txt.")
        return
    
    try:
        if algo == "Caesar":
            shift = int(key)
            result = caesar_encrypt(text, shift) if mode == "Encrypt" else caesar_decrypt(text, shift)
        elif algo == "AES":
            result = aes_encrypt(text, key) if mode == "Encrypt" else aes_decrypt(text, key)
        elif algo == "RSA":
            result = rsa_encrypt(text, public_key).hex() if mode == "Encrypt" else rsa_decrypt(bytes.fromhex(text), private_key)
        else:
            result = "Thuật toán không hợp lệ."
        
        # Ghi kết quả ra file
        output_file = "encrypted.txt" if mode == "Encrypt" else "plain.txt"
        with open(os.path.join(DATA_DIR, output_file), "w", encoding="utf-8") as f:
            f.write(result)

        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, result)
        messagebox.showinfo("Thành công", f"Kết quả đã ghi vào {output_file}")

    except Exception as e:
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, f"Lỗi: {str(e)}")

# GUI Setup
root = tk.Tk()
root.title("Basic Cryptography GUI")
root.geometry("600x500")
root.resizable(False, False)

# Chọn thuật toán
ttk.Label(root, text="Chọn thuật toán:").pack(pady=5)
algo_choice = ttk.Combobox(root, values=["Caesar", "AES", "RSA"], state="readonly")
algo_choice.current(0)
algo_choice.pack()

# Nhập khóa
ttk.Label(root, text="Nhập khóa (shift, mật khẩu hoặc bỏ trống với RSA):").pack(pady=5)
key_entry = ttk.Entry(root, width=50)
key_entry.pack()

# Nhập văn bản
ttk.Label(root, text="Văn bản đầu vào:").pack(pady=5)
input_text = tk.Text(root, height=5, width=70)
input_text.pack()

# Nút đọc từ file
ttk.Button(root, text="📂 Đọc từ plain.txt", command=load_plain_text).pack(pady=5)

# Nút Encrypt / Decrypt
btn_frame = ttk.Frame(root)
btn_frame.pack(pady=10)
ttk.Button(btn_frame, text="Encrypt", command=lambda: process("Encrypt")).pack(side=tk.LEFT, padx=10)
ttk.Button(btn_frame, text="Decrypt", command=lambda: process("Decrypt")).pack(side=tk.LEFT, padx=10)

# Kết quả
ttk.Label(root, text="Kết quả:").pack()
output_text = tk.Text(root, height=10, width=70)
output_text.pack()

# Chạy ứng dụng
root.mainloop()
