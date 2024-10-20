import tkinter as tk
from tkinter import messagebox
from force import brute_force_attack  # 导入暴力破解逻辑
from sdes_algorithm import encrypt_ascii, decrypt_ascii, encrypt, decrypt, str_to_bin_list, bin_list_to_str

# 创建 Tkinter 窗口
root = tk.Tk()
root.title("欢迎使用S-DES")

# 设置字体样式
title_font = ("Microsoft YaHei", 16, "bold")
label_font = ("Microsoft YaHei", 12)
button_font = ("Microsoft YaHei", 12, "bold")
result_font = ("Microsoft YaHei", 12, "italic")

# 创建一个容器，用于切换页面
main_frame = tk.Frame(root)
main_frame.grid(row=0, column=0, padx=10, pady=10)

# 创建函数用于显示主页
def show_home():
    for widget in main_frame.winfo_children():
        widget.destroy()  # 清空当前页面

    tk.Label(main_frame, text="请选择操作模式：", font=title_font).grid(row=0, column=0, columnspan=2, pady=20)

    # 添加ASCII和二进制模式选择
    ascii_button = tk.Button(main_frame, text="ASCII加密/解密", width=20, font=button_font, command=show_ascii_mode)
    ascii_button.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

    binary_button = tk.Button(main_frame, text="二进制加密/解密", width=20, font=button_font, command=show_binary_mode)
    binary_button.grid(row=1, column=1, padx=20, pady=10, sticky="ew")

    brute_force_button = tk.Button(main_frame, text="暴力破解", width=20, font=button_font, command=show_brute_force_page)
    brute_force_button.grid(row=2, column=0, columnspan=2, padx=20, pady=10, sticky="ew")

# 创建ASCII加密/解密页面
def show_ascii_mode():
    for widget in main_frame.winfo_children():
        widget.destroy()  # 清空当前页面

    tk.Label(main_frame, text="输入明文或密文(ASCII)：", font=label_font).grid(row=0, column=0, pady=10)
    text_entry = tk.Entry(main_frame, font=label_font)
    text_entry.grid(row=0, column=1, padx=10)

    tk.Label(main_frame, text="输入 10 位密钥：", font=label_font).grid(row=1, column=0, pady=10)
    key_entry = tk.Entry(main_frame, font=label_font)
    key_entry.grid(row=1, column=1, padx=10)

    result_label = tk.Label(main_frame, text="结果将在此显示", font=result_font)
    result_label.grid(row=3, columnspan=2, pady=10)

    def encrypt_ascii_action():
        plaintext = text_entry.get()
        key = key_entry.get()

        if len(key) != 10:
            messagebox.showerror("错误", "密钥必须是10位二进制！")
            return

        key_bits = str_to_bin_list(key, 10)
        result = encrypt_ascii(plaintext, key_bits)
        result_label.config(text="加密后的ASCII密文: " + result)

    def decrypt_ascii_action():
        ciphertext = text_entry.get()
        key = key_entry.get()

        if len(key) != 10:
            messagebox.showerror("错误", "密钥必须是10位二进制！")
            return

        key_bits = str_to_bin_list(key, 10)
        result = decrypt_ascii(ciphertext, key_bits)
        result_label.config(text="解密后的ASCII明文: " + result)

    tk.Button(main_frame, text="加密", font=button_font, command=encrypt_ascii_action).grid(row=2, column=0, pady=10, sticky="ew")
    tk.Button(main_frame, text="解密", font=button_font, command=decrypt_ascii_action).grid(row=2, column=1, pady=10, sticky="ew")
    tk.Button(main_frame, text="返回主页", font=button_font, command=show_home).grid(row=4, columnspan=2, pady=10, sticky="ew")

# 创建二进制加密/解密页面
def show_binary_mode():
    for widget in main_frame.winfo_children():
        widget.destroy()  # 清空当前页面

    tk.Label(main_frame, text="输入 8 位二进制明文或密文：", font=label_font).grid(row=0, column=0, pady=10)
    text_entry = tk.Entry(main_frame, font=label_font)
    text_entry.grid(row=0, column=1, padx=10)

    tk.Label(main_frame, text="输入 10 位密钥：", font=label_font).grid(row=1, column=0, pady=10)
    key_entry = tk.Entry(main_frame, font=label_font)
    key_entry.grid(row=1, column=1, padx=10)

    result_label = tk.Label(main_frame, text="结果将在此显示", font=result_font)
    result_label.grid(row=3, columnspan=2, pady=10)

    def encrypt_binary_action():
        plaintext = text_entry.get()
        key = key_entry.get()

        if len(plaintext) != 8 or len(key) != 10:
            messagebox.showerror("错误", "请输入8位二进制明文和10位二进制密钥！")
            return

        plaintext_bits = str_to_bin_list(plaintext, 8)
        key_bits = str_to_bin_list(key, 10)
        result = encrypt(plaintext_bits, key_bits)
        result_label.config(text="加密后的二进制密文: " + bin_list_to_str(result))

    def decrypt_binary_action():
        ciphertext = text_entry.get()
        key = key_entry.get()

        if len(ciphertext) != 8 or len(key) != 10:
            messagebox.showerror("错误", "请输入8位二进制密文和10位二进制密钥！")
            return

        ciphertext_bits = str_to_bin_list(ciphertext, 8)
        key_bits = str_to_bin_list(key, 10)
        result = decrypt(ciphertext_bits, key_bits)
        result_label.config(text="解密后的二进制明文: " + bin_list_to_str(result))

    tk.Button(main_frame, text="加密", font=button_font, command=encrypt_binary_action).grid(row=2, column=0, pady=10, sticky="ew")
    tk.Button(main_frame, text="解密", font=button_font, command=decrypt_binary_action).grid(row=2, column=1, pady=10, sticky="ew")
    tk.Button(main_frame, text="返回主页", font=button_font, command=show_home).grid(row=4, columnspan=2, pady=10, sticky="ew")

# 创建暴力破解页面
def show_brute_force_page():
    for widget in main_frame.winfo_children():
        widget.destroy()  # 清空当前页面

    tk.Label(main_frame, text="输入已知明文(8位二进制)：", font=label_font).grid(row=0, column=0, pady=10)
    plaintext_entry = tk.Entry(main_frame, font=label_font)
    plaintext_entry.grid(row=0, column=1, padx=10)

    tk.Label(main_frame, text="输入已知密文(8位二进制)：", font=label_font).grid(row=1, column=0, pady=10)
    ciphertext_entry = tk.Entry(main_frame, font=label_font)
    ciphertext_entry.grid(row=1, column=1, padx=10)

    result_label = tk.Label(main_frame, text="结果将在此显示", font=result_font)
    result_label.grid(row=3, columnspan=2, pady=10)

    def brute_force_action():
        known_plaintext = plaintext_entry.get()
        known_ciphertext = ciphertext_entry.get()

        if len(known_plaintext) != 8 or len(known_ciphertext) != 8:
            messagebox.showerror("错误", "请输入8位二进制明文和8位二进制密文！")
            return

        # 开始暴力破解
        result_label.config(text="正在进行暴力破解，请稍候...")
        root.update_idletasks()  # 更新界面显示

        # 暴力破解调用
        found_key, elapsed_time = brute_force_attack(known_plaintext, known_ciphertext, num_threads=4)

        if found_key:
            result_label.config(text=f"找到的密钥是: {found_key}，耗时: {elapsed_time:.2f} 秒")
        else:
            result_label.config(text="未能找到正确的密钥")

    tk.Button(main_frame, text="开始破解", font=button_font, command=brute_force_action).grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")
    tk.Button(main_frame, text="返回主页", font=button_font, command=show_home).grid(row=4, columnspan=2, pady=10, sticky="ew")

# 显示主页
show_home()

# 启动 Tkinter 主循环
root.mainloop()
