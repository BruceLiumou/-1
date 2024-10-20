import threading
import time
from sdes_algorithm import encrypt, str_to_bin_list, bin_list_to_str

# 全局变量用于保存破解结果
found_key = None

# 生成所有可能的10位二进制密钥
def generate_keys():
    return [format(i, '010b') for i in range(1024)]  # 生成所有可能的10位二进制密钥

# 暴力破解线程函数，尝试一组密钥
def brute_force_worker(known_plaintext, known_ciphertext, key_list, thread_id):
    global found_key
    for key in key_list:
        if found_key:
            return
        key_bits = str_to_bin_list(key, 10)
        if bin_list_to_str(encrypt(str_to_bin_list(known_plaintext, 8), key_bits)) == known_ciphertext:
            found_key = key
            print(f"线程{thread_id} 找到了正确的密钥: {key}")
            return

# 暴力破解函数，使用多线程
def brute_force_attack(known_plaintext, known_ciphertext, num_threads=4):
    global found_key
    found_key = None
    keys = generate_keys()
    keys_per_thread = len(keys) // num_threads
    threads = []
    start_time = time.time()

    # 创建并启动多个线程
    for i in range(num_threads):
        start, end = i * keys_per_thread, (i + 1) * keys_per_thread if i < num_threads - 1 else len(keys)
        thread = threading.Thread(target=brute_force_worker, args=(known_plaintext, known_ciphertext, keys[start:end], i))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    elapsed_time = time.time() - start_time
    print(f"暴力破解完成，耗时 {elapsed_time:.2f} 秒")
    return found_key, elapsed_time if found_key else (None, elapsed_time)
