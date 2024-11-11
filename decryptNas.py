import tkinter as tk
from tkinter import ttk
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from CryptoMobile.CryptoMobile.Milenage import Milenage
import json
import os
import tempfile

# 获取临时文件路径
temp_file_path = os.path.join(tempfile.gettempdir(), "nas_decryption_params.json")


def save_params():
    params = {
        "nas_pdu": nas_pdu_entry.get(),
        "ue_secret_key": ue_secret_key_entry.get(),
        "operator_code": operator_code_entry.get(),
        "random_number": random_number_entry.get(),
        "autn_value": autn_value_entry.get(),
        "algorithm_id": algorithm_id_entry.get(),
        "encrypted_nas_pdu": encrypted_nas_pdu_text.get("1.0", tk.END).strip(),
        "direction": direction_var.get(),
        "bearer": bearer_var.get(),
    }
    with open(temp_file_path, "w") as temp_file:
        json.dump(params, temp_file)


def load_params():
    if os.path.exists(temp_file_path):
        with open(temp_file_path, "r") as temp_file:
            params = json.load(temp_file)
            nas_pdu_entry.insert(0, params.get("nas_pdu", ""))
            ue_secret_key_entry.insert(0, params.get("ue_secret_key", ""))
            operator_code_entry.insert(0, params.get("operator_code", ""))
            random_number_entry.insert(0, params.get("random_number", ""))
            autn_value_entry.insert(0, params.get("autn_value", ""))
            algorithm_id_entry.insert(0, params.get("algorithm_id", ""))
            encrypted_nas_pdu_text.insert("1.0", params.get("encrypted_nas_pdu", ""))
            direction_var.set(params.get("direction", "uplink"))
            bearer_var.set(params.get("bearer", "1"))


def call_milenage(sk, op, rand, sqn_xor_ak, amf, retrieved_mac):
    mil = Milenage(op)
    res, ck, ik, ak = mil.f2345(sk, rand)
    # get sqn by ak xor sqn_xor_ak
    sqn = (
        int.from_bytes(ak, byteorder="big")
        ^ int.from_bytes(sqn_xor_ak, byteorder="big")
    ).to_bytes(6, byteorder="big")
    computed_mac = mil.f1(sk, rand, sqn, amf)

    print("op", op.hex())
    print("sk:", sk.hex())
    print("rand:", rand.hex())
    print("ck:", ck.hex())
    print("ik:", ik.hex())
    print("ak:", ak.hex())
    print("sqn:", sqn.hex())
    print("computed_mac:", computed_mac.hex())

    if computed_mac != retrieved_mac:
        print("warning: mac failure!")

    return res, ck, ik


def decrypt_nas(packet, direction, bearer, cipher_key):
    msg_nas_count = int(packet[12:14], 16)
    nas_pdu = bytes.fromhex(packet)
    print("key:", cipher_key.hex())
    # get outer security header and mac+seq.
    outer_header = nas_pdu[0:7]
    # get encrypted payload only.
    encrypted_payload = nas_pdu[7:]
    # initial counter block for AES input  should be :
    # COUNT[0] .. COUNT[31] │ BEARER[0] .. BEARER[4] │ DIRECTION │ 0^26 (i.e. 26 zero bits)
    first_byte_of_bearer_and_direction = (bearer << 3) | (direction << 2)
    # AES ciphering:
    # counter_block for AES should be 16 bytes long binary string.
    counter_block = (
        msg_nas_count.to_bytes(4, byteorder="big")
        + first_byte_of_bearer_and_direction.to_bytes(1, byteorder="big")
        + b"\x00\x00\x00"
        + b"\x00" * 8
    )
    crypto = AES.new(
        cipher_key,
        mode=AES.MODE_CTR,
        nonce=counter_block[0:8],
        initial_value=counter_block[8:16],
    )
    plain_payload = crypto.decrypt(encrypted_payload)
    return plain_payload.hex()


def generate_key():
    # 获取输入框中的值
    nas_pdu = nas_pdu_entry.get()
    ue_secret_key = ue_secret_key_entry.get()
    operator_code = operator_code_entry.get()
    random_number = random_number_entry.get()
    autn_value = autn_value_entry.get()
    algorithm_id = algorithm_id_entry.get()

    if nas_pdu.startswith("7e0041"):
        id_length = int(nas_pdu[8:12], 16)
        suci: str = nas_pdu[12 : 12 + id_length * 2]
    # elif it's identity response during GUTI attach.
    elif nas_pdu.startswith("7e01") and nas_pdu[14:20] == "7e005c":
        id_length = int(nas_pdu[20:24], 16)
        suci: str = nas_pdu[24 : 24 + id_length * 2]

    # if SUPI is IMSI format:
    if suci[0] == "0":
        # if suci is not encrypted:
        if suci[13] == "0":
            bcd_supi = (
                suci[2:8] + suci[16:]
            )  # BCD string of SUPI, for example:'13001341000021f0'
    if bcd_supi:
        print("bcd_supi:", bcd_supi)
        supi = (
            bcd_supi[1]
            + bcd_supi[0]
            + bcd_supi[3]
            + bcd_supi[5]
            + bcd_supi[4]
            + bcd_supi[2]
            + bcd_supi[7]
            + bcd_supi[6]
            + bcd_supi[9]
            + bcd_supi[8]
            + bcd_supi[11]
            + bcd_supi[10]
            + bcd_supi[13]
            + bcd_supi[12]
            + bcd_supi[15]
            + bcd_supi[14]
        )
        supi = supi.replace("f", "")
        print("supi:", supi)

    mcc = suci[3] + suci[2] + suci[5]
    mnc = suci[4] + suci[7] + suci[6]
    mnc = mnc.replace("f", "0")
    snn = "5G:mnc" + mnc + ".mcc" + mcc + ".3gppnetwork.org"
    print("snn:", snn)

    secret_key = bytes.fromhex(ue_secret_key)
    op = bytes.fromhex(operator_code)
    rand = bytes.fromhex(random_number)
    autn = bytes.fromhex(autn_value)
    sqn_xor_ak = autn[:6]
    amf = autn[6:8]
    mac = autn[8:]

    res, ck, ik = call_milenage(secret_key, op, rand, sqn_xor_ak, amf, mac)

    snn_bytes: bytes = snn.encode("ascii")
    supi_bytes: bytes = supi.encode("ascii")

    # computing kausf
    input_string = (
        b"\x6a"
        + snn_bytes
        + len(snn_bytes).to_bytes(2, byteorder="big")
        + sqn_xor_ak
        + len(sqn_xor_ak).to_bytes(2, byteorder="big")
    )
    input_key = ck + ik
    kausf = bytes.fromhex(HMAC.new(input_key, input_string, SHA256).hexdigest())
    print("kausf:", kausf.hex())

    # computing kseaf
    input_string = b"\x6c" + snn_bytes + len(snn_bytes).to_bytes(2, byteorder="big")
    input_key = kausf
    kseaf = bytes.fromhex(HMAC.new(input_key, input_string, SHA256).hexdigest())
    print("kseaf:", kseaf.hex())

    # computing kamf
    abba = b"\x00\x00"
    input_string = (
        b"\x6d"
        + supi_bytes
        + len(supi_bytes).to_bytes(2, byteorder="big")
        + abba
        + b"\x00\x02"
    )
    input_key = kseaf
    kamf = bytes.fromhex(HMAC.new(input_key, input_string, SHA256).hexdigest())
    print("kamf:", kamf.hex())

    # algorithm_id ='0' for null encryption, '1' for snow3G, '2' for 'AES', '3' for ZUC
    if algorithm_id == "0":
        return
    algorithm_type_dist = b"\x01"  # type_id for nas_encryption_key
    input_string = (
        b"\x69"
        + algorithm_type_dist
        + b"\x00\x01"
        + bytes.fromhex("0" + algorithm_id)
        + b"\x00\x01"
    )
    input_key = kamf
    # cipher_key uses only last 128 bytes of HMAC output, the bytes string would be 32 bytes long
    # so get the last 16 bytes of bytes string only for cipher_key.
    # should add more logic here, add cipher_key only if auth is successful.
    cipher_key = bytes.fromhex(HMAC.new(input_key, input_string, SHA256).hexdigest())[
        16:
    ]

    # 将生成的密钥写入ciphering key文本框
    ciphering_key_entry.delete(0, tk.END)
    ciphering_key_entry.insert(0, cipher_key.hex())


def decrypt():
    # 获取输入框中的值
    encrypted_nas_pdu = encrypted_nas_pdu_text.get("1.0", tk.END).strip()
    direction = 0 if direction_var.get() == "uplink" else 1
    bearer = int(bearer_var.get())
    key = bytes.fromhex(ciphering_key_entry.get())

    decrypted_result = decrypt_nas(encrypted_nas_pdu, direction, bearer, key)

    # 将解密的结果写入结果文本框
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, decrypted_result)


# 创建主窗口
root = tk.Tk()
root.title("NAS Decryption")

# 创建并放置标签和输入框
ttk.Label(root, text="Registration request nas pdu:").grid(
    row=0, column=0, padx=10, pady=5, sticky=tk.W
)
nas_pdu_entry = ttk.Entry(root, width=50)
nas_pdu_entry.grid(row=0, column=1, padx=10, pady=5)

ttk.Label(root, text="UE Secret Key:").grid(
    row=1, column=0, padx=10, pady=5, sticky=tk.W
)
ue_secret_key_entry = ttk.Entry(root, width=50)
ue_secret_key_entry.grid(row=1, column=1, padx=10, pady=5)

ttk.Label(root, text="Operator Code:").grid(
    row=2, column=0, padx=10, pady=5, sticky=tk.W
)
operator_code_entry = ttk.Entry(root, width=50)
operator_code_entry.grid(row=2, column=1, padx=10, pady=5)

ttk.Label(root, text="Random Number:").grid(
    row=3, column=0, padx=10, pady=5, sticky=tk.W
)
random_number_entry = ttk.Entry(root, width=50)
random_number_entry.grid(row=3, column=1, padx=10, pady=5)

ttk.Label(root, text="AUTN value:").grid(row=4, column=0, padx=10, pady=5, sticky=tk.W)
autn_value_entry = ttk.Entry(root, width=50)
autn_value_entry.grid(row=4, column=1, padx=10, pady=5)

ttk.Label(root, text="Algorithm ID:").grid(
    row=5, column=0, padx=10, pady=5, sticky=tk.W
)
algorithm_id_entry = ttk.Entry(root, width=50)
algorithm_id_entry.grid(row=5, column=1, padx=10, pady=5)

# 创建并放置按钮
generate_key_button = ttk.Button(root, text="Generate Key", command=generate_key)
generate_key_button.grid(row=6, column=0, columnspan=2, pady=10)

# 创建并放置ciphering key文本框
ttk.Label(root, text="Ciphering Key:").grid(
    row=7, column=0, padx=10, pady=5, sticky=tk.W
)
ciphering_key_entry = ttk.Entry(root, width=50)
ciphering_key_entry.grid(row=7, column=1, padx=10, pady=5)

# 添加分隔符
separator = ttk.Separator(root, orient="horizontal")
separator.grid(row=8, column=0, columnspan=2, sticky="ew", padx=10, pady=10)

ttk.Label(root, text="Encrypted NAS PDU:").grid(
    row=9, column=0, padx=10, pady=5, sticky=tk.W
)
encrypted_nas_pdu_text = tk.Text(root, width=50, height=5)
encrypted_nas_pdu_text.grid(row=9, column=1, padx=10, pady=5)

# 创建并放置direction下拉选择框
ttk.Label(root, text="Direction:").grid(row=10, column=0, padx=10, pady=5, sticky=tk.W)
direction_var = tk.StringVar()
direction_combobox = ttk.Combobox(
    root, textvariable=direction_var, values=["uplink", "downlink"], state="readonly"
)
direction_combobox.grid(row=10, column=1, padx=10, pady=5, sticky=tk.W)
direction_combobox.current(0)  # 默认选择第一个选项

# 创建并放置bearer下拉选择框
ttk.Label(root, text="Bearer:").grid(row=11, column=0, padx=10, pady=5, sticky=tk.W)
bearer_var = tk.StringVar()
bearer_combobox = ttk.Combobox(
    root, textvariable=bearer_var, values=["0", "1"], state="readonly"
)
bearer_combobox.grid(row=11, column=1, padx=10, pady=5, sticky=tk.W)
bearer_combobox.current(1)  # 默认选择第二个选项

# 创建并放置按钮
decrypt_button = ttk.Button(root, text="Decrypt", command=decrypt)
decrypt_button.grid(row=12, column=0, columnspan=2, pady=10)

# 创建并放置结果文本框
ttk.Label(root, text="Decrypt Result:").grid(
    row=13, column=0, padx=10, pady=5, sticky=tk.W
)
result_text = tk.Text(root, width=50, height=5)
result_text.grid(row=13, column=1, padx=10, pady=5)

# 加载之前保存的参数
load_params()

# 在窗口关闭时保存参数
root.protocol("WM_DELETE_WINDOW", lambda: (save_params(), root.destroy()))

# 运行主循环
root.mainloop()
