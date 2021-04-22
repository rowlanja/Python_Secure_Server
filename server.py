import socket
from Cryptodome.Cipher import AES
import time
import os.path, os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from lazyme.string import color_print

# closing will close the file and exit the client program
# def closing():
#     print('closing socket')
#     s.close()
#     exit()

#sending will send a file to the client
def sending(name, fname):
    server_address = (socket.gethostname(), 10100) #create a new socket address
    # #if the file doesnt exit, close the socket and exit program
    # if not (os.path.exists(fname.decode())):
    #     print("file not found, closing")
    #     s.close()
    #     exit()

    #f = open(fname.decode('utf-8'), 'rb') #open the requested file
    print("sending : ", fname)
    message = open(fname.decode(), 'r') #open the requested file
    buffer = 4000  # Buffer size
    key = b'Sixteen byte key' # key = get_random_bytes(16)

    while (True):
        snippet = message.read(buffer) #read buffer-sized byte section of the file
        user_pem = 'server_files/keys/'+name.decode()+'.pem'
        print('using pem file to encrypt : ', user_pem)
        if len(snippet) < 1: break#if there is no more of the file to be read, close it and end program
        with open(user_pem, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

            # send the AES nonce and the tag over encrypted channel ecrypted by ublic key
            cipher = AES.new(key, AES.MODE_EAX) #create cipher object for encryption
            nonce = cipher.nonce #generate nonce number
            ciphertext, tag = cipher.encrypt_and_digest(snippet.encode("utf-8")) #encrypt f and generate a tag for integrity-checking

            meta_decrypt = b'uniqueword' + tag + b'uniqueword' + nonce
            print("nonce : ", nonce, " tag : ", tag)
            AES_meta_encrypted = public_key.encrypt(
                meta_decrypt,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            s.sendto(AES_meta_encrypted, server_address) #send the ciphertext, tag, and nonce to the server

            time.sleep(.05) #required to send each section error-free
            s.sendto(ciphertext, server_address) #send the ciphertext, tag, and nonce to the server

#receiving will recieve a file from the client
def receiving(ciphertext):
    try:
        while (True):
            nonce, tag = meta_decrypt(ciphertext)
            ciphertext, address = s.recvfrom(buf) #recieve ciphertext sent

            #print('received {}'.format(ciphertext))
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce) #create cipher object for decryption
            plaintext = cipher.decrypt(ciphertext)           #decrypt cipher text
            decoded_plaintext = plaintext.decode()
            instruction = decoded_plaintext[0:13:1]     # find out what instruction
            decoded_plaintext = decoded_plaintext[13:]  # discard extracted information
            print('instruction : ', instruction)
            if instruction == "__verify__msg":
                username = decoded_plaintext[:decoded_plaintext.find(",")]  # find username appended to front of original_mesage
                decoded_plaintext = decoded_plaintext.replace(username+',', '')                 # discard username
                filename = decoded_plaintext[:decoded_plaintext.find(",")]  # find filename appended to front of original_message
                decoded_plaintext = decoded_plaintext.replace(filename+',', '')                 # discard filename
                print("username : ", username, " filename : ", filename)
                verified = verification(username.encode())
            if decoded_plaintext[0:13:1] == "__verify__add":
                decoded_plaintext = decoded_plaintext[13:]+" "  # find username appended to front of original_mesage
                print("adding : ", decoded_plaintext)
                add_user(decoded_plaintext)
                verified = verification(username.encode())
            elif decoded_plaintext[0:13:1] == "__verify__rmv":
                decoded_plaintext = decoded_plaintext[13:]+" "  # find username appended to front of original_mesage
                print("removing : ", decoded_plaintext)
                rmv_user(decoded_plaintext)
                verified = verification(username.encode())
            # try to verify message with tag. If its been changed in transit, throw ValueError and close file/socket and exit
            try:
                if not verified :
                    raise ValueError
                cipher.verify(tag) #verify the tag to check integrity
                print("The message is authentic : ", decoded_plaintext, " from : ", username)
                f = open('server_files/files/'+filename, 'wb') #open file that will be written to
                f.write(decoded_plaintext.encode())
            except ValueError:
                print("Key incorrect or message corrupted or access from unverified user")
                print('Closing')
                s.close()
                exit()

            s.settimeout(2)
            ciphertext, address = s.recvfrom(buf)

    except socket.timeout:
        print('closing')
        f.close()
        s.close()
        exit()

def verification(username):
    username = username.decode().strip()
    f = open("server_files/banned_users.txt")
    for x in f:
        if username == x :
            msg = "Message from bad user : " + username + "\n"
            color_print(msg, color="red", underline=True)
            return 0
    f = open("server_files/verified_users.txt")
    for x in f:
        if username == x.strip() :
            msg = "Message from verified : " + username + "\n"
            color_print(msg, color="green", underline=True)
            return 1
    msg = "Message from bad user : " + username + "\n"
    color_print(msg, color="red", underline=True)
    return 0

def add_user(new_user_info):
    key_start = new_user_info.find('__verify__key') + 13
    username = new_user_info[:(new_user_info.find('__verify__key')-1)].strip()
    print('un : ', username)
    key = new_user_info[key_start:]
    new_user_pem_file = 'server_files/keys/' + username + '.pem'
    new_user_pem_file = new_user_pem_file.strip()
    write_verified = open("server_files/verified_users.txt", 'a')
    write_key = open(new_user_pem_file, 'wb')
    write_verified.write(username + "\n")
    write_key.write(key.encode())

def rmv_user(new_user_info):
    username = new_user_info[:(new_user_info.find('__verify__key')-1)].strip()
    verified_file = "server_files/verified_users.txt"
    print('un : ', username)
    if os.path.exists("server_files/keys/"+username+".pem"):
        os.remove("server_files/keys/"+username+".pem")
        filename = "server_files/verified_users.txt"
    else:
      print("The user is not a verified member in the group")
      return
    read = open(verified_file)
    read = list(read)
    open(verified_file, 'w').close() # clears the file
    print("read : ", read)
    with open(verified_file, 'w') as f:
      for item in read:
          print(item.strip(), " vs ",username )
          if item.strip() != username :
              print("writing : ", item)
              f.write("%s" % item)
    print("[!] User removed ", username)

def meta_decrypt(meta_decrypt):
    with open("server_files/server_keys/private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
        AES_meta = private_key.decrypt(
            meta_decrypt,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        AES_meta = AES_meta[10:]
        tag = AES_meta[:AES_meta.find(b'uniqueword')]   #separate ciphertext and tag from ciphertext variable
        AES_meta = AES_meta[10:]
        nonce = AES_meta[(AES_meta.find(b'uniqueword')+10):] #separate nonce from ciphertext variable
        return nonce, tag


# Create a UDP/IP socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# Bind the socket to the port
server_address = (socket.gethostname(), 10000)

print('starting up on {} port {}'.format(*server_address))

s.bind(server_address) #bind the socket to the address
buf = 4096 #reading buffer size
key = b'Sixteen byte key' # Generate key for AES encryption


print('waiting for a connection')
while(True):
    ciphertext, address = s.recvfrom(buf) #recieve ciphertext sent
    print("recived ciphertext : ", ciphertext)
    name_index = ciphertext.find(b'isafile')
    name = ciphertext[:name_index]
    #if there is an isafile in a message, call sending function, else call receiving function
    ignore1, ignore2, filename = ciphertext.rpartition(b'isafile')
    if ignore2 :
        print("sending : ", filename)
        sending(name, filename)
    else:
        print("recieving ")

        receiving(ciphertext)
