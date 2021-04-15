#socket_echo_server.py
import socket
from Cryptodome.Cipher import AES
import time
import os.path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from lazyme.string import color_print

# closing will close the file and exit the client program
def closing():
    print('closing socket')
    s.close()
    exit()

#sending will send a file to the client
def sending(fname):
    server_address = (socket.gethostname(), 10100) #create a new socket address
    print("sending")
    # #if the file doesnt exit, close the socket and exit program
    # if not (os.path.exists(fname.decode())):
    #     print("file not found, closing")
    #     s.close()
    #     exit()

    #f = open(fname.decode('utf-8'), 'rb') #open the requested file
    message = open('sample.txt', 'r') #open the requested file
    buffer = 4000  # Buffer size
    key = b'Sixteen byte key' # key = get_random_bytes(16)

    while (True):
        snippet = message.read(buffer) #read buffer-sized byte section of the file
        if len(snippet) < 1: closing() #if there is no more of the file to be read, close it and end program
        with open("clientKeys/public_key.pem", "rb") as key_file:
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
    f = open('files/sample.txt', 'wb') #open file that will be written to
    try:
        while (True):
            ciphertext, ignore, nonce = ciphertext.rpartition(b'uniqueword') #separate nonce from ciphertext variable
            ciphertext, ignore, tag = ciphertext.rpartition(b'uniqueword')   #separate ciphertext and tag from ciphertext variable

            print('received {}'.format(ciphertext))
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce) #create cipher object for decryption
            plaintext = cipher.decrypt(ciphertext)           #decrypt cipher text
            decoded_plaintext = plaintext.decode()
            instruction = decoded_plaintext[0:13:1]
            decoded_plaintext = decoded_plaintext[13:]  # discard extracted information
            if instruction == "__verify__msg":
                username = decoded_plaintext.split(",")[0]
                verified = verification(username)
            elif instruction == "__verify__add":
                print("nothing")
            elif instruction == "__verify__rmv":
                print("nothing")
            decoded_plaintext = decoded_plaintext.replace(username+",", "") #removed name
            # try to verify message with tag. If its been changed in transit, throw ValueError and close file/socket and exit
            try:
                if not verified :
                    raise ValueError
                cipher.verify(tag) #verify the tag to check integrity
                print("The message is authentic : ", decoded_plaintext, " from : ", username)
            except ValueError:
                print("Key incorrect or message corrupted or access from unverified user")
                print('Closing')
                f.close()
                s.close()
                exit()
            f.write(plaintext)
            s.settimeout(2)
            ciphertext, address = s.recvfrom(buf)

    except socket.timeout:
        print('closing')
        f.close()
        s.close()
        exit()

def verification(username):
    f = open("server_files/banned_users.txt")
    for x in f:
        if username == x :
            msg = "Message from bad user : " + username + "\n"
            color_print(msg, color="red", underline=True)
            return 0
    return 1

# def add_user(username):


# Create a UDP/IP socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# Bind the socket to the port
server_address = (socket.gethostname(), 10000)

print('starting up on {} port {}'.format(*server_address))

s.bind(server_address) #bind the socket to the address
buf = 4096 #reading buffer size
key = b'Sixteen byte key' # Generate key for AES encryption


print('waiting for a connection')
ciphertext, address = s.recvfrom(buf) #recieve ciphertext sent

#if there is an isafile in a message, call sending function, else call receiving function
ignore1, ignore2, filename = ciphertext.rpartition(b'isafile')
# print("the bitch says : ",
#     "ctext : ", ciphertext,
#     "ignore1 : ", ignore1,
#     "ignore2 : ", ignore2,
#     "filename : ", filename,
# )
if ignore2:
    sending(filename)
else:
    receiving(ciphertext)
