import socket
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from Cryptodome.Cipher import AES
from lazyme.string import color_print
# closing will close the file and exit the client program
def closing():
    print('closing socket')
    s.close()
    exit()

#sending will send a file to the server
def sending():
    filename = "sample.txt"  # File wanting to send
    f = open(filename, 'rb')  # Open file
    buf = 4000  # Buffer size

    while (True):
        l = f.read(buf) #read buffer-sized byte section of the file
        if len(l) < 1: closing() #if there is no more of the file to be read, close it and end program

        cipher = AES.new(key, AES.MODE_EAX) #create cipher object for encryption
        nonce = cipher.nonce #generate nonce number
        ciphertext, tag = cipher.encrypt_and_digest(l) #encrypt f and generate a tag for integrity-checking
        color_print("\n[!] sending : ", ciphertext, color="red", underline=True)
        # concatinate the ciphertext, tag, and nonce separate by uniqueword pattern so that they can be separated on the server
        ciphertext = ciphertext + b'uniqueword' + tag + b'uniqueword' + nonce
        time.sleep(.01) #required to send each section error-free
        s.sendto(ciphertext, server_address) #send the ciphertext, tag, and nonce to the server


#receiving will recieve a file from the server
def recieving():
    buf = 4096 #reading buffer size
    filename = b"files/sample.txt"  # File wanting to recieve
    fnew = open(filename.decode('utf-8'), 'wb') #file name for new file

    # concatinate isafile with requested filename so it can be distingueshed as a client-recieving command
    filename = b'isafile' + filename
    #print("sending {}".format(filename))
    s.sendto(filename, server_address) #send requested filename to server

    # Create a UDP/IP socket
    r = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind the socket to the port
    new_server_address = (socket.gethostname(), 10100)
    r.bind(new_server_address) #bind the socket to the address

    color_print("\n[!] waiting for a connection ", color="red", underline=True)

    while (True):
        #if failed, will throw socket.timeout exception and file/socket will be closed/exited
        try:
            while (True):
                #read in the public key from teh key files
                with open("clientKeys/private_key.pem", "rb") as key_file:
                    private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=None,
                        backend=default_backend()
                    )
                    r.settimeout(2) #will throw socket.timeout exception when it isn't recieving anymore data

                    ciphertext, address = r.recvfrom(buf) #begin recieving file
                    print("recived ciphertext : ", ciphertext, "\nfrom : ", address)
                    original_message = private_key.decrypt(
                        ciphertext,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    print("decrypted with keys : ", original_message)
                    original_message, ignore, nonce = original_message.rpartition(b'uniqueword') #separate nonce from ciphertext variable
                    original_message, ignore, tag = original_message.rpartition(b'uniqueword')   #separate ciphertext and tag from ciphertext variable

                    print('format encrypted {}'.format(original_message))
                    print('tag {}'.format(tag))
                    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce) #create cipher object for decryption
                    plaintext = cipher.decrypt(original_message) #decrypt cipher text

                    #try to verify message with tag. If its been changed in transit, throw ValueError and close file/socket and exit
                    try:
                        cipher.verify(tag) #verify the tag to check integrity
                        print("The message is authentic:", plaintext)
                    except ValueError:
                        print("Key incorrect or message corrupted")
                        print('closing')
                        fnew.close()
                        s.close()
                        exit()
                    fnew.write(plaintext) #write data to the new file

        except socket.timeout:
            print('closing')
            fnew.close()
            s.close()
            r.close()
            exit()
    exit()
# #create our public/private keys for the client
# private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048,
#     backend=default_backend()
# )
# public_key = private_key.public_key()
# #store our public key & private key
# pem = private_key.private_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PrivateFormat.PKCS8,
#     encryption_algorithm=serialization.NoEncryption()
# )
#
# with open('clientKeys/private_key.pem', 'wb') as f:
#     f.write(pem)
#
# pem = public_key.public_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PublicFormat.SubjectPublicKeyInfo
# )
#
# with open('clientKeys/public_key.pem', 'wb') as f:
#     f.write(pem)

#print("keys : ", private_key, public_key)
# Create a UDP/IP socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# Bind the socket to the port
server_address = (socket.gethostname(), 10000)
# Generate key for AES encryption
key = b'Sixteen byte key'

cors = input("Are you receiving or sending? (r or s)")

#if sending a file, go to sending function, else if receiving a file go to receiving function, else repeat
while True:
    if cors == 'r' or cors == 'R':
        recieving()
    elif cors == 's' or cors == 'S':
        sending()
    else:
        cors = input("Enter r or s (r or s)")
