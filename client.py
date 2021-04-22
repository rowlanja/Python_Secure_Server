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

def verify():
    header = "__verify__"
    user = "Paulo"

#sending will send a file to the server
def sending(username, upload_filename):
    filename = "client_files/"+upload_filename  # File wanting to send
    f = open(filename, 'rb')  # Open file
    buf = 4000  # Buffer size

    while (True):
        l = f.read(buf) #read buffer-sized byte section of the file
        if len(l) < 1: closing() #if there is no more of the file to be read, close it and end program
        with open("server_files/server_keys/public_key.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

            l = str.encode("__verify__msg"+username+","+upload_filename+",") + l
            cipher = AES.new(key, AES.MODE_EAX) #create cipher object for encryption
            nonce = cipher.nonce #generate nonce number
            ciphertext, tag = cipher.encrypt_and_digest(l) #encrypt f and generate a tag for integrity-checking
            meta_decrypt = b'uniqueword' + tag + b'uniqueword' + nonce
            print("decrypted : ", meta_decrypt)
            AES_meta_encrypted = public_key.encrypt(
                meta_decrypt,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            color_print("\n[!] sending", color="red", underline=True)
            # concatinate the ciphertext, tag, and nonce separate by uniqueword pattern so that they can be separated on the server
            print("meta decrypt : ",AES_meta_encrypted)
            s.sendto(AES_meta_encrypted, server_address) #send the ciphertext, tag, and nonce to the server
            time.sleep(.05) #required to send each section error-free
            s.sendto(ciphertext, server_address) #send the ciphertext, tag, and nonce to the server


#receiving will recieve a file from the server
def recieving(username, filename):
    buf = 4096 #reading buffer size
    original_file = filename    #keep copy of filename sent to server
    filename = filename.encode()  # File wanting to recieve

    # concatinate isafile with requested filename so it can be distingueshed as a client-recieving command
    filename = username.encode() + b'isafile' + filename
    #print("sending {}".format(filename))
    s.sendto(filename, server_address) #send requested filename to server

    # Create a UDP/IP socket
    r = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind the socket to the port
    new_server_address = (socket.gethostname(), 10100)
    r.bind(new_server_address) #bind the socket to the address

    color_print("\n[!] waiting for a connection ", color="red", underline=True)
    complete_plaintext = ''
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
                    #print("decrypted with keys : ", original_message)
                    original_message, ignore, nonce = original_message.rpartition(b'uniqueword') #separate nonce from ciphertext variable
                    original_message, ignore, tag = original_message.rpartition(b'uniqueword')   #separate ciphertext and tag from ciphertext variable
                    #print("nonce : ", nonce, " tag : ", tag)
                    ciphertext, address = r.recvfrom(buf) #begin recieving file
                    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce) #create cipher object for decryption
                    plaintext = cipher.decrypt(ciphertext) #decrypt cipher text
                    #try to verify message with tag. If its been changed in transit, throw ValueError and close file/socket and exit
                    try:
                        cipher.verify(tag) #verify the tag to check integrity
                        print("The download is authentic")
                        complete_plaintext += plaintext.decode()
                    except ValueError:
                        print("Key incorrect or message corrupted")
                        print('closing')
                        s.close()
                        exit()

        except socket.timeout:
            # if we recieved the file list we print it out to the user and ask for what file from the file list they want to recieve
            if original_file == "server_files/file_list.txt" :
                print('finished recieving file list : ', complete_plaintext)
                return complete_plaintext
            else :
            # else we have received a file and just save it to the user files
                print('finished recieving file : ', complete_plaintext)
                fnew = open('client_files/download.txt', 'wb') #file name for new file
                fnew.write(complete_plaintext.encode()) #write data to the new file
                fnew.close()

            s.close()
            r.close()
            exit()
    exit()

def pick_file(file_list):
    file_list = file_list.split()
    for index in range(len(file_list)):
        print("[%d] %s" % (index, file_list[index]))
    req_index = input("[!] Enter index of requested file : ")
    return file_list[int(req_index)]
# #create our public/private keys for the client
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()
#store our public key & private key
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

with open('clientKeys/server_keys/private_key.pem', 'wb') as f:
    f.write(pem)

pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open('clientKeys/server_keys/public_key.pem', 'wb') as f:
    f.write(pem)

#print("keys : ", private_key, public_key)
# Create a UDP/IP socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# Bind the socket to the port
server_address = (socket.gethostname(), 10000)
# Generate key for AES encryption
key = b'Sixteen byte key'
# username = input("Please enter your username : ")
# cors = input("Are you receiving or sending? (r or s)")
username = 'Joeseph'
cors = 'r'
#if sending a file, go to sending function, else if receiving a file go to receiving function, else repeat
while True:
    if cors == 'r' or cors == 'R':
        file_list = recieving(username, "server_files/file_list.txt")
        file_choice = pick_file(file_list)
        print("requesting ", file_choice)
        file_list = recieving(username, ("server_files/files/"+file_choice))
    elif cors == 's' or cors == 'S':
        # upload_filename = input("Upload : ")

        upload_filename = "upload.txt"
        # upload_filename = 'sample_rmv_user.txt' # to rmv user
        # upload_filename = 'sample_rmv_user.txt' # to add user
        sending(username, upload_filename)
    else:
        cors = input("Enter r or s (r or s)")
