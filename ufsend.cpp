#include<iostream>
#include<openssl/ssl.h>
#include<openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include<fstream>
#include<string>
#include<filesystem>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include<stdio.h>
#include<stdlib.h>


using namespace std;
namespace fs = filesystem;


void write_file(char *filename,unsigned char *filedata,int filelength) //writing a file
{
    ofstream file(filename, ios::binary);
    file.write((const char *)filedata,filelength);
    file.flush();
    file.close();

}

int get_ip_port(char *address, char *ip)   // address taken from argument 2 of command line is split into ip and port here
{
    
    char delimiter = ':';
    int i=0;
    int j=0;
    char *portstr = new char[30];
    while(address[i] != delimiter)
    {
        ip[i]=address[i];
        i++;
    }
    ip[i+1]='\0';
    i=i+1;
    while(address[i] != '\0')
        {
            portstr[j] = address[i];        // portstr stores port number that is all digits after ':' as char*
            i++;
            j++;
        }
    int port = atoi(portstr);           // atoi converts char* to int
    return port;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        cout<<"error1";

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv))  // Initializing encryption using aes 256 in gcm, 32 byte key, 16 byte iv
                                                                            
        cout<<"error2";

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        cout<<"error3";
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        cout<<"error4";
    ciphertext_len += len;


    EVP_CIPHER_CTX_free(ctx);               // freeing ctx

    return ciphertext_len;
}

unsigned char* randomivgenerator()
{
    unsigned char *iv;
    iv = (unsigned char *)malloc(sizeof(char)*32);
    RAND_bytes(iv, 16); // generates 16 random bytes using a cryptographically secure pseudo random generator
    return iv;
}

void printkey(unsigned char* key)
{
    printf("Key: ");
    for (size_t i=0; i<32; ++i)
        printf("%02x ", key[i]);
    printf("\n");
}

char* usercreatepwd()
{
    cout << "Create a Password" << "\n";
    char* pwd = new char[1024];
    cin >> pwd;
    return pwd;
}

unsigned char* keygenerator(const char* pwd, const unsigned char* salt)  // implementing PBKDF2
{
    int keylen = 32;
    unsigned char *out;
    out = (unsigned char *)malloc(sizeof(char)*32);
    unsigned int iterations = 4096;
    PKCS5_PBKDF2_HMAC(pwd, strlen(pwd),
                      salt, strlen(salt), iterations,
                      EVP_sha3_256(),
                      keylen, out);
 

    return out;

}

int main(int argc, char** argv)  
{
    char *userpassword;
    char *address = new char[9999]; 
    char *ip=new char[9999];
    int port;
    const unsigned char *salt = "SodiumChloride";
    unsigned char *key,*iv;
    char *inputfilename = argv[1];    // taking the file containing plain text data (which is to be encrypted) as first argument
    char *encryptedfilename = new char[99999]; // encrypted file name - being saved as [name of input file + '.ufsec']
    char iv_filename[30] = "iv.txt";    //creating local iv file which contains the iv 
    strcpy(encryptedfilename,inputfilename);
    strcat(encryptedfilename,".ufsec");  // creating .ufsec file
    
    if (fs::exists(encryptedfilename))     // checking if encrypted file already exists  
    {
        cout << "File Already Exists" << endl;
        return 33;
    }
    userpassword = usercreatepwd();     // taking user defined password
    char *inputfiledata;        // character array to read plain text data from the input file 
    int inputdatalength;
    char *filetransfer_switch = argv[2]; // controls whether to run in -d(daemon mode) or -l(local mode)
    unsigned char ciphertext[99999];  // variable to store cipher text

    ifstream inputfile(inputfilename);  // opening input file
    inputfile.seekg(0,inputfile.end);
    inputdatalength = inputfile.tellg();    // extracting length of plain text and storing in input data length
    inputfile.seekg(0,inputfile.beg);

   
    inputfiledata = new char[inputdatalength];
    inputfile.read(inputfiledata,inputdatalength); 

    unsigned char *plaintext = (unsigned char *)inputfiledata;  // reading plain text data and storing it in inputfiledata variable 
    
    key = keygenerator(userpassword,salt);
    printkey(key);                          // printing 32 bit key generated by PBKDF2 in hex
    
    iv = randomivgenerator();               // generating 16 bit random iv

    int ciphertext_len = encrypt(plaintext,inputdatalength,key, iv, ciphertext);  //encryption 
    printf("cipher text: \n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len); //printing cipher text in hex

    if(strcmp(filetransfer_switch,"-d") == 0)               // Daemon mode
    {  
        printf("Running in Daemon mode\n");
        address = argv[3];
        port = get_ip_port(address,ip);
        cout << "Transmitting to " << ip << ":" << port << endl;
        
        int sock = 0, client_fd;
        struct sockaddr_in serv_addr;
        char *ciphermessage = (char *)ciphertext;               //buffer holding cipher text to be sent
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {     // socket creation
            printf("\n Socket creation error \n");
            return -1;
        }
    
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);
        serv_addr.sin_addr.s_addr = inet_addr(ip);
  
    if ((client_fd
         = connect(sock, (struct sockaddr*)&serv_addr,     // socket connection
                   sizeof(serv_addr)))
        < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }
    send(sock, iv, 16, 0);                              // sending iv to server
    send(sock, ciphermessage, ciphertext_len,0);        // sending cipher text
    printf("ciphertext sent\n");
    close(client_fd);

    }
    else if(strcmp(filetransfer_switch,"-l") == 0)      // local mode
    {
        printf("Running in local mode\n");
        write_file(encryptedfilename,ciphertext,ciphertext_len);    // writing cipher text to a *.ufsec file
        write_file(iv_filename,iv,32);                              // writing iv to a .txt file
        printf("Encryption file created\n");
    }
    return 0;
}





