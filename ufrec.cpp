#include<iostream>
#include<openssl/ssl.h>
#include<openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include<fstream>
#include<string>
#include<filesystem>
#include<netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include<stdio.h>
#include<stdlib.h>

using namespace std;
namespace fs = filesystem;

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)                        // decrypt function
{
    EVP_CIPHER_CTX *ctx;        // initializing context

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        cout<<"error5";


    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv))  // initializing decryption using aes_256_gcm, 32 byte key, 16 byte iv
        cout<<"error6";

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        cout<<"error7";
    plaintext_len = len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

char* userauthpwd()     // entering password  
{
    cout << "Enter Password" << "\n";
    char* pwd = new char[1024];
    cin >> pwd;
    return pwd;
}


void printkey(unsigned char* key) // displaying pbkdf2 generated key
{
    printf("Key: ");
    for (size_t i=0; i<32; ++i)
        printf("%02x ", key[i]);
    printf("\n");
}


unsigned char* keygenerator(const char* pwd, const unsigned char* salt)
{
    int keylen = 32;
    //unsigned char out[32];
    unsigned char *out;
    out = (unsigned char *)malloc(sizeof(char)*32);
    unsigned int iterations = 4096;
    PKCS5_PBKDF2_HMAC(pwd, strlen(pwd),
                      salt, strlen(salt), iterations,
                      EVP_sha3_256(),
                      keylen, out);
    //unsigned char *key = out+0;
    

    return out;

}


int main(int argc, char** argv)
{
    
    char *userpassword;
    char *inputfilename = argv[1];          // taking input filename that is, .ufsec file
    char *decryptedfilename = new char[1024];
    char *inputfiledata;
    int inputdatalength;
    const unsigned char *salt = "SodiumChloride";
    unsigned char *key,*iv;
    iv = (unsigned char*)malloc(sizeof(char)*16);
    char iv_filename[30] = "iv.txt";        // for local mode, reading iv from a separate .txt file, iv.txt was generated by ufsend and has iv stored in it

    int server_fd, new_socket, valrecv;         // initializing all required variables for server side socket programming  
    struct sockaddr_in address,newaddress;      
    
    socklen_t addrlen;

    for(size_t i=0; i < strlen(inputfilename)-6;i++)
    {
        decryptedfilename[i] = inputfilename[i];    // decrypted file name creates name of output file, removes .ufsec extension from input file provided in commandline arg
    }
  
    char *filetransfer_switch = argv[2];
    char *portstr = new char[30];
    int port;
    userpassword = userauthpwd();

    if(fs::exists(decryptedfilename))           // if file already exists,then the code exits
    {
        cout << "File already exists";
        return 33;
    }

    key = keygenerator(userpassword,salt);      // generates pbkdf2 derived key
    printkey(key);                              // prints 32 byte key

    

    if(strcmp(filetransfer_switch,"-d") == 0)       
    {  
      printf("running in daemon mode\n");
       portstr = argv[3];
       port = atoi(portstr);                    // converting port number to int
       cout << "Waiting for data on port " << port << endl;
       
       char buffer[1024] ;                      // buffer used to receive data
       
        // Creating socket file descriptor
        if ((server_fd = socket(AF_INET, SOCK_STREAM, 0))
            == 0) {
            perror("socket failed");
            exit(EXIT_FAILURE);
        }
    
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
         address.sin_port = htons(port);
        

        if (bind(server_fd, (struct sockaddr*)&address,
             sizeof(address))                           // socket binding
        < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
        }
        if (listen(server_fd, 10) < 0) {
            perror("listen");
            exit(EXIT_FAILURE);
        }
        addrlen = sizeof(newaddress);
        if ((new_socket
            = accept(server_fd, (struct sockaddr*)&newaddress,
                    &addrlen))
            < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        FILE *temp_file;                                // writing cipher text received from ufsend to input file provided by commandline that is, *.ufsec file 
        temp_file=fopen(inputfilename,"w");
      
        printf("receiving ciphertext\n");
        while(1)
        {
           
            valrecv = recv(new_socket,buffer,1024,0);       // receiving data
            if(valrecv <= 0)
            {
                printf("cipher text received\n");
                break;
            }
            
           
            fwrite(buffer,sizeof(char),valrecv,temp_file);      // writing data to *.ufsec file
           
            memset(buffer,0,sizeof(buffer));
            
        }
        
        fclose(temp_file);
        
    // closing the connected socket
        close(new_socket);
    // closing the listening socket
        shutdown(server_fd, SHUT_RDWR);
        FILE *cipher_iv_file;                                   // reading back data from *.ufsec in order to get back iv and decrypt the ciphertext
        cipher_iv_file = fopen(inputfilename,"r");
        fseek(cipher_iv_file,0,SEEK_END);
        inputdatalength = ftell(cipher_iv_file);
        inputfiledata = new char[inputdatalength-16];
        fseek(cipher_iv_file,0,SEEK_SET);
        fread(iv,sizeof(char),16,cipher_iv_file);
        fread(inputfiledata,sizeof(char),inputdatalength-16,cipher_iv_file);

    }
    else if(strcmp(filetransfer_switch,"-l") == 0)
    {
        printf("running in local mode\n");
       char *iv_buf; 
       ifstream ivfile(iv_filename,ios::binary);
       ivfile.seekg(0,ivfile.end);
       int ivlength = ivfile.tellg();
       ivfile.seekg(0,ivfile.beg);
       iv_buf = new char[ivlength];
       ivfile.read(iv_buf,ivlength);
       
       iv = (unsigned char*)iv_buf;
       
      

         ifstream inputfile(inputfilename, ios::binary);
        inputfile.seekg(0,inputfile.end);
        inputdatalength = inputfile.tellg();
        inputfile.seekg(0,inputfile.beg);

        
        inputfiledata = new char[inputdatalength];

        inputfile.read(inputfiledata,inputdatalength);
        inputfile.close();  
    }
    
    
           
    
    unsigned char *ciphertext = (unsigned char *)inputfiledata;

    unsigned char decryptedtext[99999];
    int decryptedtext_len;
    if(strcmp(filetransfer_switch,"-d") == 0)
    {
    decryptedtext_len = decrypt(ciphertext, inputdatalength-16, key, iv, decryptedtext);
    BIO_dump_fp (stdout, (const char *)inputfiledata, inputdatalength-16);                  // printing ciphertext
    }

    if(strcmp(filetransfer_switch,"-l") == 0)
    {
    decryptedtext_len = decrypt(ciphertext, inputdatalength, key, iv, decryptedtext);
    BIO_dump_fp (stdout, (const char *)inputfiledata, inputdatalength);                     // printing ciphertext
    }

    decryptedtext[decryptedtext_len] = '\0'; 
    //cout << decryptedtext_len;
    /* Show the decrypted text */
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);                                                          // printing back original data
    ofstream decryptedfile(decryptedfilename,ios::binary);
    
    decryptedfile.write((const char *)decryptedtext,decryptedtext_len);
    decryptedfile.flush();
    decryptedfile.close();

    cout << "Successfully received and decrypted the file";
    

    return 0;
}



    



