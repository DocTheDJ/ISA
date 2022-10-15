#include <iostream>
#include <vector>
#include <string>
#include <string_view>

// #include "HTTPClient.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <regex>
#include <libxml2/libxml/parser.h>

/* OpenSSL headers */

# include  <openssl/bio.h>
# include  <openssl/ssl.h>
# include  <openssl/err.h>

using namespace std;

class Path{
    public:
        bool is_https = false;
        char* original;
        char* scheme;
        char* host;
        char* port;
        char* path;

        void parse(char* url){
            original = url;
            if(!OSSL_parse_url(url, &scheme, NULL, &host, &port, NULL, &path, NULL, NULL)){
                cout << "failed to parse URL" << endl;
                exit(1);
            }
            if((string)scheme == "https")
                is_https = true;
            if(atoi(port) == 0){
                if(is_https){
                    port = (char*)"443\0";
                }else{
                    port = (char*)"80\0";
                }
            }
        }
};

class Args{
    public:
        Path Url;
        string path;
        string cFile;
        string cDir;
        bool f = false;
        bool T = false;
        bool a = false;
        bool u = false;

        void init(int argc, char** argv){
            for(int i = 1; i < argc; i++){
                if(((string)argv[i]).length() > 2){
                    if(path.empty()){
                        Url.parse(argv[i]);
                    }else{
                        break;
                    }
                }else{
                    if(argv[i][0] == '-' && argv[i][1] == 'f'){
                        path = (string)argv[++i];
                        f = true;
                    }else if(argv[i][0] == '-' && argv[i][1] == 'c'){
                        cFile = argv[++i];
                    }else if(argv[i][0] == '-' && argv[i][1] == 'C'){
                        cDir = argv[++i];
                    }else if(argv[i][0] == '-' && argv[i][1] == 'T'){
                        T = true;
                    }else if(argv[i][0] == '-' && argv[i][1] == 'u'){
                        u = true;
                    }else if(argv[i][0] == '-' && argv[i][1] == 'a'){
                        a = true;
                    }
                }
            }
        }

        int getCertificates(SSL_CTX* ctx){
            if(cFile.empty() && cDir.empty()){
                return SSL_CTX_set_default_verify_paths(ctx);
            }else if (cDir.empty()){
                return SSL_CTX_load_verify_locations(ctx, cFile.c_str(), NULL);
            }else{
                return SSL_CTX_load_verify_locations(ctx, NULL, cDir.c_str());
            }
        }
};

// static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
// {
//   size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
//   return written;
// }

int main(int argc, char** argv)
{
    Args params;
    params.init(argc, argv);

    BIO *bio;
    SSL_CTX *ctx;
    SSL *ssl;

    SSL_load_error_strings();
    SSL_library_init();
    if(!params.Url.is_https){
        bio = BIO_new_connect(strcat(strcat(params.Url.host, ":"), params.Url.port));
        if(bio == NULL){
            cout << "failed BIO" << endl;
            return 1;
        }
        while (BIO_do_connect(bio) <= 0) {
            if (!BIO_should_retry(bio)) {
                cout << "bio should retry failed" << endl;
                return 1;
            } else {
                continue;
            }
        }
    }else{
        ctx = SSL_CTX_new(SSLv23_client_method());
        if(!params.getCertificates(ctx)){
            cout << "certificates failed" << endl;
            return 1;
        }
        bio = BIO_new_ssl_connect(ctx);
        BIO_get_ssl(bio, &ssl);
        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
        BIO_set_conn_hostname(bio, strcat(strcat(params.Url.host, ":"), params.Url.port));
        while(BIO_do_connect(bio) <= 0){
            if (!BIO_should_retry(bio)) {
                cout << "failed bio retry" << endl;
                return 1;
            } else {
                continue;
            }
        }
        if(SSL_get_verify_result(ssl) != X509_V_OK){
            cout << "ssl verify result failed" << endl;
            return 1;
        }
    }

    string request = "GET " + ((string)params.Url.path) + " HTTP/1.0\r\nHost: " + ((string)params.Url.host) + "\r\nUser-Agent: Feedreader-xvitul03\r\nAccept: application/xml\r\nAccept-Charset: UTF-8,*\r\nCache-Control: private, no-store, max-age=0\r\nConnection: close\r\n\r\n";
    while(BIO_write(bio, request.c_str(), (request.length() + 1) * sizeof(char)) <= 0){
        if (!BIO_should_retry(bio)) {
            cout << "failed to send request" << endl;
            return 1;
        } else {
            continue;
        }
    }

    int size = 8192;
    char* response = (char*)malloc(sizeof(char) * (size + 1));
    string result = "";
    int round = 0;
    string ret_code;
    while(true){
        int len = BIO_read(bio, (void*)response, size);
        if (len < 0) {
            if (!BIO_should_retry(bio)) {
                cout << "failed bio reatry in read" << endl;
                return 1;
            } else {
                continue;
            }
        } else if (len == 0) {
            break;
        } else {
            if(round++ == 0){
                smatch m;
                result = (string)response;
                regex_search(result, m, regex("[H,h][T,t]{2}[P,p][S, s]*/1.\\d \\d{3}"));
                ret_code = m.str();
                regex_search(ret_code, m, regex("\\d{3}"));
                ret_code = m.str();
                regex_search(result, m, regex("\r\n\r\n"));
                result = (string)&response[m.position() + 4];
            }else{
                result += (string)response;
            }
            continue;
        }
    }
    if(atoi(ret_code.c_str()) != 200){
        cout << "http response is not OK" << endl;
        return 1;
    }
    cout << result << endl;
    cout << ret_code << endl;

    xmlDocPtr doc = xmlReadMemory(result.c_str(), result.length(), NULL, NULL, XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if(doc == NULL){
        cout << "failed to parse XML" << endl;
        return 1;
    }

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if(root == NULL){
        cout << "failed to get root" << endl;
        return 1;
    }

    cout << root->name << endl << root->children << endl;
    return 0;
}