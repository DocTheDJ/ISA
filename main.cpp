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
// #include <libxml/tree.h>

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
            }else if (cDir.empty())
            {
                if(! SSL_CTX_load_verify_locations(ctx, cFile.c_str(), NULL)){
                    cout << "unable to load certificate file" << endl;
                    exit(1);
                }
                return SSL_CTX_load_verify_file(ctx, cFile.c_str());
            }else{
                if(! SSL_CTX_load_verify_locations(ctx, NULL, cDir.c_str())){
                    cout << "unable to load certificate folder" << endl;
                    exit(1);
                }
                return SSL_CTX_load_verify_dir(ctx, cDir.c_str());
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
        bio = BIO_new_connect(((string)params.Url.host + ":" + (string)params.Url.port).c_str());
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
    }

    return 0;
}