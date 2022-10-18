#include <iostream>
#include <vector>
#include <string.h>
#include <regex>
#include <algorithm>
#include <fstream>
#include <stdio.h>
// #include <libxml2/libxml/parser.h>

/* OpenSSL headers */

# include  <openssl/bio.h>
# include  <openssl/ssl.h>

using namespace std;

class Path{
    public:
        bool is_https = false;
        string original;
        string scheme;
        string host;
        string port;
        string path;

        void init(char* url){
            original = url;
            parse(url);
        }

        void parse(char* url){
            smatch found;
            string tmp = (string)url;
            string rest = "";
            if(regex_search(tmp, found, regex("(.*?)://(.*)"))){
                scheme = found.str(1);
                for(long unsigned int i = 0; i < scheme.length(); i++){
                    scheme[i] = tolower(scheme[i]);
                }
                if(scheme == "https")
                    is_https = true;
                rest = found.str(2);
                if(regex_search(rest, found, regex("(.*?):(.*)"))){
                    host = found.str(1);
                    rest = found.str(2);
                    if(regex_search(rest, found, regex("(.*?)(/.*)"))){
                        if(found.str(1).empty()){
                            if(is_https)
                                port = (char*)"443\0";
                            else
                                port = (char*)"80\0";
                        }else{
                            port = found.str(1);
                        }
                        path = found.str(2);
                    }else{
                        cout << "url parse failed on port" << endl;
                    }
                }else{
                    if(is_https)
                        port = (char*)"443\0";
                    else
                        port = (char*)"80\0";
                    if(regex_search(rest, found, regex("(.*?)(/.*)"))){
                        host = found.str(1);
                        path = found.str(2);
                    }else{
                        cout << "url parse failed on host" << endl;
                    }
                }
            }else{
                cout << "url parse failed on scheme" << endl;
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
                        Url.init(argv[i]);
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
    string host_port = params.Url.host + ":" + params.Url.port;
    if(!params.Url.is_https){
        bio = BIO_new_connect(host_port.c_str());
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
        BIO_set_conn_hostname(bio, host_port.c_str());
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

    int size = 16384;
    char* response = (char*)malloc(sizeof(char) * (size + 1));
    string result = "";
    int round = 0;
    string ret_code;
    string fileName = "a.txt";
    ofstream file(fileName, ios::out | ios::trunc);
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
            cout << "len is 0" << endl;
            smatch found;
            // cout << result << endl;
            regex_search(result, found, regex("(.*)</rss>"));
            cout << found.position() << endl;
            result = result.substr(0, found.position() + ((string)"</rss>").length());
            file << result;
            break;
        } else {
            if(result != ""){
                file << result;
            }
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
                result = (string)response;
            }
            continue;
        }
    }
    if(atoi(ret_code.c_str()) != 200){
        cout << "http response is not OK" << endl;
        return 1;
    }
    BIO_free_all(bio);
    cout << ret_code << endl;
    // if(remove(fileName.c_str()) != 0)
    //     cout << "error deleting temp file" << endl;

    // xmlDocPtr doc = xmlReadMemory(result.c_str(), result.length(), NULL, NULL, XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    // if(doc == NULL){
    //     cout << "failed to parse XML" << endl;
    //     return 1;
    // }

    // xmlNodePtr root = xmlDocGetRootElement(doc);
    // if(root == NULL){
    //     cout << "failed to get root" << endl;
    //     return 1;
    // }

    // cout << root->name << endl << root->children << endl;
    return 0;
}