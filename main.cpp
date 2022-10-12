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
#include <libxml/tree.h>

#include <curl/curl.h>

/* OpenSSL headers */

# include  <openssl/bio.h>
# include  <openssl/ssl.h>
# include  <openssl/err.h>

using namespace std;

class Args{
    public:
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
                        path = argv[i];
                    }else{
                        break;
                    }
                }else{
                    if(argv[i][0] == '-' && argv[i][1] == 'f'){
                        path = argv[++i];
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

static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
  return written;
}

static void print_element_names(xmlNode * a_node)
{
    xmlNode *cur_node = NULL;

    for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE) {
            printf("node type: Element, name: %s\n", cur_node->name);
        }

        print_element_names(cur_node->children);
    }
}

int main(int argc, char** argv)
{
    Args params;
    params.init(argc, argv);
    cout << params.path << endl;

    CURL *curl_handle;
    static const char *pagefilename = "page.out";
    FILE *pagefile;

    curl_global_init(CURL_GLOBAL_ALL);
    curl_handle = curl_easy_init();
    curl_easy_setopt(curl_handle, CURLOPT_URL, params.path.c_str());
    // curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_data);
    pagefile = fopen(pagefilename, "wb");
    if(pagefile){
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, pagefile);
        curl_easy_perform(curl_handle);
        long http_code = 0;
        curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);
        fclose(pagefile);
    }
    curl_easy_cleanup(curl_handle);
    curl_global_cleanup();


    LIBXML_TEST_VERSION
    xmlDoc *doc = xmlReadFile(pagefilename, NULL, 0);
    if(doc == NULL){
        cout << "error: could not parse" << endl;
        return 1;
    }
    xmlNode *root = xmlDocGetRootElement(doc);
    print_element_names(root);
    xmlFreeDoc(doc);
    xmlCleanupParser();

    return 0;
}