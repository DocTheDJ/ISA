#include <iostream>
#include <vector>
#include <string.h>
#include <regex>
#include <algorithm>
#include <fstream>
#include <stdio.h>
#include <iterator>
#include <list>
#include <libxml2/libxml/parser.h>
#include <libxml2/libxml/tree.h>

/* OpenSSL headers */

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;

class Path{
    public:
        bool is_https = false;
        bool is_rss = false;
        string original;
        string scheme;
        string host;
        string port;
        string path;
        string result = "";

        Path init(char* url){
            original = url;
            parse(url);
            return *this;
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

	void getFinish(string last){
		size_t found_at = last.find("</rss>");
		if(found_at != string::npos){
			last = last.substr(0, found_at + ((string)"</rss>").length());
			result += last;
			return;
		}
		found_at = last.find("</feed>");
		if(found_at != string::npos){
			last = last.substr(0, found_at + ((string)"</feed>").length());
			result += last;
			return;
		}
		result += last;
		found_at = result.find("</rss>");
		if(found_at != string::npos){
			result = result.substr(0, found_at + ((string)"</rss>").length());
			return;
		}
		found_at = result.find("</feed>");
		if(found_at != string::npos){
			result = result.substr(0, found_at + ((string)"</feed>").length());
		}
	}
};

class Args{
    public:
        list<Path> Urls;
        list<string> paths;
        list<string> cFiles;
	    list<string> cDirs;
        bool f = false;
        bool T = false;
        bool a = false;
        bool u = false;

        void init(int argc, char** argv){
            for(int i = 1; i < argc; i++){
                int ret = isOneOfParams(argv[i]);
                if(!ret){
                    Urls.push_back(Path().init(argv[i]));
                    continue;
                }
                if(ret == 1 || ret == 2 || ret == 6){
                    shouldNotBeParam(argv[++i], ret);
                }
            }
            if(f){
                list<string>::iterator files;
                for(files = paths.begin(); files != paths.end(); ++files){
                    readUrlsFromFile(*files);
                }
            }
        }

    private:
        int isOneOfParams(string param){
            if(param == "-c")
                return 1;
            if(param == "-C")
                return 2;
            if(param == "-T"){
                T = true;
                return 3;
            }
            if(param == "-u"){
                u = true;
                return 4;
            }
            if(param == "-a"){
                a = true;
                return 5;
            }
            if(param == "-f"){
                f = true;
                return 6;
            }
            return 0;
        }

        void shouldNotBeParam(string param, int target){
            if(isOneOfParams(param)){
                cout << "invalid argument sequence" << endl;
                exit(1);
            }else{
                switch(target){
                    case 1:
                        cFiles.push_back(param);
                        break;
                    case 2:
                        cDirs.push_back(param);
                        break;
                    case 6:
                        paths.push_back(param);
                        break;
                    default:
                        cout << "error in arguments" << endl;
                        exit(1);
                }
            }
        }
	
	void readUrlsFromFile(string path){
		std::ifstream ifs(path);
		string tmp;
		while(getline(ifs, tmp)){
			ltrim(tmp);
			if(!(tmp.empty())){
				if(!strncmp(tmp.c_str(), "#", strlen("#")))
					continue;
				else
					Urls.push_back(Path().init((char*)(tmp.c_str())));
			}
		}
		ifs.close();
	}
	
	static inline void ltrim(std::string &s) {s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {return !std::isspace(ch);}));
}
};

class Communication{
    private:
        BIO *bio;
        SSL_CTX *ctx;
        SSL *ssl;
        char* response;
    public:
        int run(Path* Url, Args params){
            SSL_load_error_strings();
            SSL_library_init();
            string host_port = Url->host + ":" + Url->port;
            if(!Url->is_https){
                bio = BIO_new_connect(host_port.c_str());
                if(bio == NULL){
                    cleanup(3);
                    cout << "failed BIO" << endl;
                    return 1;
                }
                while (BIO_do_connect(bio) <= 0) {
                    if (!BIO_should_retry(bio)) {
                        cout << "bio should retry failed" << endl;
                        cleanup(2);
                        return 1;
                    } else {
                        continue;
                    }
                }
            }else{
                ctx = SSL_CTX_new(SSLv23_client_method());
                getCertificates(params);
                bio = BIO_new_ssl_connect(ctx);
                BIO_get_ssl(bio, &ssl);
		        SSL_set_tlsext_host_name(ssl, Url->host.c_str());
                SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
                BIO_set_conn_hostname(bio, host_port.c_str());
                while(BIO_do_connect(bio) <= 0){
                    if (!BIO_should_retry(bio)) {
                        cout << "failed bio retry" << endl;
                        cleanup(1);
                        return 1;
                    } else {
                        continue;
                    }
                }
                if(SSL_get_verify_result(ssl) != X509_V_OK){
                    cout << "ssl verify result failed" << endl;
                    cleanup(1);
                    return 1;
                }
            }

            string request = "GET " + ((string)Url->path) + " HTTP/1.0\r\nHost: " + ((string)Url->host) + "\r\nUser-Agent: Feedreader-xvitul03\r\nAccept: application/xml\r\nAccept-Charset: UTF-8,*\r\nCache-Control: private, no-store, max-age=0\r\nConnection: close\r\n\r\n";
            while(BIO_write(bio, request.c_str(), (request.length() + 1) * sizeof(char)) <= 0){
                if (!BIO_should_retry(bio)) {
                    cout << "failed to send request" << endl;
                    cleanup(1);
                    return 1;
                } else {
                    continue;
                }
            }

            int size = 16384;
            response = (char*)malloc(sizeof(char) * (size + 1));
            int round = 0;
            string ret_code;
            string tmp = "";
            while(true){
                int len = BIO_read(bio, (void*)response, size);
		        response[len] = 0;
                if (len < 0) {
                    if (!BIO_should_retry(bio)) {
                        cout << "failed bio reatry in read" << endl;
                        cleanup(0);
                        return 1;
                    } else {
                        continue;
                    }
                } else if (len == 0) {
			        Url->getFinish(tmp);
	                break;
                } else {
		        	Url->result += tmp;
                    if(round++ == 0){
			            smatch m;
                        tmp = (string)response;
                        regex_search(tmp, m, regex("[H,h][T,t]{2}[P,p][S, s]*/1.\\d (\\d{3})"));
                        ret_code = m.str(1);
                        regex_search(tmp, m, regex("\r\n\r\n"));
                        tmp = (string)&response[m.position() + 4];
                    }else{
                        tmp = (string)response;
                    }
                    continue;
                }
            }
            if(atoi(ret_code.c_str()) != 200){
                cout << "http response is not OK" << endl;
                cleanup(0);
                return 1;
            }
            cleanup(0);
            return 0;
        }
    private:
        void getCertificates(Args params){
            if(params.cFiles.empty()){
                if(!SSL_CTX_set_default_verify_paths(ctx)){
                    cout << "certificates failed" << endl;
                    exit(1);
                }
            }else {
                list<string>::iterator files;
                for(files = params.cFiles.begin(); files != params.cFiles.end(); ++files){
                    if(!SSL_CTX_load_verify_locations(ctx, (*files).c_str(), NULL)){
                        cout << "certificates failed" << endl;
                        exit(1);
                    }
                }
		        for(files = params.cDirs.begin(); files != params.cDirs.end(); ++files){
                    if(!SSL_CTX_load_verify_locations(ctx, NULL, (*files).c_str())){
                        cout << "certificates failed" << endl;
                        exit(1);
                    }
                }
            }
        }

        void cleanup(int way){
            if(way < 4)
                ERR_free_strings();
            if(way < 3)
                BIO_free_all(bio);
            if(way < 2)
                SSL_CTX_free(ctx);
            if(way < 1)
                free(response);
        }
};

xmlNodePtr findNodeByName(xmlNodePtr root, const xmlChar* name){
	xmlNodePtr node = root;
	if(node == NULL)
		return NULL;
	while(node != NULL){
		if(!xmlStrcmp(node->name, name)){
			return node;
		}else if(node->children != NULL){
			xmlNodePtr res = findNodeByName(node->children, name);
			if(res != NULL)
				return res;
		}
		node = node->next;
	}
	return NULL;
}

void printData(xmlNodePtr node, string preFix, string postFix){
        xmlChar* tmp = xmlNodeGetContent(node);
        cout << preFix << (char*)tmp << postFix;
        xmlFree(tmp);
}


void getDesiredData(xmlNodePtr node, Args params, bool rss){
	xmlNodePtr title = findNodeByName(node, (xmlChar*)(((string)"title").c_str()));
	if(title != NULL)
		printData(title, "", "\n");
	if(rss){
		if(params.u){
			title = findNodeByName(node, (xmlChar*)(((string)"link").c_str()));
			if(title != NULL)
				printData(title, "URL: ", "\n");
		}
		if(params.T){
			title = findNodeByName(node, (xmlChar*)(((string)"pubDate").c_str()));
			if(title != NULL)
				printData(title, "Aktualizace: ", "\n");
		}
		if(params.a){
			title = findNodeByName(node, (xmlChar*)(((string)"author").c_str()));
			if(title != NULL)
				printData(title, "Autor: ", "\n");
		}
		if(params.u || params.T || params.a)
			cout << endl;
		return;
	}else{
		if(params.u){
			title = findNodeByName(node, (xmlChar*)(((string)"link").c_str()));
			if(title != NULL){
				xmlChar* tmp = xmlGetProp(title, (xmlChar*)(((string)"href").c_str()));
				cout << "URL: " << (char*)tmp << endl;
				xmlFree(tmp);
			}
		}
		if(params.T){
			title = findNodeByName(node, (xmlChar*)(((string)"updated").c_str()));
			if(title != NULL)
				printData(title, "Aktualizace: ", "\n");
		}
		if(params.a){
			title = findNodeByName(node, (xmlChar*)(((string)"author").c_str()));
			if(title != NULL){
				cout << "Autor: ";
				xmlNodePtr name = findNodeByName(title, (xmlChar*)(((string)"name").c_str()));
				if(name != NULL)
					printData(name, "Autor: ", "");
				name = findNodeByName(title, (xmlChar*)(((string)"email").c_str()));
				if(name != NULL)
					printData(name, "", "\n");
			}
		}
		if(params.u || params.T || params.a)
			cout << endl;
		return;
	}
}

void xmlCleanUp(xmlDocPtr doc){
	xmlFreeDoc(doc);
        xmlCleanupParser();
        xmlMemoryDump();
        cout << endl;
}

int main(int argc, char** argv)
{
    Args params;
    params.init(argc, argv);

    list<Path>::iterator tmp;
    for(tmp = params.Urls.begin(); tmp != params.Urls.end(); ++tmp){
        if(Communication().run(&(*tmp), params)){
            continue;
        }

        xmlDocPtr doc = xmlReadMemory((*tmp).result.c_str(), (*tmp).result.length(), NULL, NULL, 0);
        if(doc == NULL){
            cout <<  "parsing failed" << endl;
		xmlCleanUp(doc);
            continue;
        }

        xmlNodePtr root = xmlDocGetRootElement(doc);
        if(root == NULL){
            cout << "failed to get root" << endl;
		xmlCleanUp(doc);
            continue;
        }

        if(!xmlStrcmp(root->name, (xmlChar*)(((string)"rss").c_str())))
            (*tmp).is_rss = true;

        if((*tmp).is_rss){
            xmlNodePtr channel = findNodeByName(root, (xmlChar*)(((string)"channel").c_str()));
            if(channel != NULL){
                xmlNodePtr title = findNodeByName(channel, (xmlChar*)(((string)"title").c_str()));
                if(title != NULL)
			printData(title, "*** ", " ***\n");
                xmlNodePtr curr_child = channel->children;
                while(curr_child != NULL){
                    if(!xmlStrcmp(curr_child->name, (xmlChar*)(((string)"item").c_str()))){
                        getDesiredData(curr_child, params, ((*tmp).is_rss));
                    }
                    curr_child = curr_child->next;
                }
            }
        }else{
            xmlNodePtr title = findNodeByName(root, (xmlChar*)(((string)"title").c_str()));
            if(title != NULL)
		printData(title, "*** ", " ***\n");
            xmlNodePtr curr_child = root->children;
            while(curr_child != NULL){
                if(!xmlStrcmp(curr_child->name, (xmlChar*)(((string)"entry").c_str())))
                    getDesiredData(curr_child, params, ((*tmp).is_rss));
                curr_child = curr_child->next;
            }
	}
	xmlCleanUp(doc);
    }
    return 0;
}