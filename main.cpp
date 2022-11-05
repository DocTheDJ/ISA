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

//definition of Path class which contains all the needed information about the URL
class Path{
    public:
        //is the url https
        bool is_https = false;
        //is the type of feed rss
        bool is_rss = false;
        //the original url link
        string original;
        //string of http or https
        string scheme;
        //server name
        string host;
        //port on the server
        string port;
        //specific path to file on the server
        string path;
        //the entire downloaded feed
        string result = "";

        //simple setup that puts original url to appropriate attribute and then parsing of that url
        Path init(char* url){
            original = url;
            parse(url);
            //return of this parsed url to be used in a list
            return *this;
        }

        //implementation of url parsing method since the library that contained such function in openssl was purposefully deleted
        void parse(char* url){
            smatch found;
            string tmp = (string)url;
            string rest = "";
            //using regex to identify scheme that is http or https
            if(regex_search(tmp, found, regex("(.*?)://(.*)"))){
                //sheme is found in the first designated group
                scheme = found.str(1);
                //scheme can be mangled with capitals
                for(long unsigned int i = 0; i < scheme.length(); i++){
                    scheme[i] = tolower(scheme[i]);
                }
                if(scheme == "https")
                    is_https = true;
                rest = found.str(2);
                //search for hostname which is usually divided by colon from port
                if(regex_search(rest, found, regex("(.*?):(.*)"))){
                    host = found.str(1);
                    rest = found.str(2);
                    //now split the port number from path that follows
                    if(regex_search(rest, found, regex("(.*?)(/.*)"))){
                        //if however the port is not there tha defaults get set for their respective protocols
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
                    //if there is no port that means that defaulsts are in order
                    if(is_https)
                        port = (char*)"443\0";
                    else
                        port = (char*)"80\0";
                    //the host is divided from path by a slash
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

    //method to separete the trash that might follow the feed from the feed
	void getFinish(string last){
        //first try to find the end of rss feed
		size_t found_at = last.find("</rss>");
        //if found cut the string after
		if(found_at != string::npos){
			last = last.substr(0, found_at + ((string)"</rss>").length());
			result += last;
			return;
		}
        //same for atom
		found_at = last.find("</feed>");
		if(found_at != string::npos){
			last = last.substr(0, found_at + ((string)"</feed>").length());
			result += last;
			return;
		}
        //there also some edge cases like that the end of feed tag can be split between the last two so the tag has to be found in the entire feed string
        //hopefully this does not happen often
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

//this class describes the parameters that were given to the program
class Args{
    public:
        //list of url made from Path class
        list<Path> Urls;
        //paths is for possible multiple files with urls
        list<string> paths;
        //cFiles contains all the files with certificates
        list<string> cFiles;
        //cDirs contains all the directories with certificates
	    list<string> cDirs;
        //these are from assignment
        bool f = false;
        bool T = false;
        bool a = false;
        bool u = false;

        //method that iterates through the parameters given
        void init(int argc, char** argv){
            //go through parameters starying at 1 since 0 is program itself
            for(int i = 1; i < argc; i++){
                //decide on the paramer
                int ret = isOneOfParams(argv[i]);
                if(!ret){
                    //append Path to Urls list
                    Urls.push_back(Path().init(argv[i]));
                    continue;
                }
                //specify what comes after
                if(ret == 1 || ret == 2 || ret == 6){
                    shouldNotBeParam(argv[++i], ret);
                }
            }
            if(f){
                //iterate through the files with Urls given
                list<string>::iterator files;
                for(files = paths.begin(); files != paths.end(); ++files){
                    readUrlsFromFile(*files);
                }
            }
        }

    private:
        //method to decide which parameter it is dealing with and appropriate attributes are set
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

        //check to see if the given parameter is valid
        void shouldNotBeParam(string param, int target){
            //if not finish
            if(isOneOfParams(param)){
                cout << "invalid argument sequence" << endl;
                exit(1);
            }else{
                //if is then decide what should happen with target
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
	
    //method to read Urls from file given
	void readUrlsFromFile(string path){
		std::ifstream ifs(path);
		string tmp;
		while(getline(ifs, tmp)){
            //trim whitespaces
			ltrim(tmp);
            //check to see if empty
			if(!(tmp.empty())){
                //decide comment
				if(!strncmp(tmp.c_str(), "#", strlen("#")))
					continue;
				else
                    //append url to list
					Urls.push_back(Path().init((char*)(tmp.c_str())));
			}
		}
		ifs.close();
	}
	
    //inline method downloaded from internet to help with string trimming, in object oriented languages standard for string
	static inline void ltrim(std::string &s) {s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {return !std::isspace(ch);}));
}
};

//class to connect and downaload feed from given feed
class Communication{
    private:
        BIO *bio;
        SSL_CTX *ctx;
        SSL *ssl;
        char* response;
    public:
        int run(Path* Url, Args params){
            //initialise
            SSL_load_error_strings();
            SSL_library_init();
            //get host_port to be used
            string host_port = Url->host + ":" + Url->port;
            //decide on the path
            if(!Url->is_https){
                //create bio, abstruction from openssl
                bio = BIO_new_connect(host_port.c_str());
                if(bio == NULL){
                    cleanup(3);
                    cout << "failed establishing connection" << endl;
                    return 1;
                }
                //try to connect
                while (BIO_do_connect(bio) <= 0) {
                    //if possible try to reconnect
                    if (!BIO_should_retry(bio)) {
                        cout << "failed to reconnect" << endl;
                        cleanup(2);
                        return 1;
                    } else {
                        continue;
                    }
                }
            }else{
                //initialise ctx with SSL client method for current version
                ctx = SSL_CTX_new(SSLv23_client_method());
                //load possible certificates
                getCertificates(params);
                //create abstraction from openssl
                bio = BIO_new_ssl_connect(ctx);
                //get ssl from bio
                BIO_get_ssl(bio, &ssl);
                //set tls hostname, very important
		        SSL_set_tlsext_host_name(ssl, Url->host.c_str());
                //set mode
                SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
                //set connection target
                BIO_set_conn_hostname(bio, host_port.c_str());
                //try to connect
                while(BIO_do_connect(bio) <= 0){
                    //possible reconnect
                    if (!BIO_should_retry(bio)) {
                        cout << "failed to reconnect" << endl;
                        cleanup(1);
                        return 1;
                    } else {
                        continue;
                    }
                }
                //verify that provided certificates are valid
                if(SSL_get_verify_result(ssl) != X509_V_OK){
                    cout << "Certificates failed to confirm the validity" << endl;
                    cleanup(1);
                    return 1;
                }
            }

            //build http resquest
            string request = "GET " + ((string)Url->path) + " HTTP/1.0\r\nHost: " + ((string)Url->host) + "\r\nUser-Agent: Feedreader-xvitul03\r\nAccept: application/xml\r\nAccept-Charset: UTF-8,*\r\nCache-Control: private, no-store, max-age=0\r\nConnection: close\r\n\r\n";
            //send the request until success
            while(BIO_write(bio, request.c_str(), (request.length() + 1) * sizeof(char)) <= 0){
                //or until the reconnect fails
                if (!BIO_should_retry(bio)) {
                    cout << "failed to send request" << endl;
                    cleanup(1);
                    return 1;
                } else {
                    continue;
                }
            }

            //the feed is read in blocks of 16384 bytes, can be something else, i feel this is nice common ground
            int size = 16384;
            //allocate memory for result from reading
            response = (char*)malloc(sizeof(char) * (size + 1));
            int round = 0;
            string ret_code;
            //the string that serves as a one round buffer to then check for end 
            string tmp = "";
            while(true){
                //read from http response
                int len = BIO_read(bio, (void*)response, size);
                //add termination to end
		        response[len] = 0;
                if (len < 0) {
                    //if shorter than 0 then chech to retry
                    if (!BIO_should_retry(bio)) {
                        cout << "failed retry in read" << endl;
                        cleanup(0);
                        return 1;
                    } else {
                        continue;
                    }
                } else if (len == 0) {
                    // if equal to 0 then that means there is no more data to download
			        Url->getFinish(tmp);
	                break;
                } else {
                    //else the previous response block is appended to result
		        	Url->result += tmp;
                    if(round++ == 0){
                        //if round 1 of blocks that means that in the response there is the http header
			            smatch m;
                        tmp = (string)response;
                        //which must me read
                        regex_search(tmp, m, regex("[Hh][Tt]{2}[Pp][Ss]?/1.\\d (\\d{3})"));
                        //get response code
                        ret_code = m.str(1);
                        //get the start of feed
                        regex_search(tmp, m, regex("\r\n\r\n"));
                        tmp = (string)&response[m.position() + 4];
                    }else{
                        //else the resnse is put in the buffer
                        tmp = (string)response;
                    }
                }
            }
            //check to see if the http response was OK
            if(atoi(ret_code.c_str()) != 200){
                cout << "http response is not OK" << endl;
                cleanup(0);
                return 1;
            }
            cleanup(0);
            return 0;
        }
    private:
        //method to load all the cerficates that the feed might need
        void getCertificates(Args params){
            //if there are not any then load defaults
            if(params.cFiles.empty()){
                if(!SSL_CTX_set_default_verify_paths(ctx)){
                    cout << "certificates failed" << endl;
                    exit(1);
                }
            }else {
                list<string>::iterator files;
                //iteration through all the certificates given in files
                for(files = params.cFiles.begin(); files != params.cFiles.end(); ++files){
                    if(!SSL_CTX_load_verify_locations(ctx, (*files).c_str(), NULL)){
                        cout << "certificates failed" << endl;
                        exit(1);
                    }
                }
                //iteration through all the certificates given in directories
		        for(files = params.cDirs.begin(); files != params.cDirs.end(); ++files){
                    if(!SSL_CTX_load_verify_locations(ctx, NULL, (*files).c_str())){
                        cout << "certificates failed" << endl;
                        exit(1);
                    }
                }
            }
        }

        //cleanup based on the phase the error was given
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

//function ot get node by name, using DFS
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

//function just to specifically free result from xmlNodeGetContent and then print it with given prefix and postfix
void printData(xmlNodePtr node, string preFix, string postFix){
        xmlChar* tmp = xmlNodeGetContent(node);
        cout << preFix << (char*)tmp << postFix;
        xmlFree(tmp);
}

void getDesiredData(xmlNodePtr node, Args params, bool rss){
    //get title of article
	xmlNodePtr title = findNodeByName(node, (xmlChar*)(((string)"title").c_str()));
	if(title != NULL)
		printData(title, "", "\n");
    //decide on rss
	if(rss){
        //if parameter was given then print also URL
		if(params.u){
			title = findNodeByName(node, (xmlChar*)(((string)"link").c_str()));
			if(title != NULL)
				printData(title, "URL: ", "\n");
		}
        //if parameter was given then print also update time
		if(params.T){
			title = findNodeByName(node, (xmlChar*)(((string)"pubDate").c_str()));
			if(title != NULL)
				printData(title, "Aktualizace: ", "\n");
		}
        //if parameter was given then print also Author
		if(params.a){
			title = findNodeByName(node, (xmlChar*)(((string)"author").c_str()));
			if(title != NULL)
				printData(title, "Autor: ", "\n");
		}
        //if any of the parameters were given then put an extra newline after print of article
		if(params.u || params.T || params.a)
			cout << endl;
		return;
	}else{
        //all is the same in atom execpt tags
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
            //and author has nested tags
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

//cleanup after xml is done for feed
void xmlCleanUp(xmlDocPtr doc){
	xmlFreeDoc(doc);
        xmlCleanupParser();
        xmlMemoryDump();
        cout << endl;
}

int main(int argc, char** argv)
{
    //get params
    Args params;
    params.init(argc, argv);

    //iterate through all the urls gotten from the arguments
    list<Path>::iterator tmp;
    for(tmp = params.Urls.begin(); tmp != params.Urls.end(); ++tmp){
        //run download
        if(Communication().run(&(*tmp), params)){
            continue;
        }

        //let xml parse from memory
        xmlDocPtr doc = xmlReadMemory((*tmp).result.c_str(), (*tmp).result.length(), NULL, NULL, 0);
        if(doc == NULL){
            cout <<  "parsing failed" << endl;
		xmlCleanUp(doc);
            continue;
        }

        //get root from document
        xmlNodePtr root = xmlDocGetRootElement(doc);
        if(root == NULL){
            cout << "failed to get root" << endl;
		xmlCleanUp(doc);
            continue;
        }

        //check to set which type of feed this is
        if(!xmlStrcmp(root->name, (xmlChar*)(((string)"rss").c_str())))
            (*tmp).is_rss = true;

        //feeds differ in tags
        if((*tmp).is_rss){
            //after root there is channel to be found
            xmlNodePtr channel = findNodeByName(root, (xmlChar*)(((string)"channel").c_str()));
            if(channel != NULL){
                //in channel get title of feed
                xmlNodePtr title = findNodeByName(channel, (xmlChar*)(((string)"title").c_str()));
                if(title != NULL)
			        printData(title, "*** ", " ***\n");
                xmlNodePtr curr_child = channel->children;
                //iterate through all his children
                while(curr_child != NULL){
                    //but get just item
                    if(!xmlStrcmp(curr_child->name, (xmlChar*)(((string)"item").c_str()))){
                        getDesiredData(curr_child, params, ((*tmp).is_rss));
                    }
                    curr_child = curr_child->next;
                }
            }
        }else{
            //atom has title directly after root
            xmlNodePtr title = findNodeByName(root, (xmlChar*)(((string)"title").c_str()));
            if(title != NULL)
		        printData(title, "*** ", " ***\n");
            xmlNodePtr curr_child = root->children;
            //child iteration
            while(curr_child != NULL){
                //get only entries
                if(!xmlStrcmp(curr_child->name, (xmlChar*)(((string)"entry").c_str())))
                    getDesiredData(curr_child, params, ((*tmp).is_rss));
                curr_child = curr_child->next;
            }
	    }
	    xmlCleanUp(doc);
    }
    return 0;
}