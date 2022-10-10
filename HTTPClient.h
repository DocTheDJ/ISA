/*
 * @file HTTPClient.h
 * @brief libcurl wrapper for HTTP requests
 *
 * @author Mohamed Amine Mzoughi <mohamed-amine.mzoughi@laposte.net>
 * @date 2017-01-04
 */

#ifndef INCLUDE_HTTPCLIENT_H_
#define INCLUDE_HTTPCLIENT_H_

#define CLIENT_USERAGENT "httpclientcpp-agent/1.0"

#include <algorithm>
#include <atomic>
#include <cstddef>         // std::size_t
#include <cstdio>          // snprintf
#include <cstdlib>
#include <cstring>         // strerror, strlen, memcpy, strcpy
#include <ctime>
#include <curl/curl.h>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>    // std::unique_ptr
#include <mutex>
#include <stdio.h>
#include <stdlib.h>
#include <sstream>
#include <stdarg.h>  // va_start, etc.
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unordered_map>
#include <vector>

#include "CurlHandle.h"

class CHTTPClient
{
public:
   // Public definitions
   typedef std::function<int(void*, double, double, double, double)> ProgressFnCallback;
   typedef std::function<void(std::string&)> LogFnCallback;
   typedef std::unordered_map<std::string, std::string> HeadersMap;
   typedef std::vector<char> ByteBuffer;

   /* This struct represents the form information to send on POST Form requests */
   struct PostFormInfo
   {
      PostFormInfo();
      ~PostFormInfo();
      
      /* Fill in the file upload field */
      void AddFormFile(std::string& fieldName, std::string& fieldValue);
      
      /* Fill in the filename or the submit field */
      void AddFormContent(std::string& fieldName, std::string& fieldValue);

      struct curl_httppost* m_pFormPost;
      struct curl_httppost* m_pLastFormptr;
   };

   // Progress Function Data Object - parameter void* of ProgressFnCallback references it
   struct ProgressFnStruct
   {
      ProgressFnStruct() : dLastRunTime(0), pCurl(nullptr), pOwner(nullptr) {}
      double dLastRunTime;
      CURL*  pCurl;
      /* owner of the CHTTPClient object. can be used in the body of the progress
      * function to send signals to the owner (e.g. to update a GUI's progress bar)
      */
      void*  pOwner;
   };

   // HTTP response data
   struct HttpResponse
   {
      HttpResponse() : iCode(0) {}
      int iCode; // HTTP response code
      HeadersMap mapHeaders; // HTTP response headers fields
      std::string strBody; // HTTP response body
   };

   enum SettingsFlag
   {
      NO_FLAGS = 0x00,
      ENABLE_LOG = 0x01,
      VERIFY_PEER = 0x02,
      VERIFY_HOST = 0x04,
      ALL_FLAGS = 0xFF
   };

   /* Please provide your logger thread-safe routine, otherwise, you can turn off
   * error log messages printing by not using the flag ALL_FLAGS or ENABLE_LOG */
   explicit CHTTPClient(LogFnCallback oLogger);
   virtual ~CHTTPClient();

   // copy constructor and assignment operator are disabled
   CHTTPClient(CHTTPClient& Copy) = delete;
   CHTTPClient& operator=(CHTTPClient& Copy) = delete;

   // Setters - Getters (for unit tests)
   /*inline*/ void SetProgressFnCallback(void* pOwner, ProgressFnCallback& fnCallback);
   /*inline*/ void SetProxy(std::string& strProxy);
   inline void SetTimeout(int& iTimeout) { m_iCurlTimeout = iTimeout; }
   inline void SetNoSignal(bool& bNoSignal) { m_bNoSignal = bNoSignal; }
   inline void SetHTTPS(bool& bEnableHTTPS) { m_bHTTPS = bEnableHTTPS; }
   inline auto GetProgressFnCallback() const
   {
      return m_fnProgressCallback.target<int(*)(void*, double, double, double, double)>();
   }
   inline void* GetProgressFnCallbackOwner() { return m_ProgressStruct.pOwner; }
   inline std::string& GetProxy() { return m_strProxy; }
   inline int GetTimeout() { return m_iCurlTimeout; }
   inline bool GetNoSignal() { return m_bNoSignal; }
   inline std::string& GetURL()      { return m_strURL; }
   inline unsigned char GetSettingsFlags() { return m_eSettingsFlags; }
   inline bool GetHTTPS() { return m_bHTTPS; }

   // Session
   bool InitSession(const bool& bHTTPS = false,
                     const SettingsFlag& SettingsFlags = ALL_FLAGS);
   virtual bool CleanupSession();
   CURL* GetCurlPointer() { return m_pCurlSession; }

   // HTTP requests
   bool GetText(std::string& strURL,
                      std::string& strText,
                      long& lHTTPStatusCode);

   bool DownloadFile(std::string& strLocalFile,
                           std::string& strURL,
                           long& lHTTPStatusCode);

   bool DownloadFile(std::vector<unsigned char>& data, std::string& strURL, long& lHTTPStatusCode);

   bool UploadForm(std::string& strURL,
                         PostFormInfo& data,
                         long& lHTTPStatusCode);

   inline void AddHeader(std::string& strHeader)
   {
      m_pHeaderlist = curl_slist_append(m_pHeaderlist, strHeader.c_str());
   }

   // REST requests
   bool Head(std::string& strUrl, HeadersMap& Headers, HttpResponse& Response);
   bool Get(std::string& strUrl, HeadersMap& Headers, HttpResponse& Response);
   bool Del(std::string& strUrl, HeadersMap& Headers, HttpResponse& Response);
   bool Post(std::string& strUrl, HeadersMap& Headers,
             std::string& strPostData, HttpResponse& Response);
   bool Put(std::string& strUrl, HeadersMap& Headers,
            std::string& strPutData, HttpResponse& Response);
   bool Put(std::string& strUrl, HeadersMap& Headers,
            ByteBuffer& Data, HttpResponse& Response);
   
   // SSL certs
   static std::string& GetCertificateFile() { return s_strCertificationAuthorityFile; }
   static void SetCertificateFile(std::string& strPath) { s_strCertificationAuthorityFile = strPath; }

   void SetSSLCertFile(std::string& strPath) { m_strSSLCertFile = strPath; }
   std::string& GetSSLCertFile() { return m_strSSLCertFile; }

   void SetSSLKeyFile(std::string& strPath) { m_strSSLKeyFile = strPath; }
   std::string& GetSSLKeyFile() { return m_strSSLKeyFile; }

   void SetSSLKeyPassword(std::string& strPwd) { m_strSSLKeyPwd = strPwd; }
   std::string& GetSSLKeyPwd() { return m_strSSLKeyPwd; }

#ifdef DEBUG_CURL
   static void SetCurlTraceLogDirectory(std::string& strPath);
#endif

#ifdef WINDOWS
   static std::string AnsiToUtf8(std::string& ansiStr);
   static std::wstring Utf8ToUtf16(std::string& str);
#endif

protected:
   // payload to upload on POST requests.
   struct UploadObject
   {
      UploadObject() : pszData(nullptr), usLength(0) {}
      char* pszData; // data to upload
      size_t usLength; // length of the data to upload
   };

   /* common operations are performed here */
   inline CURLcode Perform();
   inline void UpdateURL(std::string& strURL);
   inline bool InitRestRequest(std::string& strUrl, HeadersMap& Headers,
                               HttpResponse& Response);
   inline bool PostRestRequest(CURLcode ePerformCode, HttpResponse& Response);

   // Curl callbacks
   static size_t WriteInStringCallback(void* ptr, size_t size, size_t nmemb, void* data);
   static size_t WriteToFileCallback(void* ptr, size_t size, size_t nmemb, void* data);
   static size_t WriteToMemoryCallback(void* ptr, size_t size, size_t nmemb, void* data);
   static size_t ReadFromFileCallback(void* ptr, size_t size, size_t nmemb, void* stream);
   static size_t ThrowAwayCallback(void* ptr, size_t size, size_t nmemb, void* data);
   static size_t RestWriteCallback(void* ptr, size_t size, size_t nmemb, void* userdata);
   static size_t RestHeaderCallback(void* ptr, size_t size, size_t nmemb, void* userdata);
   static size_t RestReadCallback(void* ptr, size_t size, size_t nmemb, void* userdata);
   
   // String Helpers
   static std::string StringFormat(std::string strFormat, ...);
   static inline void TrimSpaces(std::string& str);

   // Curl Debug informations
#ifdef DEBUG_CURL
   static int DebugCallback(CURL* curl, curl_infotype curl_info_type, char* strace, size_t nSize, void* pFile);
   inline void StartCurlDebug() const;
   inline void EndCurlDebug() const;
#endif

   std::string          m_strURL;
   std::string          m_strProxy;

   bool                 m_bNoSignal;
   bool                 m_bHTTPS;
   SettingsFlag         m_eSettingsFlags;

   struct curl_slist*    m_pHeaderlist;

   // SSL
   static std::string   s_strCertificationAuthorityFile;
   std::string          m_strSSLCertFile;
   std::string          m_strSSLKeyFile;
   std::string          m_strSSLKeyPwd;

   CURL*         m_pCurlSession;
   int           m_iCurlTimeout;

   // Progress function
   ProgressFnCallback    m_fnProgressCallback;
   ProgressFnStruct      m_ProgressStruct;
   bool                  m_bProgressCallbackSet;

   // Log printer callback
   LogFnCallback         m_oLog;

private:
#ifdef DEBUG_CURL
   static std::string s_strCurlTraceLogDirectory;
   mutable std::ofstream      m_ofFileCurlTrace;
#endif

   CurlHandle& m_curlHandle;
};

inline CHTTPClient::SettingsFlag operator|(CHTTPClient::SettingsFlag a, CHTTPClient::SettingsFlag b) {
    return static_cast<CHTTPClient::SettingsFlag>(static_cast<int>(a) | static_cast<int>(b));
}

// Logs messages
#define LOG_ERROR_EMPTY_HOST_MSG                "[HTTPClient][Error] Empty hostname."
#define LOG_WARNING_OBJECT_NOT_CLEANED          "[HTTPClient][Warning] Object was freed before calling " \
                                                "CHTTPClient::CleanupSession(). The API session was cleaned though."
#define LOG_ERROR_CURL_ALREADY_INIT_MSG         "[HTTPClient][Error] Curl session is already initialized ! " \
                                                "Use CleanupSession() to clean the present one."
#define LOG_ERROR_CURL_NOT_INIT_MSG             "[HTTPClient][Error] Curl session is not initialized ! Use InitSession() before."


#define LOG_ERROR_CURL_REQ_FAILURE_FORMAT       "[HTTPClient][Error] Unable to perform request from '%s' " \
                                                "(Error = %d | %s) (HTTP_Status = %ld)"
#define LOG_ERROR_CURL_REST_FAILURE_FORMAT      "[HTTPClient][Error] Unable to perform a REST request from '%s' " \
                                                "(Error = %d | %s)"
#define LOG_ERROR_CURL_DOWNLOAD_FAILURE_FORMAT  "[HTTPClient][Error] Unable to perform a request - '%s' from '%s' " \
                                                "(Error = %d | %s) (HTTP_Status = %ld)"
#define LOG_ERROR_DOWNLOAD_FILE_FORMAT          "[HTTPClient][Error] Unable to open local file %s"

#endif
