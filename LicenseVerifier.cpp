#include "LicenseVerifier.h"
#include "log.h"
#include <cstring>
#include <string.h>
#include <cctype>
#include <cstdio>
#include <cstdarg>
#include <ctime>
#include <iostream>
#include<fstream>
#include <algorithm>
#include <windows.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include "curl/curl.h"
#include "openssl/aes.h"
#include "openssl/evp.h"
#include "openssl/bio.h"
#include "openssl/buffer.h"
#include "rapidjson/rapidjson.h"
#include "rapidjson/document.h"
//#include "python.h"
const size_t kHeaderBufferSize = 512;
const char kHeaderEnding[] = "\r\n";
const int ProductID = 10012;
const char ProductKey[] = "iuvZ1NLcbzqL8pQmKvTT5VsATqFzz63H";

using namespace std;

LicenseVerifier* g_licenseVerifier = nullptr;
//#ifdef  __cplusplus
extern "C"
{
//#endif
    __declspec(dllexport) bool LicenseVerifier_Init(const char* license)
    {
       // MessageBoxA(NULL, "", "test", MB_OK);
        CreateLogFile();
        if (g_licenseVerifier == nullptr)
        {
            g_licenseVerifier = new LicenseVerifier();
        }
        return (g_licenseVerifier != nullptr);
    }

    __declspec(dllexport) bool LicenseVerifier_VerifyLicense(const char* license, char* message, int char_count)
    {
       if (g_licenseVerifier != nullptr)
       {
           return g_licenseVerifier->VerifyLicense(ProductID, ProductKey, license, message, char_count);
       }
       return 0;
    }

    __declspec(dllexport) bool LicenseVerifier_GetToken(unsigned char* buffer, int char_count, unsigned int* token_orig_len, unsigned int* token_len)
    {
        if (g_licenseVerifier != nullptr)
        {
            return g_licenseVerifier->GetToken(ProductKey, buffer, char_count, token_orig_len, token_len);
        }

        return false;
    }

    __declspec(dllexport) bool LicenseVerifier_GetMaccAddress(char buffer[][64], int buffer_count, int* address_count)
    {
        if (g_licenseVerifier != nullptr)
        {
            return g_licenseVerifier->GetMacAddress(buffer, buffer_count, address_count);
        }

        return false;
    }

    __declspec(dllexport) bool LicenseVerifier_GetCPUID(char* buffer, int char_count)
    {
        if (g_licenseVerifier != nullptr)
        {
            return g_licenseVerifier->GetCPUID(buffer, char_count);
        }

        return false;
    }

    __declspec(dllexport) void LicenseVerifier_Log(const char* log)
    {
        if (g_licenseVerifier != nullptr)
        {
            return g_licenseVerifier->Log(log);
        }
    }

    __declspec(dllexport) bool LicenseVerifier_Uninit(const char* license)
    {
        CloseLogFile();
        if (g_licenseVerifier != nullptr)
        {
            delete g_licenseVerifier;
            g_licenseVerifier = nullptr;
        }
        return true;
    }
	__declspec(dllexport)void LicenseVerifier_GetUser()
	{

		if (g_licenseVerifier != nullptr)
		{

            g_licenseVerifier->GetUser();
		}
	}
//#ifdef  __cplusplus
}
//#endif

LicenseVerifier::LicenseVerifier()
{
	curl_global_init(CURL_GLOBAL_DEFAULT);
    memset(token_, 0, sizeof(token_));
    token_origin_len_ = 0;
    token_len_ = 0;
    gen_token_time_ = 0;
}

LicenseVerifier::~LicenseVerifier()
{
	curl_global_cleanup();
}

void LicenseVerifier::GetUser()
{
   
    //return license_info_.product_info.c_str();
    const char* user = "invalid_user";
	if(license_info_.valid)
        user= license_info_.product_info.data();

    ofstream ofs;
    ofs.open("user.txt", ios::out);
    ofs << license_info_.product_info.data() << endl;
    ofs.close();
}

bool LicenseVerifier::VerifyToken(int product_id, const char* product_key, const char* token)
{
	if (product_key == nullptr)
	{
        Log("[Verify]product_key is null");
		return false;
	}

	if (token == nullptr)
	{
        Log("[Verify]token is null");
		return false;
	}

	char* buffer = new char[MAX_LEN_LECENSE_BODY];
	if (buffer == nullptr)
	{
		Log("[Verify]fail to alloc buffer");
		return false;
	}

	memset(buffer, 0, MAX_LEN_LECENSE_BODY);

	bool success = false;
	do {
		if (!Decrypt(token, buffer, MAX_LEN_LECENSE_BODY, product_key))
		{
			Log("[Verify]Decrpyt token fail {}", token);
			break;
		}

        rapidjson::Document dom;
        dom.Parse(buffer);
        if (dom.HasParseError()) {
            rapidjson::ParseErrorCode errorCode = dom.GetParseError();
            size_t offset = dom.GetErrorOffset();
            Log("[DecryptLicense]Parse data fail, errorCode:%d, offset:%d\n", errorCode, offset);
            break;;
        }

        // check product id
        if (!dom.HasMember("productID"))
        {
            Log("[DecryptLicense]FAIL to get productID");
            break;
        }

        unsigned int product_id_in_token = dom["productID"].GetInt();
        if (product_id_in_token != product_id)
        {
            Log("[Verify]fail to verify token in step 1, {}, {}", product_id_in_token, product_id);
            break;
        }

        if (!dom.HasMember("MACAddress"))
        {
            Log("[DecryptLicense]fail to get deviceinfo 1");
            break;
        }

        string mac_address = dom["MACAddress"].GetString();
        std::transform(mac_address.begin(), mac_address.end(), mac_address.begin(), [](unsigned char c) { return std::tolower(c); });

        if (!dom.HasMember("deviceID"))
        {
            Log("[DecryptLicense]fail to get deviceinfo 2");
            break;
        }

        string device_id = dom["deviceID"].GetString();
        std::transform(device_id.begin(), device_id.end(), device_id.begin(), [](unsigned char c) { return std::tolower(c); });

        char message[1024] = { 0 };
        if (!VerifyDeviceInfo(mac_address.c_str(), device_id.c_str(), message, _countof(message)))
        {
            Log("[Verify]fail to  verify token in step 2");
            break;
        }

        // check agent process id
        if (!dom.HasMember("parentProcessID"))
        {
            Log("[DecryptLicense]fail to get deviceinfo 2");
            break;
        }

        unsigned int pid_in_token = dom["processID"].GetUint();;

        if (pid_in_token != GetCurrentProcessId())
        {
            Log("[Verify]fail to verify token in step 3, %u, %u", pid_in_token, GetCurrentProcessId());
            break;
        }

        if (!dom.HasMember("createProcessTime"))
        {
            Log("[DecryptLicense]fail to get createProcessTime");
            break;
        }

        // check agent created time
        int64_t create_process_time_in_token = dom["createProcessTime"].GetInt64();
        int64_t create_process_time = 0;
        if (!GetProcessCreateTime(create_process_time))
        {
            Log("[Verify]fail to GetProcessCreateTime, error:%d", GetLastError());
            break;
        }

        if (std::abs(create_process_time_in_token - create_process_time) > 2 * 60 * 60)
        {
            Log("[Verify]fail to verify token in step 4, %lld, %lld", create_process_time_in_token, create_process_time);
            break;
        }

        // check token time
        time_t  timer;
        std::time(&timer);
        

        if (!dom.HasMember("time"))
        {
            Log("[Verify]fail to get timestamp");
            break;
        }

        int64_t timestamp = dom["time"].GetInt64();
        if (std::abs(timestamp - (int64_t)timer) > 12 * 60 * 60)
        {
            Log("[Verify]fail to verify token in step 5, %lld, %lld", timestamp, (int64_t)timer);
            break;
        }

		success = true;
	} while (0);

	if (buffer != nullptr)
	{
		delete[] buffer;
		buffer = nullptr;
	}
	return success;
}

bool LicenseVerifier::VerifyLicense(int product_id, const char* product_key, const char* license, char* message, int char_count)
{
    bool success = true;
    //const char* result = "success";
    LicenseInfo license_info;
    license_info.valid = false;
    do {

        if (!VerifyLicenseImpl(product_id, license, product_key, message, char_count))
        {
            success = false;
            //result = "[VerifyLicense]Verify at step 1\n";
            break;
        }

        Log("[VerifyLicense]Verify at step 1\n");

        if (!DecryptLicense(product_id, license, product_key, license_info, message, char_count))
        {
            //result = "[VerifyLicense]Verify at step 2\n";
            success = false;
            break;
        }

        Log("[VerifyLicense]Verify at step 2\n");
        if (!VerifyDeviceInfo(license_info.unique_info.mac_address.c_str(), license_info.unique_info.device_id.c_str(), message, char_count))
        {
           // result = message;
            success = false;
            break;
        }

        Log("[VerifyLicense]Verify at step 3\n");
        
        license_info.valid = success;

       // if (success && license_info.expiration_date == 0)
        //{
        //    std::time_t timer;
       //     time(&timer);
        //    license_info.expiration_date = (int64_t)timer;
       // }
        
        std::lock_guard<std::mutex> guard(mutex_);
        license_info_ = license_info;
    } while (0);

    if (!success && message != nullptr && strlen(message) == 0)
    {
        strcpy_s(message, char_count, "Fail to verify license");

        char temp[1024] = { 0 };
        strcpy_s(temp, 1024, "Fail to verify license");
    }

	return success;
}

bool LicenseVerifier::GetToken(const char* product_key, unsigned char* buffer, int char_count, unsigned int* token_origin_len, unsigned int* token_len)
{
    if (product_key == nullptr || buffer == nullptr || char_count <= 0 || !license_info_.valid)
    {
        return false;
    }

    std::time_t timer;
    time(&timer);

    if (std::abs((int64_t)timer - gen_token_time_) > 25 * 60)
    {
        LicenseInfo license_info;
        {
            std::lock_guard<std::mutex> guard(mutex_);
            license_info = license_info_;
        }

        char token[1024] = { 0 };
        unsigned int origin_len = 0;
        unsigned int token_len = 0;
        memset(token_, 0, sizeof(token_));
        token_origin_len_ = 0;
        token_len_ = 0;
        if (!GenerateToken(product_key, license_info, token_, _countof(token_), token_origin_len_, token_len_))
        {
            return false;
        }

        gen_token_time_ = timer;
    }

    memcpy(buffer, token_, token_len_);

    if (token_origin_len != nullptr)
    {
        *token_origin_len = token_origin_len_;
    }

    if (token_len != nullptr)
    {
        *token_len = token_len_;
    }

    return true;
}

bool LicenseVerifier::GenerateToken(const char* product_key, LicenseInfo license_info, unsigned char* buffer, int char_count, unsigned int& token_origin_len, unsigned int& token_len)
{
    if (product_key == nullptr || buffer == nullptr || char_count == 0)
    {
        return false;
    }

    if (!license_info.valid)
    {
        Log("[Verify]fail to crate token, license invalid");
        return false;
    }

    bool success = false;
    unsigned int pid = GetCurrentProcessId();
    int64_t create_process_time = 0;
    std::time_t timer;
    time(&timer);

    if (!GetProcessCreateTime(create_process_time))
    {
        Log("[Verify]fail to get process create time");
        return false;
    }

    char* token = nullptr;
    token = new char[MAX_LEN_LECENSE_BODY];
    if (token == nullptr)
    {
        return false;
    }

    memset(token, 0, MAX_LEN_LECENSE_BODY);
    memset(buffer, 0, char_count);
    snprintf(
        token,
        MAX_LEN_LECENSE_BODY,
        "{\"productID\":\"%s\", \"productInfo\":\"%s\", \"valid\":%d, \"MACAddress\":\"%s\",  \"deviceID\":\"%s\",\"checkTime\":%lld,\"time\":%lld,\"startDate\":%lld, \"expirationDate\":%lld, \"gracePeriod\":%lld, \"creationDate\":%lld,\"processID\":%u, \"createProcessTime\":%lld }",
        license_info.product_id.c_str(),
        license_info.product_info.c_str(),
        license_info.valid ? 1 : 0,
        license_info.unique_info.mac_address.c_str(),
        license_info.unique_info.device_id.c_str(),
        license_info.timestamp,
        (long long)timer,
        license_info.start_date,
        license_info.expiration_date,
        license_info.grace_period,
        license_info.creation_date,
        pid,
        create_process_time
    );

    token_origin_len = strlen(token);

    if (LicenseVerifier::Encrypt(token, MAX_LEN_LECENSE_BODY, buffer, char_count, token_len, product_key, false))
    {
        success = true;
    }
    else
    {
        Log("[Verify]failed to encrypt token");
    }

    delete[] token;
    return success;
}

bool LicenseVerifier::VerifyLicenseImpl(int product_id, const char* license, const char* product_key, char* message, int char_count)
{
	if (product_id == 0 || license == nullptr || product_key == nullptr || message == nullptr || char_count <= 0)
	{
		return false;
	}

	bool success = false;
	char* buffer = nullptr;
	char* encrpyted_buffer = nullptr;

	do {
		buffer = new char[MAX_LEN_LECENSE_BODY];
		encrpyted_buffer = new char[MAX_LEN_LECENSE_BODY];
		if (buffer == nullptr || encrpyted_buffer == nullptr)
		{
			break;
		}

		memset(buffer, 0, MAX_LEN_LECENSE_BODY);
		memset(encrpyted_buffer, 0, MAX_LEN_LECENSE_BODY);
		std::time_t timer;
        unsigned int output_len = 0;
		time(&timer);

		snprintf(buffer, MAX_LEN_LECENSE_BODY, "{\"timestamp\":%lld,\"license\":\"%s\"}", (long long)timer, license);
		if (!Encrypt(buffer, MAX_LEN_LECENSE_BODY, (unsigned char*)encrpyted_buffer, MAX_LEN_LECENSE_BODY, output_len, product_key, true))
		{
			break;
		}

		memset(buffer, 0, MAX_LEN_LECENSE_BODY);
		snprintf(buffer, MAX_LEN_LECENSE_BODY, "{\"productID\":\"%d\",\"request\":\"%s\"}", product_id, encrpyted_buffer);

		int response_code = 0;
		//char error_msg[1024] = { 0 };
		std::vector<std::string> headers;
		headers.push_back("Content-Type:application/json");
		memset(encrpyted_buffer, 0, MAX_LEN_LECENSE_BODY);

		if (!RequestHttp(
			"https://tlicense.qdnative.com/license/v1/verify",
			headers,
			(unsigned char*)buffer,
			(int)strlen(buffer),
			encrpyted_buffer,
			2 * 60,
			&response_code,
            message,
            char_count))
		{
            Log("[VerifyLicense]RequestHttp fail, errorCode:%d, error:%s\n", response_code, message);
			break;
		}

        rapidjson::Document dom;
        dom.Parse(encrpyted_buffer);
        if (dom.HasParseError()) {
            rapidjson::ParseErrorCode errorCode = dom.GetParseError();
            size_t offset = dom.GetErrorOffset();
            strcpy_s(message, char_count, "Https response error");
            Log("[VerifyLicense]Parse response fail, errorCode:%d, offset:%d\n", errorCode, offset);
            break;
        }

        if (!dom.HasMember("code") || !dom.HasMember("data"))
        {
            Log("[VerifyLicense]Parse response fail, no code and data, \n");
            break;
        }

        int code = dom["code"].GetInt();
        if (code != 0)
        {
            snprintf(message, char_count, "License invalid, error:%d", code);
            Log("[VerifyLicense]Server verify error, errorCode:%d, \n", code);
            if (dom.HasMember("message"))
            {
                const char* str = dom["message"].GetString();

                if (str != nullptr)
                {
                    Log("[VerifyLicense]Server verify fail, error:%s, \n", str);
                }
            }
            break;
        }

        memset(buffer, 0, MAX_LEN_LECENSE_BODY);
        if (!Decrypt(dom["data"].GetString(), buffer, MAX_LEN_LECENSE_BODY, product_key))
        {
            strcpy_s(message, char_count, "Https response error");
            break;
        }

        dom.Parse(buffer);
        if (dom.HasParseError()) {
            rapidjson::ParseErrorCode errorCode = dom.GetParseError();
            size_t offset = dom.GetErrorOffset();
            strcpy_s(message, char_count, "Https response error");
            Log("[VerifyLicense]Parse data fail, errorCode:%d, offset:%d\n", errorCode, offset);
            break;
        }

        if (!dom.HasMember("timestamp") || !dom.HasMember("valid"))
        {
            break;
        }

        int64_t timestamp = dom["timestamp"].GetInt64();
        time(&timer);

        if (std::abs((int64_t)timer - timestamp) > 5 * 60)
        {
            break;
        }

        if (!dom.HasMember("valid"))
        {
            break;
        }

        success = dom["valid"].GetBool();
	} while (0);

	if (buffer != nullptr)
	{
		delete[] buffer;
	}

	if (encrpyted_buffer != nullptr)
	{
		delete[] encrpyted_buffer;
	}

	return success;
}

bool LicenseVerifier::DecryptLicense(int product_id, const char* license, const char* product_key, LicenseInfo& license_info, char* message, int char_count)
{
	if (product_id == 0 || license == nullptr || product_key == nullptr || message == nullptr || char_count <= 0)
	{
		return false;
	}

	bool success = false;
	char* buffer = nullptr;
	char* encrpyted_buffer = nullptr;

	do {
		buffer = new char[MAX_LEN_LECENSE_BODY];
		encrpyted_buffer = new char[MAX_LEN_LECENSE_BODY];
		if (buffer == nullptr || encrpyted_buffer == nullptr)
		{
			break;
		}

		memset(buffer, 0, MAX_LEN_LECENSE_BODY);
		memset(encrpyted_buffer, 0, MAX_LEN_LECENSE_BODY);

		time_t  timer;
        unsigned int output_len = 0;
		time(&timer);
		snprintf(buffer, MAX_LEN_LECENSE_BODY, "{\"timestamp\":%lld,\"license\":\"%s\"}", (long long)timer, license);

		if (!Encrypt(buffer, MAX_LEN_LECENSE_BODY, (unsigned char*)encrpyted_buffer, MAX_LEN_LECENSE_BODY, output_len, product_key, true))
		{
			break;
		}

		memset(buffer, 0, MAX_LEN_LECENSE_BODY);
		snprintf(buffer, MAX_LEN_LECENSE_BODY, "{\"productID\":\"%d\",\"request\":\"%s\"}", product_id, encrpyted_buffer);

		int response_code = 0;
		char error_msg[1024] = { 0 };
		std::vector<std::string> headers;
		headers.push_back("Content-Type:application/json;");
		memset(encrpyted_buffer, 0, MAX_LEN_LECENSE_BODY);

		if (!RequestHttp(
			"https://tlicense.qdnative.com/license/v1/decrypt",
			headers,
			(unsigned char*)buffer,
			(int)strlen(buffer),
			encrpyted_buffer,
			2 * 60,
			&response_code,
            message,
            char_count))
		{
            Log("[VerifyLicense]RequestHttp fail, errorCode:%d, error:%s\n", response_code, message);
			break;
		}

        rapidjson::Document dom;
        dom.Parse(encrpyted_buffer);
        if (dom.HasParseError()) {
            rapidjson::ParseErrorCode errorCode = dom.GetParseError();
            size_t offset = dom.GetErrorOffset();
            strcpy_s(message, char_count, "Https response error");
            Log("[DecryptLicense]Parse response fail, errorCode:%d, offset:%d\n", errorCode, offset);
            break;
        }

        if (!dom.HasMember("code") || !dom.HasMember("data"))
        {
            Log("[VerifyLicense]Parse response fail, no code and data, \n");
            break;
        }

        int code = dom["code"].GetInt();
        if (code != 0)
        {
            snprintf(message, char_count, "License invalid, error:%d", code);
            Log("[VerifyLicense]Server response error, errorCode:%d, \n", code);
            if (dom.HasMember("message"))
            {
                const char* str = dom["message"].GetString();

                if (str != nullptr)
                {
                    Log("[VerifyLicense]Server response error, error:%s, \n", str);
                }
            }
            break;
        }

        memset(buffer, 0, MAX_LEN_LECENSE_BODY);
        if (!Decrypt(dom["data"].GetString(), buffer, MAX_LEN_LECENSE_BODY, product_key))
        {
            strcpy_s(message, char_count, "Https response error");
            break;
        }

        success = GetLicenseInfo(buffer, license_info);
	} while (0);

	if (buffer != nullptr)
	{
		delete[] buffer;
	}

	if (encrpyted_buffer != nullptr)
	{
		delete[] encrpyted_buffer;
	}

	return success;
}

bool LicenseVerifier::GetTime(int product_id, const char* license, const char* product_key, int64_t& time)
{
	if (product_id == 0 || license == nullptr || product_key == nullptr)
	{
		return false;
	}

	bool success = false;
	char* buffer = nullptr;
	char* encrpyted_buffer = nullptr;

	do {
		buffer = new char[MAX_LEN_LECENSE_BODY];
		encrpyted_buffer = new char[MAX_LEN_LECENSE_BODY];
		if (buffer == nullptr || encrpyted_buffer == nullptr)
		{
			break;
		}

		memset(buffer, 0, MAX_LEN_LECENSE_BODY);
		memset(encrpyted_buffer, 0, MAX_LEN_LECENSE_BODY);
		snprintf(buffer, MAX_LEN_LECENSE_BODY, "{\"productID\":\"%d\"}", product_id);

		int response_code = 0;
		char error_msg[1024] = { 0 };
		std::vector<std::string> headers;
		headers.push_back("Content-Type:application/json");
		if (!RequestHttp(
			"https://tlicense.qdnative.com/license/v1/time",
			headers,
			(unsigned char*)buffer,
			(int)strlen(buffer),
			encrpyted_buffer,
			2 * 60,
			&response_code,
			error_msg,
			sizeof(error_msg)))
		{
			break;
		}

        rapidjson::Document dom;
        dom.Parse(encrpyted_buffer);
        if (dom.HasParseError()) {
            rapidjson::ParseErrorCode errorCode = dom.GetParseError();
            size_t offset = dom.GetErrorOffset();
            Log("[GetTime]Parse response fail, errorCode:%d, offset:%d\n", errorCode, offset);
            break;
        }

        if (!dom.HasMember("data"))
        {
            return false;
        }

        memset(buffer, 0, MAX_LEN_LECENSE_BODY);
        if (!Decrypt(dom["data"].GetString(), buffer, MAX_LEN_LECENSE_BODY, product_key))
        {
            Log("[VerifyLicense]Decrypt data fail");
            break;
        }

        dom.Parse(buffer);
        if (dom.HasParseError()) {
            rapidjson::ParseErrorCode errorCode = dom.GetParseError();
            size_t offset = dom.GetErrorOffset();
            Log("[VerifyLicense]Parse data fail, errorCode:%d, offset:%d\n", errorCode, offset);
            break;
        }

        if (!dom.HasMember("timestamp"))
        {
            break;
        }

        time = dom["timestamp"].GetInt64();
        success = true;
	} while (0);

	if (buffer != nullptr)
	{
		delete[] buffer;
	}

	if (encrpyted_buffer != nullptr)
	{
		delete[] encrpyted_buffer;
	}

	return success;
}

size_t LicenseVerifier::WriteCallback(char* data, size_t size, size_t nmemb, char* writer_data) {
	if (writer_data == NULL)
		return 0;
	int len = static_cast<int>(size * nmemb);
	memcpy(writer_data, data, len);
	return len;
}

size_t LicenseVerifier::ReadCallback(char* buffer, size_t size, size_t nitems, void* instream) {
	if (instream && buffer) {
		ReadStream* rs = reinterpret_cast<ReadStream*>(instream);
		if (rs) {
			size_t total_bytes = rs->buffer_len;
			if (total_bytes > rs->read_bytes) {
				size_t remain_size = total_bytes - rs->read_bytes;
				size_t copy_size = min(size * nitems, remain_size);
				memcpy(buffer, rs->buffer + rs->read_bytes, copy_size);
				rs->read_bytes += copy_size;
				return copy_size;
			}
		}
	}
	return 0;
}

bool LicenseVerifier::RequestHttp(const std::string& url,
	std::vector<std::string> headers,
	const unsigned char* request_body,
	int request_body_len,
	char* response,
	unsigned int timeout_second,
	int* response_code,
	char* error_msg,
	int error_msg_len) {
	bool result = false;
	size_t rsp_code = 0;
	CURL* curl = curl_easy_init();
	if (curl) {
		ReadStream rs;
		rs.buffer = request_body;
		rs.buffer_len = request_body_len;
		rs.read_bytes = 0;
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		if (headers.size() > 0) {
			curl_slist* plist = NULL;
			for (std::vector<std::string>::iterator iter = headers.begin();
				iter != headers.end();
				++iter) {
				plist = curl_slist_append(plist, iter->c_str());
			}
			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, plist);
		}
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
		curl_easy_setopt(curl, CURLOPT_POST, 1L);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, request_body_len);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_body);
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, LicenseVerifier::WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, ReadCallback);
		curl_easy_setopt(curl, CURLOPT_READDATA, &rs);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, timeout_second);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_second);

		CURLcode res = curl_easy_perform(curl);
		result = (res == CURLE_OK);
		if (response_code) {
			if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &rsp_code) == CURLE_OK) {
				*response_code = static_cast<int>(rsp_code);
			}
		}
		if (!result) {
			const char* error_text = curl_easy_strerror(res);
			if (error_text)
			{
				strcpy_s(error_msg, error_msg_len, error_text);
			}
		}
		curl_easy_cleanup(curl);
	}
	return result;
}

size_t LicenseVerifier::RspHeaderCallback(void* ptr, size_t size, size_t nmemb, void* stream) {
	size_t s = size * nmemb;
	if (s > sizeof(kHeaderEnding) - 1) {
		s -= sizeof(kHeaderEnding) - 1;
		char buffer[kHeaderBufferSize] = { 0 };
		memcpy(buffer, ptr, min(s, sizeof(buffer) - 1));
		if (stream) {
			std::vector<std::string>* headers = reinterpret_cast<std::vector<std::string>*>(stream);
			if (headers) {
				headers->push_back(buffer);
			}
		}
	}
	return size * nmemb;
}

// PKCS5Padding
bool LicenseVerifier::PKCS5Padding(char* input, int input_buffer_len, int block_size)
{
	if (input == nullptr)
	{
		return false;
	}

	int input_text_len = (int)strlen(input);
	int padding_len = block_size - (input_text_len % block_size);

	if (input_text_len + padding_len > input_buffer_len)
	{
		return false;
	}

	for (int i = 0; i < padding_len; ++i)
	{
		input[input_text_len + i] = (char)padding_len;
	}

	return true;
}

// PKCS5UnPadding
bool LicenseVerifier::PKCS5UnPadding(char* input, int input_char_count, int block_size)
{
	if (input == nullptr || input_char_count < 0)
	{
		return false;
	}

	int unpadding_len = input[input_char_count - 1];
	if (unpadding_len < 0 || input_char_count < unpadding_len)
	{
		return false;
	}

	input[input_char_count - unpadding_len] = 0;

	return true;
}

bool LicenseVerifier::Encrypt(char* input, int input_buffer_len, unsigned char* output, int buffer_len, unsigned int& output_len, const char* key, bool enable_base64_encode)
{
	if (input == nullptr || output == nullptr /*|| key == nullptr*/)
	{
		return false;
	}

	AES_KEY aes_key;
	unsigned char ivec[AES_BLOCK_SIZE + 1] = { 0 };
	memset(ivec, 0, sizeof(ivec));
	memcpy(ivec, key, AES_BLOCK_SIZE);
	if (AES_set_encrypt_key((unsigned char*)key, 256, &aes_key) < 0)
	{
		return false;
	}

	if (!PKCS5Padding(input, input_buffer_len, AES_BLOCK_SIZE))
	{
		return false;
	}

	int input_len = (int)strlen(input);
	AES_cbc_encrypt((const unsigned char*)input, output, input_len, &aes_key, ivec, AES_ENCRYPT);
    output_len = input_len;

    if (enable_base64_encode)
    {
        int output_char_count = 0;
        char* base64_result = Base64Encode((const unsigned char*)output, input_len, false, output_char_count);
        if (base64_result == nullptr)
        {
            return false;
        }

        output_len = strlen(base64_result);
        memcpy(output, base64_result, strlen(base64_result));
        free(base64_result);
    }

	return true;
}

bool LicenseVerifier::Decrypt(const char* input, char* output, int buffer_len, const char *key)
{
	if (input == nullptr || output == nullptr || key == nullptr)
	{
		return false;
	}

	AES_KEY aes_key;
	unsigned char ivec[AES_BLOCK_SIZE] = { 0 };
	memcpy(ivec, key, 16);
	if (AES_set_decrypt_key((const unsigned char*)key, 256, &aes_key) < 0)
	{
		return false;
	}

	int char_count = 0;
	unsigned char* base64_result = Base64Decode(input, false, char_count);
	if (base64_result == nullptr)
	{
		return false;
	}

	AES_cbc_encrypt((const unsigned char*)base64_result, (unsigned char*)output, char_count, &aes_key, ivec, AES_DECRYPT);

	free(base64_result);

	PKCS5UnPadding((char*)output, char_count, AES_BLOCK_SIZE);

	return true;
}

bool LicenseVerifier::GetLicenseInfo(const char* json_string, LicenseInfo& license_info)
{
	if (json_string == nullptr)
	{
		return false;
	}

    Log("%s\n", json_string);
    rapidjson::Document dom;
    dom.Parse(json_string);
    if (dom.HasParseError()) {
        rapidjson::ParseErrorCode errorCode = dom.GetParseError();
        size_t offset = dom.GetErrorOffset();
        Log("[DecryptLicense]Parse data fail, errorCode:%d, offset:%d\n", errorCode, offset);
        return false;
    }

    if (!dom.HasMember("timestamp") || !dom.HasMember("license"))
    {
        Log("[DecryptLicense]FAIL to get timestamp and license");
        return false;
    }

    int64_t timestamp = dom["timestamp"].GetInt64();
    time_t  timer;
    time(&timer);

    if (std::abs((int64_t)timer - timestamp) > 5 * 60)
    {
        Log("[DecryptLicense]license time INVALID, %lld, %lld", (int64_t)timer, timestamp);
        return false;
    }

    license_info.timestamp = timestamp;

    if (!dom.HasMember("license"))
    {
        return false;
    }
    const rapidjson::Value& license = dom["license"];

    if (!license.HasMember("productID") || !license.HasMember("productInfo") || !license.HasMember("uniqueInfo"))
    {
        return false;
    }

    license_info.product_id = license["productID"].GetString();
    license_info.product_info = license["productInfo"].GetString();

    if (license.HasMember("uniqueInfo"))
    {
        const rapidjson::Value& uniqueInfo = license["uniqueInfo"];
        if (!uniqueInfo.HasMember("MACAddress"))
        {
            Log("[DecryptLicense]fail to get deviceinfo 1");
            return false;
        }

        license_info.unique_info.mac_address = uniqueInfo["MACAddress"].GetString();
        std::transform(
            license_info.unique_info.mac_address.begin(),
            license_info.unique_info.mac_address.end(),
            license_info.unique_info.mac_address.begin(),
            [](unsigned char c) { return std::tolower(c); });

        if (!uniqueInfo.HasMember("deviceID"))
        {
            Log("[DecryptLicense]fail to get deviceinfo 2");
            return false;
        }

        license_info.unique_info.device_id = uniqueInfo["deviceID"].GetString();
        std::transform(
            license_info.unique_info.device_id.begin(),
            license_info.unique_info.device_id.end(),
            license_info.unique_info.device_id.begin(),
            [](unsigned char c) { return std::tolower(c); });
    }

    if (license.HasMember("startDate"))
    {
        license_info.start_date = license["startDate"].GetInt64();
    }

    if (license.HasMember("expirationDate"))
    {
        license_info.expiration_date = license["expirationDate"].GetInt64();
    }

    if (license.HasMember("gracePeriod"))
    {
        license_info.grace_period = license["gracePeriod"].GetInt64();
    }

    if (license.HasMember("creationDate"))
    {
        license_info.creation_date = license["creationDate"].GetInt64();
    }

	return true;
}

char* LicenseVerifier::Base64Encode(const unsigned char * input, int char_count, bool with_new_line, int& output_length)
{
	BIO * bmem = NULL;
	BIO * b64 = NULL;
	BUF_MEM * bptr = NULL;

	b64 = BIO_new(BIO_f_base64());
	if (!with_new_line) {
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	}
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	output_length = BIO_write(b64, input, char_count);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	char * buff = (char *)malloc(bptr->length + 1);
	memcpy(buff, bptr->data, bptr->length);
	buff[bptr->length] = 0;

	BIO_free_all(b64);

	return buff;
}

unsigned char* LicenseVerifier::Base64Decode(const char * input, bool with_new_line, int& output_length)
{
	BIO * b64 = NULL;
	BIO * bmem = NULL;
	size_t input_length = strlen(input);
	unsigned char * buffer = (unsigned char *)malloc(input_length);
	if (buffer == nullptr)
	{
		return nullptr;
	}

	memset(buffer, 0, input_length);

	b64 = BIO_new(BIO_f_base64());
	if (!with_new_line) {
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	}
	bmem = BIO_new_mem_buf(input, (int)input_length);
	bmem = BIO_push(b64, bmem);
	output_length = BIO_read(bmem, buffer, (int)input_length);

	BIO_free_all(bmem);

	return buffer;
}

bool LicenseVerifier::GetProcessCreateTime(int64_t& time)
{
	bool success = false;
	HANDLE process_handle = GetCurrentProcess();

	if (process_handle == nullptr)
	{
        Log("[Verify]fail to open parent process, error: %d", GetLastError());
		return false;
	}

	FILETIME create_time;
	FILETIME exit_time;
	FILETIME kernel_time;
	FILETIME user_time;
	if (GetProcessTimes(process_handle, &create_time, &exit_time, &kernel_time, &user_time))
	{
		time = *(int64_t*)&create_time;
		success = true;
	}
	else
	{
        Log("[Verify]fail to GetProcessTimes, error: %d", GetLastError());
	}

	return success;
}

bool LicenseVerifier::VerifyDeviceInfo(const char* mac_address, const char* cpu_id, char* message, int char_count)
{
    if (mac_address == nullptr || cpu_id == nullptr || message == nullptr || char_count <= 0)
    {
    }
	if (!VerifyMacAddress(mac_address))
	{
        strcpy_s(message, char_count, "Fail to verify first device info");
		Log("[Verify]fail to verify device at step 1");
		return false;
	}

	if (!VerifyCPUID(cpu_id))
	{
        strcpy_s(message, char_count, "Fail to verify second device info");
		Log("[Verify]fail to verify device at step 2");
		return false;
	}

	return true;
}

bool LicenseVerifier::VerifyMacAddress(const char* mac_address)
{
	bool success = false;
	if (mac_address == nullptr)
	{
		return false;
	}

   // IPAddr add = 0x08080808;
   // DWORD adapter_index = 0;
    //DWORD get_adapter_index_res = GetBestInterface(add, &adapter_index);

	IP_ADAPTER_INFO *info = nullptr;
	unsigned long size = 0;

	GetAdaptersInfo(info, &size);

	if (size == 0)
	{
        Log("[Verify]GetAdaptersInfo failed at first time, error: %d", GetLastError());
		return false;
	}

	info = (IP_ADAPTER_INFO *)malloc(size);
	if (info == nullptr)
	{
        Log("[Verify]GetAdaptersInfo malloc failed, error: %d", GetLastError());
		return false;
	}

	unsigned int res = GetAdaptersInfo(info, &size);
	if (res != NO_ERROR)
	{
        Log("[Verify]GetAdaptersInfo failed at second time, result:%u, error: %d", res, GetLastError());
		free(info);
		return false;
	}

	for (IP_ADAPTER_INFO* pos = info; pos != nullptr; pos = pos->Next) {
       // if (get_adapter_index_res == NO_ERROR && pos->Index != adapter_index)
       // {
       //     continue;
       // }

		char address[32] = { 0 };
		sprintf_s(address,
			sizeof(address),
			"%02x-%02x-%02x-%02x-%02x-%02x",
			pos->Address[0],
			pos->Address[1],
			pos->Address[2],
			pos->Address[3],
			pos->Address[4],
			pos->Address[5]);

		ToLower(address);

		if (strcmp(mac_address, address) == 0)
		{
			success = true;
			break;
		}
	}

	free(info);
	return success;
}

bool LicenseVerifier::GetMacAddress(char buffer[][64], int buffer_count, int* address_count)
{
    if (buffer == nullptr || address_count == nullptr || buffer_count <= 0)
    {
        return false;
    }

    IP_ADAPTER_INFO *info = nullptr;
    unsigned long size = 0;

    GetAdaptersInfo(info, &size);

    if (size == 0)
    {
        Log("[Verify]GetAdaptersInfo failed at first time, error: %d", GetLastError());
        return false;
    }

    info = (IP_ADAPTER_INFO *)malloc(size);
    if (info == nullptr)
    {
        Log("[Verify]GetAdaptersInfo malloc failed, error: %d", GetLastError());
        return false;
    }

    unsigned int res = GetAdaptersInfo(info, &size);
    if (res != NO_ERROR)
    {
        Log("[Verify]GetAdaptersInfo failed at second time, result:%u, error: %d", res, GetLastError());
        free(info);
        return false;
    }

    *address_count = 0;
    for (IP_ADAPTER_INFO* pos = info; pos != nullptr; pos = pos->Next) {
        char address[32] = { 0 };
        sprintf_s(address,
            sizeof(address),
            "%02x-%02x-%02x-%02x-%02x-%02x",
            pos->Address[0],
            pos->Address[1],
            pos->Address[2],
            pos->Address[3],
            pos->Address[4],
            pos->Address[5]);

        ToLower(address);

        if (*address_count < buffer_count)
        {
            strcpy_s(buffer[*address_count], 64, address);
            ++(*address_count);
        }
    }

    free(info);
    return true;
}

bool LicenseVerifier::VerifyCPUID(const char* cpu_id)
{
	if (cpu_id == nullptr)
	{
		return false;
	}

	char id[64] = { 0 };
	int cpu_info[4] = { 0 };
	__cpuidex(cpu_info, 1, 1);
	sprintf_s(id, sizeof(id), "%08x%08x", cpu_info[3], cpu_info[0]);

	if (strcmp(cpu_id, id) == 0)
	{
		return true;
	}

	return false;
}

bool LicenseVerifier::GetCPUID(char* buffer, int char_count)
{
    if (buffer == nullptr || char_count <= 0)
    {
        return false;
    }

    char id[64] = { 0 };
    int cpu_info[4] = { 0 };
    __cpuidex(cpu_info, 1, 1);
    sprintf_s(buffer, char_count, "%08x%08x", cpu_info[3], cpu_info[0]);

    return true;
}

void LicenseVerifier::ToLower(char* str)
{
	if (str == nullptr)
	{
		return;
	}

	while (*str != 0)
	{
		*str = (char)tolower(*str);
		++str;
	}
}

void LicenseVerifier::Log(const char* lpszFormat, ...)
{
    std::lock_guard<std::mutex> guard(mutex_);
    va_list pArg;
    va_start(pArg, lpszFormat);
    char szMessage[1024] = { 0 };
    DWORD dwSize = 0;
    _vsnprintf_s(szMessage, 1023, 1023, lpszFormat, pArg);
    OutputTraceInfo(szMessage);
}
