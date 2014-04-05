/*
	DiabloHorn http://diablohorn.wordpress.com
	Simple example of using wininet to do HTTP POST & GET
*/
#include "simple_http.h"
#include <WinInet.h>
#include <urlmon.h>
#include <malloc.h>

#include "zmem.h"

#pragma comment(lib,"wininet.lib")
#pragma comment(lib,"urlmon.lib")

#define SH_DEFAULT_UA "really_should_change_me"

/* 
	free the url parsed components and zero the structure 
*/
void destroy_url_components(URL_COMPONENTS *parsed_url){
	zfree(parsed_url->lpszScheme);
	zfree(parsed_url->lpszHostName);
	zfree(parsed_url->lpszUrlPath);
	zfree(parsed_url->lpszExtraInfo);

	RtlZeroMemory(parsed_url, sizeof(URL_COMPONENTS));
}

/* 
	parse url into needed compnenents 
	return a structure with size 0 if it fails
*/
URL_COMPONENTS parse_url(char *url){
	URL_COMPONENTS cracked_url;
	RtlZeroMemory(&cracked_url, sizeof(URL_COMPONENTS));
	cracked_url.dwStructSize = sizeof(URL_COMPONENTS);

	cracked_url.dwSchemeLength = INTERNET_MAX_SCHEME_LENGTH;
	cracked_url.dwHostNameLength = INTERNET_MAX_HOST_NAME_LENGTH;
	cracked_url.dwUrlPathLength = INTERNET_MAX_PATH_LENGTH;
	cracked_url.dwExtraInfoLength = INTERNET_MAX_PATH_LENGTH;
	cracked_url.lpszScheme = malloc(INTERNET_MAX_SCHEME_LENGTH);
	cracked_url.lpszHostName = malloc(INTERNET_MAX_HOST_NAME_LENGTH);
	cracked_url.lpszUrlPath = malloc(INTERNET_MAX_PATH_LENGTH);
	cracked_url.lpszExtraInfo = malloc(INTERNET_MAX_PATH_LENGTH);
	if (!InternetCrackUrl(url, strlen(url), 0, &cracked_url)){
		RtlZeroMemory(&cracked_url, sizeof(URL_COMPONENTS));
	}

	return cracked_url;
}

/*
	Retrieve IE user agent
	return hardcoded UA if it fails
*/
char *get_default_ua(){
	char *ua;	
	DWORD ualength = 512;
	int res = 0;

	ua = malloc(512);
	RtlZeroMemory(ua, 512);
	if (ua == NULL){
		return NULL;
	}
	RtlZeroMemory(ua, 512);
	/*	If AV picks up, reading reg could be a possible alternative:
		https://diablohorn.wordpress.com/2010/08/14/internetqueryoption-internet_option_user_agent-replacement/
	*/
	res = ObtainUserAgentString(0, ua, &ualength);
	if (res != NOERROR){
		strcpy_s(ua, 512, SH_DEFAULT_UA);
	}

	return ua;
}

/* 
	get the http respnse code 
	return -1 if it fails
*/
DWORD get_http_status_code(HINTERNET requesthandle){
	DWORD response_code = -1;
	DWORD response_code_size = sizeof(DWORD);
	BOOL ishttpqueryinfo = FALSE;

	ishttpqueryinfo = HttpQueryInfo(requesthandle, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &response_code, &response_code_size, NULL);
	if (!ishttpqueryinfo){
		return response_code;
	}
	return response_code;
}

/* 
	get the length of the response body 
	if we pass 1 as the second argument, the value will be ended with a 0byte
	return -1 if it fails
*/
DWORD get_http_content_length(HINTERNET requesthandle, int isString){
	DWORD content_length = 0;
	DWORD content_lengt_size = sizeof(DWORD);
	BOOL ishttpqueryinfo = FALSE;

	ishttpqueryinfo = HttpQueryInfo(requesthandle, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &content_length, &content_lengt_size, NULL);
	if (!ishttpqueryinfo){
		return -1;
	}
	/* decide if we want to have an extra \0 for string purposes */
	if (isString){
		return (content_length + 1);
	}

	return content_length;
}

/* retrieve the actual response content */
unsigned char *get_http_content(HINTERNET requesthandle, DWORD content_length){
	unsigned char *http_data = NULL;
	DWORD bytes_read = 0;

	/* doesn't take into account a max size, thus could run out of memory */
	http_data = (unsigned char *)malloc(content_length);	
	if (http_data == NULL){
		return NULL;
	}
	RtlSecureZeroMemory(http_data, content_length);
	if(!InternetReadFile(requesthandle, http_data, content_length, &bytes_read)){
		zfree(http_data);
		return NULL;
	}

	return http_data;
}

/* the most "low level" request on which we base all "wrappers" */
DWORD http_raw_request(int dopost, char *http_host, short http_port, char *http_headers, char *http_url, const char *accept_types[], unsigned char *http_data, unsigned int http_data_len, unsigned char **response_data){
	HINTERNET internetopenhandle = NULL;
	HINTERNET internetconnecthandle = NULL;
	HINTERNET httpopenrequesthandle = NULL; 
	BOOL ishttpsendrequest = FALSE;
	DWORD http_response_code = -1;
	DWORD http_response_content_length = 0;
	char *ua;

	ua = get_default_ua();
	if (ua == NULL){
		ua = malloc(32);
		if (ua = NULL){
			return http_response_code;
		}
		RtlZeroMemory(ua, 32);
		strcpy_s(ua, 32, SH_DEFAULT_UA);
	}
	internetopenhandle = InternetOpen(ua, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (internetopenhandle == NULL){
		return http_response_code;
	}
	
	internetconnecthandle = InternetConnect(internetopenhandle, http_host, http_port, NULL, NULL, INTERNET_SERVICE_HTTP, INTERNET_FLAG_RELOAD, 0);
	if (internetconnecthandle == NULL){
		return http_response_code;
	}

	/* adjust http verb according to flag */
	if (dopost){
		httpopenrequesthandle = HttpOpenRequest(internetconnecthandle, "POST", http_url, NULL, NULL, accept_types, 0, 0);
	}
	else{
		httpopenrequesthandle = HttpOpenRequest(internetconnecthandle, "GET", http_url, NULL, NULL, accept_types, 0, 0);
	}

	if (httpopenrequesthandle == NULL){
		return http_response_code;
	}

	/* send the actual request */
	ishttpsendrequest = HttpSendRequest(httpopenrequesthandle, http_headers, -1, http_data, http_data_len);
	if (!ishttpsendrequest){
		return http_response_code;
	}

	/* retrieve http response status code */
	http_response_code = get_http_status_code(httpopenrequesthandle);
	if (http_response_code == -1){
		return http_response_code;
	}
	
	/* assume that we can retrieve length */
	http_response_content_length = get_http_content_length(httpopenrequesthandle,1);
	
	if (http_response_content_length == -1){
		return http_response_code;
	}
	
	/* get the actual response content */
	*response_data = get_http_content(httpopenrequesthandle, http_response_content_length);
	if (*response_data == NULL){
		return http_response_code;
	}

	/* cleanup after ourselfs */
	zfree(ua);
	InternetCloseHandle(httpopenrequesthandle);
	InternetCloseHandle(internetconnecthandle);
	InternetCloseHandle(internetopenhandle);
	return http_response_code;
}

DWORD http_get_content(char *target, unsigned char **response_data){
	URL_COMPONENTS urlinfo;
	char *rgpszAcceptTypes[] = { "text/*", NULL };
	char *posturl;
	int posturllength = 0;
	char *hostheader;
	int hostheaderlength = 0;
	DWORD response_code = -1;

	/* parse the given url into the correct components */
	urlinfo = parse_url(target);
	if (urlinfo.dwStructSize == 0){
		return response_code;
	}

	/* concatenate path and extra info */
	posturllength = (urlinfo.dwExtraInfoLength + urlinfo.dwUrlPathLength) + 1;
	posturl = malloc(posturllength);
	memset(posturl, 0, posturllength);
	strncat_s(posturl, posturllength, urlinfo.lpszUrlPath, urlinfo.dwUrlPathLength);
	strncat_s(posturl, posturllength, urlinfo.lpszExtraInfo, urlinfo.dwExtraInfoLength);

	/* create the Host: header */
	hostheaderlength = urlinfo.dwHostNameLength + 7;
	hostheader = malloc(hostheaderlength);
	memset(hostheader, 0, hostheaderlength);
	strncat_s(hostheader, hostheaderlength, "Host: ", 6);
	strncat_s(hostheader, hostheaderlength, urlinfo.lpszHostName, urlinfo.dwHostNameLength);

	/* call the actual request making function */
	response_code = http_raw_request(0, urlinfo.lpszHostName, urlinfo.nPort, hostheader, posturl, rgpszAcceptTypes, NULL, 0, response_data);

	/* free all the resources */
	destroy_url_components(&urlinfo);
	zfree(hostheader);
	zfree(posturl);
	return response_code;
}

DWORD http_post_binary(char *target, unsigned char *post_data, int post_data_length, unsigned char **response_data){
	URL_COMPONENTS urlinfo;
	char *rgpszAcceptTypes[] = { "application/octet-stream", NULL };
	char *posturl;
	int posturllength = 0;
	char *hostheader;
	int hostheaderlength = 0;
	DWORD response_code = -1;

	/* parse the given url into the correct components */
	urlinfo = parse_url(target);
	if (urlinfo.dwStructSize == 0){
		return response_code;
	}

	/* concatenate path and extra info */
	posturllength = (urlinfo.dwExtraInfoLength + urlinfo.dwUrlPathLength) + 1;
	posturl = malloc(posturllength);
	memset(posturl, 0, posturllength);
	strncat_s(posturl, posturllength, urlinfo.lpszUrlPath, urlinfo.dwUrlPathLength);
	strncat_s(posturl, posturllength, urlinfo.lpszExtraInfo, urlinfo.dwExtraInfoLength);

	/* create the Host: header */
	hostheaderlength = urlinfo.dwHostNameLength + 7;
	hostheader = malloc(hostheaderlength);
	memset(hostheader, 0, hostheaderlength);
	strncat_s(hostheader, hostheaderlength, "Host: ", 6);
	strncat_s(hostheader, hostheaderlength, urlinfo.lpszHostName, urlinfo.dwHostNameLength);

	/* call the actual request making function */
	response_code = http_raw_request(1, urlinfo.lpszHostName, urlinfo.nPort, NULL, posturl, rgpszAcceptTypes, post_data, post_data_length, response_data);

	/* free all the resources */
	destroy_url_components(&urlinfo);
	zfree(hostheader);
	zfree(posturl);
	return response_code;
}

