#include "httpd.h"

#include <string.h>

#include <errno.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include "logger.h"

#define BOOL int
#define TRUE   1
#define FALSE  0

#define MHD_RESULT enum MHD_Result


//#if MHD_VERSION < 0x00095300
//	#define MHD_HTTP_PAYLOAD_TOO_LARGE MHD_HTTP_REQUEST_ENTITY_TOO_LARGE
//#endif
//
//#if MHD_VERSION < 0x00093400
//typedef int MHD_socket;
//#define MHD_INVALID_SOCKET (-1)
//#endif

struct request {
    BIO *payload;
    BOOL abandoned;
}; /* struct request */

//struct httpd {
//    struct MHD_Daemon *daemon;
//    httpd_handler_t handler;
//    void *context;
//    uint16_t port;
//}; /* struct httpd */

static const unsigned char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *query; // pointe vers la variable "QUERY_STRING"
char *SCRIPT_NAME; // pointe vers la variable "SCRIPT_NAME
char *REQUEST_METHOD; //pointe vers la variable "REQUEST_METHOD"
char *content_type; //pointe vers la variable "content_type"
char *content_length; //pointe vers la variable "content_length"
char *script_uri;
char *PATH_INFO;
char Copie_Query[65536] = {0};
char scNb_Param;
size_t	Taille_Data_Recue = 0; //quantité de donnée recu. ici utile pour alouer de la mémoire lors d'un POST

/**
 * @fn int httpd_hello(void)
 * @brief
 *
 * @return
 */
//void httpd_hello(int number) {
//	printf("Content-Type: text/html\n\n");
//	printf("<html>\n");
//	printf("<body>\n");
//	printf("Error %d\n",number); /* prints !!!Hello World!!! */
//	printf("</body>\n");
//	printf("</html>\n");
//	exit(EXIT_SUCCESS);
//}

/**
 * @fn char http_parameter*(char*, char*)
 * @brief get the value of a parameter in the query_string
 *
 * @param query_string
 * @param ParameterName
 * @return 0 if OK and -1 if not
 */
int http_parameter(char * query_string, char * ParameterName ,char * buffer, size_t buffer_length)
{
	int ret = -1;
	int i;
	size_t l;
	char *pDeb = NULL;
	char *pC = NULL;

	if ((query_string != NULL)
		&& (ParameterName != NULL)
		&& (buffer != NULL)
		&& (buffer_length > 0)
		)
	{
		pDeb = strstr(query_string,ParameterName);
		pC = pDeb;
		if (pDeb != NULL)
		{
			// Get the value
			pDeb = strchr(pDeb,'=');
			if (pDeb != NULL)
			{
				pDeb++;
				pC = buffer;
				l = 0;
				*pC = 0;
				while ((*pDeb != 0)
						&& (*pDeb != '=')
						&& (*pDeb != '&'))
				{
					if (l<buffer_length)
					{
						*pC = *pDeb;
						pC++;
						l++;
					}
					else
					{
						break;
					}
					pDeb++;
				}
				ret = 0;
			}

		}
	}

	return (ret);
}

/**
 * @fn int32_t Initialisation(HTTPParameters*)
 * @brief
 *
 * @param pClientParams
 * @return
 */
int32_t http_uri_decode(HTTPParameters *pClientParams)
{
    uint32_t  nArg;
//    UINT32  nResult;
//    CHAR    *pSearchPtr = NULL;
//    CHAR    PortNum[64];
	//UINT32	ui32Count;
	//CHAR	extension[10];
	char	nom_fichier[300];
	char    *pCaractere;
	char    debut_fichier[10];


	// Récupération des variables d'environnement utile
	query = getenv("QUERY_STRING"); // Les variables demandé par le site
	SCRIPT_NAME = getenv("SCRIPT_NAME");
	script_uri = getenv("SCRIPT_URI");
	PATH_INFO = getenv("PATH_INFO");
	content_type = getenv("CONTENT_TYPE");
	content_length = getenv("CONTENT_LENGTH");

	strcpy(Copie_Query,query);

	if (content_length != NULL)
	{
		Taille_Data_Recue = atol(content_length);
	}
	else
	{
		Taille_Data_Recue = 0;
	}
	REQUEST_METHOD = getenv("REQUEST_METHOD");


	strcpy(nom_fichier, SCRIPT_NAME);

	nArg = strlen(nom_fichier);
	pCaractere = &nom_fichier[nArg];
	while ((pCaractere > &nom_fichier[0]) && (*pCaractere!='.')) {
		pCaractere--;
	}

	// On récupére l'extension du fichier
	if (pCaractere > &nom_fichier[0]) {
//		ui32Count = strlen(nom_fichier) - (pCaractere - &nom_fichier[0]);
//		strncpy(extension, pCaractere, ui32Count);
		*pCaractere = '\0';
//		extension[ui32Count]=0;
	}

	// On cherche le nom du fichier uniquement
	while ((pCaractere > &nom_fichier[0]) && (*pCaractere!='/')) {
		pCaractere--;
	}
	if (pCaractere > &nom_fichier[0]) {
		pCaractere++;
		strncpy(debut_fichier,pCaractere,4);
		debut_fichier[4] = 0;
	}
	LOGD("nom_fichier = %s",nom_fichier);
	LOGD("Request method = %s",REQUEST_METHOD);
	LOGD("query =%s",query); // = getenv("QUERY_STRING"); // Les variables demandé par le site
	LOGD("SCRIPT_NAME =%s",	SCRIPT_NAME);// = getenv("SCRIPT_NAME");
	LOGD("script_uri =%s",	script_uri);// = getenv("SCRIPT_URI");
	LOGD("PATH_INFO =%s",	PATH_INFO);// = getenv("PATH_INFO");
	LOGD("content_type =%s",	content_type);// = getenv("CONTENT_TYPE");
	LOGD("content_length =%s",	content_length);// = getenv("CONTENT_LENGTH");
//	if (strcmp(debut_fichier,"slt_")==0)
//	{
//		// On est sur un fichier à générer par le plugin et non dans le switch
//		strcpy(pClientParams->Uri,pCaractere);
//		return 1; // On part maintenant car il n'y a jamais de paramétres sur les fichiers auto généré...
//	}
//
//
//
//	// En fonction de l'extension, on execute quelque chose
//	strcpy(pClientParams->Uri, "http://1.0.0.2");
//	strcat(pClientParams->Uri, nom_fichier);
//	if (query != 0)
//	{
//		strcat(pClientParams->Uri, "?");
//		strcat(pClientParams->Uri, query);
//	}
//
//	pClientParams->Verbose = FALSE;
//	//pClientParams->ProxyHost = "";
//	//pClientParams->ProxyPort;
//	pClientParams->AuthType = AuthSchemaNone;
//	//pClientParams->UserName;
//	//pClientParams->Password;

    return 0;
}

/**
 * @fn int httpd_html_escape(const char*, int)
 * @brief Convert special character to html code
 *
 * @param s char *: pointer to the string we need to write
 * @param escape_apos
 * @return 0 if OK and -1 if NOK
 */
static int httpd_html_escape(
		char *http_response,
		size_t http_response_length,
        const char *s,
        BOOL escape_apos)
{
    const char *p;
    size_t needed;
    int ret;

    for (needed = 0, p = s; *p; ++p) {
        switch (*p) {
        case '\'' : needed += escape_apos ? 5 : 1; break;
        case '"'  : needed += 6; break;
        case '&'  : needed += 5; break;
        case '<'  : needed += 4; break;
        case '>'  : needed += 4; break;
        default   : needed += 1; break;
        }
    }

    for (p = s; *p; ++p) {
        switch (*p) {
        case '"' : ret = snprintf(http_response, http_response_length, "&quot;"); break;
        case '&' : ret = snprintf(http_response, http_response_length, "&amp;"); break;
        case '<' : ret = snprintf(http_response, http_response_length, "&lt;"); break;
        case '>' : ret = snprintf(http_response, http_response_length, "&gt;"); break;
        case '\'':
            if (escape_apos) {
                ret = snprintf(http_response, http_response_length, "&#39;");
            } else {
                ret = snprintf(http_response, http_response_length, p, 1);
            }
            break;
        default:
            ret = snprintf(http_response, http_response_length, p, 1);
            break;
        };

        if (ret <= 0) {
            return -1;
        }
    }

    return 0;
}

/**
 * @fn enum MHD_Result httpd_create_standard_response*(char*, unsigned int)
 * @brief
 *
 * @param http_response
 * @param status_code
 * @return
 */
static enum MHD_Result  httpd_create_standard_header(
        char * http_response,
		size_t http_response_length,
		unsigned int status_code)
{


	enum MHD_Result r = MHD_NO;
	char *pC = 0;

	if ((http_response != NULL)
		&& (http_response_length >= MINIMUM_HEADER_LENGTH))
	{
		strncpy(http_response, "Content-Type: text/html\n", http_response_length - 1);
		pC = http_response + strlen(http_response);
		snprintf(pC, (http_response_length - 1 - strlen(http_response)), "Status: %d\n\n",status_code);
		r = MHD_YES;
	}
	return(r);
}

/**
 * @fn enum MHD_Result httpd_create_standard_response*(char*, unsigned int, const char*, int)
 * @brief
 *
 * @param http_response
 * @param status_code
 * @param extra
 * @param close
 * @return
 */
static enum MHD_Result  httpd_create_standard_response(
        char * http_response,
		size_t http_response_length,
		unsigned int status_code,
        const char *extra,
        BOOL close)
{
	enum MHD_Result r = MHD_NO;
    const char *status;
    BUF_MEM *bptr;
    //BIO *bp;
    char *pC = NULL;

    switch (status_code) {
    case MHD_HTTP_FOUND:
        status = "Found";
        break;
    case MHD_HTTP_BAD_REQUEST:
        status = "Bad Request";
        break;
    case MHD_HTTP_FORBIDDEN:
        status = "Forbidden";
        break;
    case MHD_HTTP_NOT_FOUND:
        status = "Not Found";
        break;
    case MHD_HTTP_METHOD_NOT_ALLOWED:
        status = "Method Not Allowed";
        break;
    case MHD_HTTP_PAYLOAD_TOO_LARGE:
        status = "Payload Too Large";
        break;
    case MHD_HTTP_INTERNAL_SERVER_ERROR:
        status = "Internal Server Error";
        break;
    default:
        abort();
    }

    pC = http_response + strlen(http_response);
    snprintf(pC,
    		http_response_length - strlen(http_response),
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
            "<html><head>\n"
            "<title>%u %s</title>\n"
            "</head><body>\n"
            "<h1>%s</h1>\n"
            "<p>", status_code, status, status);

    switch (status_code) {
    case MHD_HTTP_FOUND:
    	pC = http_response + strlen(http_response);
    	snprintf(pC,
    	   		http_response_length - strlen(http_response),
				"The document has moved <a href=\"");
    	httpd_html_escape(http_response, http_response_length,extra, FALSE);
    	snprintf(http_response,	http_response_length, "\">here</a>.");
        break;

    case MHD_HTTP_BAD_REQUEST:
    	pC = http_response + strlen(http_response);
    	snprintf(pC,
    			http_response_length - strlen(http_response),
				"Your browser sent a request that this server could "
                "not understand.<br />\n");
        break;

    case MHD_HTTP_FORBIDDEN:
    	pC = http_response + strlen(http_response);
    	snprintf(pC,
    	   		http_response_length - strlen(http_response),
				"You don't have permission to access this resource.");
        break;

    case MHD_HTTP_NOT_FOUND:
    	pC = http_response + strlen(http_response);
    	snprintf(pC,
    	   		http_response_length - strlen(http_response),
				"The requested URL was not found on this server.");
        break;

    case MHD_HTTP_METHOD_NOT_ALLOWED:
    	pC = http_response + strlen(http_response);
    	snprintf(pC,
    	   		http_response_length - strlen(http_response),
				"The requested method ");
    	//httpd_html_escape(http_response, http_response_length,extra, FALSE);
    	pC = http_response + strlen(http_response);
        snprintf(pC,
        		pC = http_response + strlen(http_response),
				" is not allowed for this URL.");
        break;

    case MHD_HTTP_PAYLOAD_TOO_LARGE:
    	pC = http_response + strlen(http_response);
    	snprintf(pC,
    	   		http_response_length - strlen(http_response),
				"The requested resource does not allow "
                "request data with ");
//    	pC = http_response + strlen(http_response);
//    	httpd_html_escape(pC, http_response_length-strlen(http_response) ,extra, FALSE);
    	pC = http_response + strlen(http_response);
    	snprintf(pC,
    	   		http_response_length - strlen(http_response),
				" requests, or the amount of data provided in\n"
                "the request exceeds the capacity limit.");
        break;

    case MHD_HTTP_INTERNAL_SERVER_ERROR:
    	pC = http_response + strlen(http_response);
    	snprintf(pC,
    	   		http_response_length - strlen(http_response),
				"The server encountered an internal error or\n"
                "misconfiguration and was unable to complete\n"
                "your request.</p>\n"
                "<p>Please contact the server administrator at \n"
                " ");
        //httpd_html_escape(http_response, http_response_length,extra, FALSE);
        snprintf(http_response,
            	http_response_length,
				" to inform them of the time this error occurred,\n"
                " and the actions you performed just before this error.</p>\n"
                "<p>More information about this error may be available\n"
                "in the server error log.");
        break;

    default:
        abort();
        return (r);
    }

    pC = http_response + strlen(http_response);
    snprintf(pC,
       		http_response_length - strlen(http_response),
			"</p>\n</body></html>\n");

    r = MHD_YES;
    return (r);
}

/**
 * @fn enum MHD_Result httpd_standard_response(char*, unsigned int, const char*, int)
 * @brief
 *
 * @param http_response : buffer to send datas
 * @param status_code
 * @param extra
 * @param close
 * @return
 */
static enum MHD_Result httpd_standard_response(
        //struct MHD_Connection *connection,
		char * http_response,
		size_t http_response_length,
        unsigned int status_code,
        const char *extra,
        BOOL close)
{
//    struct MHD_Response *r;
	FILE * fp = NULL;
    enum MHD_Result ret, r;

    r = httpd_create_standard_header(http_response, http_response_length, status_code);
    if (r == MHD_NO) {
		return MHD_NO;
	}

    r = httpd_create_standard_response(http_response, http_response_length, status_code, extra, close);
    if (r == MHD_NO) {
        return MHD_NO;
    }

    LOGD("http: standard response %u is sent to webserver", status_code);
    //ret = MHD_queue_response(connection, status_code, r);
    //MHD_destroy_response(r);
    //httpd_hello(30);
    fp = fopen("/opt/httpd_standard_response.log","w");
    if (fp != NULL)
    {
    	fprintf(fp,"%s",http_response);
    	fclose(fp);
    }
    printf("%s",http_response);
    exit(EXIT_SUCCESS);
    return ret;
}

/**
 * @fn struct MHD_Response httpd_create_redirect_response*(char*, size_t, const char*)
 * @brief
 *
 * @param http_response
 * @param http_response_length
 * @param url
 * @return
 */
static enum MHD_Result httpd_create_redirect_response(
		char * http_response,
		size_t http_response_length,
		const char *url)
{
	enum MHD_Result r;
	size_t i = 0;

    r = httpd_create_standard_header(http_response, http_response_length, MHD_HTTP_FOUND);
	if (!r) {
		return MHD_NO;
	}

	i = (size_t)snprintf(http_response, http_response_length -1,"Location: %s\n",url);
	if (i>= http_response_length-1)
	{
		return MHD_NO;
	}

	r = httpd_create_standard_response(http_response, http_response_length, MHD_HTTP_FOUND, url, FALSE);
    if (!r) {
        return MHD_NO;
    }

    return MHD_YES;
}

/**
 * @fn enum MHD_Result httpd_redirect(char*, size_t, const char*)
 * @brief
 *
 * @param http_response
 * @param http_response_length
 * @param url
 * @return
 */
static enum MHD_Result httpd_redirect(
		char * http_response,
		size_t http_response_length,
        const char *url)
{
    enum MHD_Result ret;

    ret = httpd_create_redirect_response(http_response, http_response_length, url);
    if (!ret) {
        return MHD_NO;
    }

    printf("%s",http_response);
    return ret;
}

/**
 * @fn enum MHD_Result httpd_error(struct MHD_Connection*, const char*)
 * @brief
 *
 * @param connection
 * @param admin
 * @return
 */
static enum MHD_Result httpd_error(
		char * http_response,
		size_t http_response_length,
		const char *admin)
{
    return httpd_standard_response(
    		http_response,
			http_response_length,
            MHD_HTTP_INTERNAL_SERVER_ERROR,
            admin,
            TRUE);
}

/**
 * base64_decode - Base64 decode
 * @src: Data to be decoded
 * @len: Length of the data to be decoded
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of decoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
int httpd_base64_decode(
		const unsigned char *src,
		size_t len,
		unsigned char *out,
	    size_t *out_len)
{
	unsigned char dtable[256] = {0x80};
	unsigned char *pos;
	unsigned char block[4];
	unsigned char tmp;
	size_t i = 0;
	size_t count = 0;
	int pad = 0;

	//os_memset(dtable, 0x80, 256);
	for (i = 0; i < sizeof(base64_table) - 1; i++)
		dtable[base64_table[i]] = (unsigned char) i;
	dtable['='] = 0;

	count = 0;
	for (i = 0; i < len; i++) {
		if (dtable[src[i]] != 0x80)
			count++;
	}

	if (count == 0 || count % 4)
		return 1;

	//olen = count / 4 * 3;
	pos = out; // = os_malloc(olen);
	if (out == NULL)
		return 1;

	count = 0;
	for (i = 0; i < len; i++) {
		tmp = dtable[src[i]];
		if (tmp == 0x80)
			continue;

		if (src[i] == '=')
			pad++;
		block[count] = tmp;
		count++;
		if (count == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;
			if (pad) {
				if (pad == 1)
					pos--;
				else if (pad == 2)
					pos -= 2;
				else {
					/* Invalid padding */
					//os_free(out);
					return 1;
				}
				break;
			}
		}
	}

	*out_len = pos - out;
	return 0;
}

/**
 * @fn int httpd_base64_decode_bio(const char*, BIO*)
 * @brief
 *
 * @param input
 * @param bp
 * @return
 */
static int httpd_base64_decode_bio(const char *input, BIO *bp)
{
    unsigned char buffer[1024];
    size_t len;
    BIO *bmem;
    BIO *b64;
    int ret;

    len = strlen(input);
    bmem = BIO_new_mem_buf(input, len);
    if (!bmem) {
        return -1;
    }

    b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        BIO_free_all(bmem);
        return -1;
    }

    b64 = BIO_push(b64, bmem);

    for (;;) {
        ret = BIO_read(b64, buffer, sizeof(buffer));
        if (ret < 0) {
            BIO_free_all(b64);
            return -1;
        } else if (ret == 0) {
            break;
        }

        if (BIO_write(bp, buffer, ret) != ret) {
            BIO_free_all(b64);
            return -1;
        }
    }

    BIO_free_all(b64);
    return 0;
}


/**
 * @fn enum MHD_Result httpd_handler(void*, struct MHD_Connection*, const char*, const char*, const char*, const char*, size_t*, void**)
 * @brief
 *
 * @param cls
 * @param connection
 * @param url
 * @param method
 * @param version
 * @param upload_data
 * @param upload_data_size
 * @param con_cls
 * @return
 */
MHD_RESULT httpd_handler(
		struct context *context,
        const char *url,
        const char *method,
        size_t *upload_data_size
		)
{
	char http_response_buf[1048576] = {0};
    static const size_t kMaximum = 1048576;
    struct request *request;
    enum MHD_Result result;
    //struct MHD_Response *r;
    char operation[50] = {0};
    //struct httpd *httpd;
    unsigned int status;
    char message[1048576] = {0};
    char payload[1048576] = {0};
    const char *rct;
    BUF_MEM *bptr;
    BIO *response;
    int ret;
    int32_t scep_operation = 0;
    uint32_t u32;

    //request = (struct request *)*con_cls;
    //if (!request) {

    LOGD("Enter httpd_handler");
	request = (struct request *)malloc(sizeof(*request));
	if (!request) {
		LOGE("Error to create request");
		return MHD_NO;
	}


	memset(request, 0, sizeof(*request));
	request->payload = BIO_new(BIO_s_mem());
	//request->payload = BIO_new_fp(stdin, BIO_NOCLOSE);
	if (!request->payload) {
		LOGE("Error to create request->payload");
		free(request);
		return MHD_NO;
	}

        //*con_cls = request;

        //return MHD_YES;
    //}



    if (*upload_data_size) {
    	LOGD("upload_data_size = %ld", *upload_data_size);
        if (request->abandoned) {
        	LOGD("Request abandonned");
            *upload_data_size = 0;
            return MHD_YES;
        }
//        else if (strcmp(method, "POST") == 0) {
//        	LOGD("method = POST so abandoned");
//            request->abandoned = TRUE;
//            *upload_data_size = 0;
//            return MHD_YES;
//        }

        // Read data from stdin to request->payload
        u32 = *upload_data_size;
        while (u32 >0)
        {
        	if (u32< sizeof(payload))
        	{
        		fread(payload,1,u32,stdin);
        		ret = BIO_write(request->payload, payload, u32);
        		if ((ret < 0) || ((size_t)ret != u32))
        		{
					LOGE("Error to write in BIO %ld datas: Request abandonned", u32);
					*upload_data_size = 0;
					//return MHD_NO;
				}
        		u32 = 0;
        	}
        	else
        	{
        		fread(payload,1,sizeof(payload),stdin);
        		ret = BIO_write(request->payload, payload, sizeof(payload));
        		if ((ret < 0) || ((size_t)ret != sizeof(payload)))
				{
					LOGE("Error to write in BIO : Request abandonned");
					*upload_data_size = 0;
					//return MHD_NO;
				}
        		u32 -= sizeof(payload);
        	}

        }

        // Get pointer of datas
        BIO_get_mem_ptr(request->payload, &bptr);
        if (bptr == NULL)
        {
        	LOGD("Error to create bptr");
			request->abandoned = TRUE;
			return MHD_NO;
        }

        if (bptr->length + *upload_data_size > kMaximum) {
        	LOGD("payload length = %ld", bptr->length);
            request->abandoned = TRUE;
            return MHD_YES;
        }
        if (bptr->length >0) LOGD("uploaded datas (%s)", bptr->data);
        //ret = BIO_write(request->payload, upload_data, *upload_data_size);
        // Get the datas from stdin to get the payload

//        if (ret < 0 || (size_t)ret != *upload_data_size) {
//            return MHD_NO;
//        }
//        LOGD("return upload_data_size = 0");
//        *upload_data_size = 0;
//        return MHD_YES;

    } else if (request->abandoned) {
    	LOGE("Request abandonned");
        return httpd_standard_response(
        		http_response_buf,
				sizeof(http_response_buf),
                MHD_HTTP_PAYLOAD_TOO_LARGE,
                method,
				TRUE);
    }



    // Get the scep operation
//    operation = MHD_lookup_connection_value(
//            connection, MHD_GET_ARGUMENT_KIND, "operation");

    ret = http_parameter(query, "operation", operation, sizeof(operation));
    if ((strlen(operation) == 0) || (ret != 0)) {
    	LOGE("operation must define");
        return httpd_standard_response(
        		http_response_buf,
        		sizeof(http_response_buf),
                MHD_HTTP_BAD_REQUEST,
                NULL, FALSE);
    }

    LOGD("http: %s %s?operation=%s", method, url, operation);


    if (strcmp(method, "GET") == 0) {
    	// the message is in the URL with parameter message
//        message = MHD_lookup_connection_value(
//                connection, MHD_GET_ARGUMENT_KIND, "message");
    	ret = http_parameter(query, "message", message, sizeof(message));
    	if ((strlen(message) == 0) || (ret != 0)) {
//            if (httpd_base64_decode(message, sizeof(message), payload, sizeof(payload)))
    		LOGD("message is here so we decod it\n");
    		if (httpd_base64_decode_bio(message, request->payload))
            {
    			LOGE("Error to decod the message in base64\n");
                return httpd_error(
                		http_response_buf,
                		sizeof(http_response_buf),
						"admin@example.com");
            }
        }

    } else if (strcmp(method, "POST") == 0) {
        /* Nothing special about this */
    	LOGD("method POST : nothing to do\n");

    } else {
    	LOGE("METHOD IS not allowed\n");
        return httpd_standard_response(
        		http_response_buf,
        		sizeof(http_response_buf),
                MHD_HTTP_METHOD_NOT_ALLOWED,
                method, FALSE);
    }

    LOGD("create response to the message\n");
    response = BIO_new(BIO_s_mem());
    if (!response) {
        return MHD_NO;
    }

    LOGD("Execute the operation\n");
    rct = NULL;
//    httpd = (struct httpd *)cls;
//    status = httpd->handler(httpd->context, operation, request->payload, &rct, response);
    status = handle( context, operation, request->payload, &rct, response, &scep_operation);
    LOGD("Status after operation %d\n", status);

    BIO_get_mem_ptr(response, &bptr);
    switch (status) {
    case MHD_HTTP_FOUND:
    case MHD_HTTP_MOVED_PERMANENTLY:
//        result = httpd_redirect(
//        					http_response_buf,
//							sizeof(http_response_buf),
//							bptr->data);
        BIO_free_all(response);
        return result;

    case MHD_HTTP_FORBIDDEN:
    case MHD_HTTP_NOT_FOUND:
    case MHD_HTTP_BAD_REQUEST:
        BIO_free_all(response);
        return httpd_standard_response(
        		http_response_buf,
				sizeof(http_response_buf),
				status,
				NULL,
				FALSE);

    case MHD_HTTP_OK:
        break;

    default:
        BIO_free_all(response);
        return httpd_error(
        		http_response_buf,
				sizeof(http_response_buf),
				"admin@example.com");
    }

//    r = MHD_create_response_from_buffer(
//            bptr->length, bptr->data,
//            MHD_RESPMEM_MUST_COPY);

    // send header to the Apache server
    snprintf(http_response_buf,
			sizeof(http_response_buf),
			"Content-Type: %s\r\n", rct);
    strncat(http_response_buf, MHD_HTTP_HEADER_CACHE_CONTROL
    							": private, no-cache, no-store, must-revalidate, "
    		                	"max-age=0\r\n", sizeof(http_response_buf));
    strncat(http_response_buf, MHD_HTTP_HEADER_PRAGMA": no-cache\r\n", sizeof(http_response_buf));
    strncat(http_response_buf, "\r\n", sizeof(http_response_buf));
    printf("%s",http_response_buf);
    //send datas to the Apache server
    fwrite(bptr->data, 1, bptr->length, stdout);
//    strncat(http_response_buf, bptr->data, sizeof(http_response_buf));
//
////    if (scep_operation == GetCAcaps)
////	{
////		strncat(http_response_buf, "\r\n", sizeof(http_response_buf));
////	}
//    fD = fopen("/opt/httpd_handler.log","w");
//    if (fD != NULL)
//    {
//    	fprintf(fD,"%s",http_response_buf);
//    	fclose(fD);
//    }

    //printf("%s",http_response_buf);
    LOGD("http: user response (%s) is sent. Length of datas : %ld; bptr->length = %ld", http_response_buf, strlen(http_response_buf), bptr->length);

    if (response) BIO_free_all(response);
    exit(EXIT_SUCCESS);
    if (bptr) BUF_MEM_free(bptr);

//    if (!r) {
//        return httpd_error(
//        		http_response_buf,
//				sizeof(http_response_buf),
//				"admin@example.com");
//    }

//    if (MHD_add_response_header(r, MHD_HTTP_HEADER_SERVER,
//                "Apache") != MHD_YES ||
//        MHD_add_response_header(r, MHD_HTTP_HEADER_CACHE_CONTROL,
//                "private, no-cache, no-store, must-revalidate, "
//                "max-age=0") != MHD_YES ||
//        MHD_add_response_header(r, MHD_HTTP_HEADER_PRAGMA,
//                "no-cache") != MHD_YES ||
//        (rct && MHD_add_response_header(r, MHD_HTTP_HEADER_CONTENT_TYPE,
//                rct) != MHD_YES) ){
//
//        MHD_destroy_response(r);
//        return httpd_error(connection, "admin@example.com");
//    }

    // send the response
//    result = MHD_queue_response(
//    		http_response_buf,
//			sizeof(http_response_buf),
//			status,
//			r);

    //MHD_destroy_response(r);
    return result;
}

#if 0
/**
 * @fn void httpd_completed(void*, struct MHD_Connection*, void**, enum MHD_RequestTerminationCode)
 * @brief
 *
 * @param cls
 * @param connection
 * @param con_cls
 * @param toe
 */
static void httpd_completed(
        void *cls,
        struct MHD_Connection *connection,
        void **con_cls,
        enum MHD_RequestTerminationCode toe)
{
    struct request *request;

    (void)cls;
    (void)connection;
    (void)toe;

    request = (struct request *)(*con_cls);
    BIO_free_all(request->payload);
    free(request);
}

struct httpd *httpd_new(uint16_t port, httpd_handler_t handler, void *context)
{
    struct httpd *httpd;

    if (!port || !handler) {
        return NULL;
    }

    httpd = (struct httpd *)malloc(sizeof(*httpd));
    if (!httpd) {
        return NULL;
    }

    memset(httpd, 0, sizeof(*httpd));
    httpd->handler = handler;
    httpd->context = context;
    httpd->port = port;
    return httpd;
}

int httpd_start(struct httpd *httpd)
{
    const unsigned int flags = MHD_USE_DUAL_STACK;

    httpd->daemon = MHD_start_daemon(
            flags, httpd->port, NULL, NULL,
            httpd_handler, httpd,
            MHD_OPTION_NOTIFY_COMPLETED,
            httpd_completed, httpd,
            MHD_OPTION_END);

    if (!httpd->daemon) {
        return -1;
    }

    return 0;
}

int httpd_poll(struct httpd *httpd, sigset_t *sigset)
{
    fd_set rset;
    fd_set wset;
    fd_set eset;
    int max;
    int ret;

    max = -1;
    FD_ZERO(&rset);
    FD_ZERO(&wset);
    FD_ZERO(&eset);
    if (MHD_get_fdset(httpd->daemon, &rset, &wset, &eset, &max) != MHD_YES) {
        return -1;
    }

    ret = pselect(max + 1, &rset, &wset, &eset, NULL, sigset);
    if (ret < 0) {
        if (errno != EINTR) {
            return -1;
        }
        return 0;
    } else if (ret == 0) {
        return 0;
    }

    if (MHD_run_from_select(httpd->daemon, &rset, &wset, &eset) != MHD_YES) {
        return -1;
    }

    return 0;
}

int httpd_stop(struct httpd *httpd)
{
    MHD_socket listener;

    listener = MHD_quiesce_daemon(httpd->daemon);
    MHD_stop_daemon(httpd->daemon);
    if (listener != MHD_INVALID_SOCKET) {
        close(listener);
    }

    httpd->daemon = NULL;
    return 0;
}

void httpd_free(struct httpd *httpd)
{
    free(httpd);
}

#endif
