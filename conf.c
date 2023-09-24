/*
 * conf.c
 *
 *  Created on: 19 sept. 2023
 *      Author: gege
 */

#include <stdio.h>
#include "scep.h"
#include "httpd.h"
#include "conf.h"
#include "logger.h"

char challenge[512] = {0};

/**
 * @fn void conf_init(struct scep_configure*, struct context*)
 * @brief
 *
 * @param configure
 * @param ctx
 */
void conf_init(struct scep_configure * configure, struct context *ctx)
{
	ctx->challenge_password = "emis";
	ctx->allow_renew_days = 0;
	ctx->depot = NULL;
	ctx->validity_days = 10000;

	configure->set_subject_alternative_name = 1;
	configure->tolerate_exposed_challenge_password = 0;
	configure->no_validate_transaction_id = 1;
}
/**
 * @fn int32_t conf_read_file(char*, struct scep_configure*, struct context*)
 * @brief
 *
 * @param conf_filename
 * @param configure
 * @param ctx
 * @return
 */
int32_t conf_read_file(char * conf_filename, struct scep_configure * configure, struct context *ctx)
{
	int32_t ret = 0;
	FILE * fp;
	char line[256] = {0};
	char *ParameterName = NULL;
	char *ParameterValue = NULL;
	char *pC;
	long i32;

	LOGD("Enter in conf_read_file");
	fp=fopen(conf_filename,"r");
	if (fp)
	{
		while (fgets(line, sizeof(line)-1, fp) != NULL)
		{
			if ((line[0] != '#')
				&& (strlen(line)>2))
			{
				// We have a line like this challenge_password=toto;
				// First, we search ParameterName
				pC = strchr(line,'=');
				if (pC == NULL)
				{
					LOGE("Error when searching =");
					ret = 1;
					break;
				}
				ParameterName = &line[0];
				*pC = 0;
				pC++;
				ParameterValue = pC;

				// We search the end of line
				pC = strchr(pC, ';');
				if (pC != NULL)
				{
					*pC = 0;
				}
				else
				{
					i32 = strlen(pC);
					*(pC + i32) = 0;
				}

				// We have all the informations that we need so we manage the control
				if (strcmp(ParameterName,"challenge_password") == 0)
				{
					ctx->challenge_password = challenge;
					strncpy(challenge, ParameterValue, sizeof(challenge)-1);
				}
				else if (strcmp(ParameterName,"allow_renew_days") == 0)
				{
					ctx->allow_renew_days = atol(ParameterValue);
				}
				else if (strcmp(ParameterName,"validity_days") == 0)
				{
					ctx->validity_days = atol(ParameterValue);
				}
				else if (strcmp(ParameterName,"set_san") == 0)
				{
					configure->set_subject_alternative_name = atoi(ParameterValue);
				}
				else if (strcmp(ParameterName,"tolerate_exposed_challenge_password") == 0)
				{
					configure->tolerate_exposed_challenge_password = atoi(ParameterValue);
				}
				else if (strcmp(ParameterName,"no_validate_transaction_id") == 0)
				{
					configure->no_validate_transaction_id = atoi(ParameterValue);
				}
			}
		}
		fclose(fp);
	}
	else
	{
		ret = 1;
	}

//	if (ret != 0)
//	{
//		printf("ERROR template n° %d\n",ret);
//	}
	return(ret);
}

/**
 * @fn int32_t conf_save_file(char*, struct scep_configure*, struct context*)
 * @brief This function save on the disk the current configuration of scep_cgi
 *
 * @param conf_filename char *: filename of the configuration
 * @param configure struct scep_configure * :
 * @param ctx struct context * :
 * @return 0 if OK
 */
int32_t conf_save_file(char * conf_filename, struct scep_configure * configure, struct context *ctx)
{
	FILE * fp = NULL;

	if ((conf_filename == NULL)
		|| (configure == NULL)
		|| (ctx == NULL))
	{
		return -1;
	}

	fp = fopen(conf_filename,"w");
	if (fp != NULL)
	{
		fprintf(fp,"#\n");
		fprintf(fp,"# scep_cgi configuration file\n");
		fprintf(fp,"#\n");
		if (ctx->challenge_password) fprintf(fp,"challenge_password=%s;\n",ctx->challenge_password);
		fprintf(fp,"allow_renew_days=%ld;\n",ctx->allow_renew_days);
		fprintf(fp,"validity_days=%ld;\n",ctx->validity_days);
		fprintf(fp,"set_san=%d;\n",configure->set_subject_alternative_name);
		fprintf(fp,"tolerate_exposed_challenge_password=%d;\n",configure->tolerate_exposed_challenge_password);
		fprintf(fp,"no_validate_transaction_id=%d;\n",configure->no_validate_transaction_id);
		fclose(fp);
	}
	else return -1;
	return 0;
}
