/*
 * query.c
 *
 *  Created on: 26 juin 2017
 *      Author: slat
 *  Cette unite contient les fonctions de gestion des paramètres envoyé par les pages Web
 */
#include "string.h"
#include "query.h"
#include "stdio.h"

struct st_QueryParam para_query[500];
char Nb_Q;
/**
 * @fn char Query_Cut(char * query_from)
 * @brief Cette fonction découpe la requete en tableau de pointeur sur les paramètres de la requéte
 * @param char * query_from pointeur sur la requete
 * @retval Nombre de paramètres trouvé dans la requéte
 */
char Query_Cut(char * query_from, unsigned short length_Buffer)
{
	unsigned char Nb_Requette = 0;
	unsigned short i = 0;
	char * p;
	//debug
	//FILE *fp_Data = NULL;
	//debug

	p = query_from;

	while (i < length_Buffer)
	{
		if ((*p) == 0)
		{
			i = length_Buffer;
			break;
		}
		if (Nb_Requette == 0)
		{
			// Le premier caractére correspond au premier nom de parametre
			para_query[Nb_Requette].Name_Param = p;
			Nb_Requette++;
		}
		else
		{
			// après le nom de paramètre, on cherche la valeur
			if ((*p) == '=')
			{
				para_query[Nb_Requette - 1].Value_Param = p+1;
				*p = 0;
			}
			if ((*p) == '&')
			{
				*p = 0;
				para_query[Nb_Requette].Name_Param = p+1;
				Nb_Requette++;
			}
		}
		p++;
		i++; // surveillance de la taille du buffer;
	}
	Nb_Q = Nb_Requette;

//	fp_Data = fopen("/usr/slat_debug/debug_query.txt","w"); // On ouvre le fichier en ecriture
//	if (fp_Data != NULL)
//	{
//		fprintf(fp_Data,"Requette=%s\n",query_from);
//		fprintf(fp_Data,"Nombre de parametres=%d\n",Nb_Q);
//		i = 0;
//		while (i< Nb_Q)
//		{
//			fprintf(fp_Data,"Parametre %d = %s - Valeur = %s\n",i,para_query[i].Name_Param,para_query[i].Value_Param);
//			i++;
//		}
//		fclose(fp_Data);
//	}
	return Nb_Requette;
}

/**
 * @fn char Value_Query(char * Param_Name, char * Param_Value)
 * @brief Retourne dans le pointeur Param_Value la valeur du paramètre indiqué par Param_Name
 * @param Param_Name : char * pointeur sur le nom du paramètre à lire
 * @retval char : retourne 1 si OK et 0 si pas OK
 */
char Value_Query(char * Param_Name, char * Param_Value)
{
	unsigned char err = 0;
	unsigned char i = 0;
	while (i< Nb_Q)
	{
		if (strcmp(Param_Name,para_query[i].Name_Param) == 0)
		{
			// On a trouvé le paramètre, on copie dans Param_Value
			strcpy(Param_Value,para_query[i].Value_Param);
			err = 1;
		}
		i++;
	}

	return err;
}

/**
 * @fn unsigned char hex2dec(unsigned char ucHex)
 * @brief convertit un caractere hexadécimal en caractère décimal
 * @param
 * @retval
 */
unsigned char hex2dec(unsigned char ucHex)
{
	if (ucHex <= '9')
	{
		return (ucHex - '0');
	}
	return ((ucHex & ~0x20) - 'A' +10);
}
/**
 * @fn void unescape(char * pFormIn)
 * @brief Cette fonction convertie une chaine envoyé par le site en chaine normale
 * @param char * pFormIn : pointeur vers la chaine à traduire
 * @retval none
 */
void unescape(char * pFormIn)
{
	char * pFormOut;
	unsigned char ucCharAscii;

	if (pFormIn)
	{
		pFormOut = pFormIn;
		do
		{
			switch (*pFormIn)
			{
			case '+' :
				pFormIn++;
				*pFormOut=' ';
				break;
			case '%' :
				pFormIn++;
				ucCharAscii = hex2dec(*pFormIn++) << 4;
				*pFormOut = ucCharAscii | hex2dec(*pFormIn++);
				break;
			default:
				*pFormOut = *pFormIn++;
				break;

			}
		}
		while (*pFormOut++);
	}
}
