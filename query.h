/*
 * query.h
 *
 *  Created on: 26 juin 2017
 *      Author: slat
 */

#ifndef QUERY_H_
#define QUERY_H_

///////////////////////////////////////////////////
// constantes pour les protocoles BACnet et SNMP //
///////////////////////////////////////////////////
// constantes liées à la variable ucgCfgProtocols
// bits 0 à 1 : configruation BACnet
// bits 2 à 4 : Configuration SNMP (bit 2: ReadOnly / Read-Write, bits 3-4: version SNMP)
// bit 5 :		-- Reserved --
// bit 6 : 		Uplink mode Off(=0)/On(=1)
// bit 7 : 		DHCP Off(=0)/On(=1)
#define cMskProtocoleBACnet			0x03
#define cProtocoleBACnetReadWrite	0x03
#define cProtocoleBACnetReadOnly	0x02
#define cProtocoleBACnetDisabled	0x01
#define cProtocoleBACnetMaxValue	0x03
#define cMskProtocoleSnmp			(0x07<<2)
#define cMskProtocoleSnmpRw			(0x01<<2)
#define cProtocoleSnmpVxReadWrite	(0x00<<2)
#define cProtocoleSnmpVxReadOnly	(0x01<<2)
#define cProtocoleSnmpVersion		(0x06<<2)
#define cProtocoleSnmpV1			(0x00<<2)
#define cProtocoleSnmpV2			(0x02<<2)
#define cProtocoleSnmpV3			(0x04<<2)
#define cProtocoleSnmpV1ReadWrite	(cProtocoleSnmpV1 | cProtocoleSnmpVxReadWrite)
#define cProtocoleSnmpV1ReadOnly	(cProtocoleSnmpV1 | cProtocoleSnmpVxReadOnly)
#define cProtocoleSnmpV2ReadWrite	(cProtocoleSnmpV2 | cProtocoleSnmpVxReadWrite)
#define cProtocoleSnmpV2ReadOnly	(cProtocoleSnmpV2 | cProtocoleSnmpVxReadOnly)
#define cProtocoleSnmpV3ReadWrite	(cProtocoleSnmpV3 | cProtocoleSnmpVxReadWrite)
#define cProtocoleSnmpV3ReadOnly	(cProtocoleSnmpV3 | cProtocoleSnmpVxReadOnly)
#define cProtocoleSnmpMaxValue		0x05

#define cMskProtocoleUpmode			0x40
#define cMskProtocoleDhcp			0x80

#define cDbAddrUsmUser		cDbAddrDataSnmpV3
// taille égale à SNMP_MAX_USER_NAME_LEN=16
#define cDbSizeUsmUser		16
#define cDbSizeAuthPwd		16
#define cDbSizePrivPwd		16
#define cDbSizeAuthAlg		1
#define cDbSizeSnmpV3Alg	2
#define cDbSizePrivAlg		1

struct st_QueryParam{
	char * Name_Param;
	char * Value_Param;
};

/**
 * @brief Access modes
 **/

typedef enum
{
   SNMP_ACCESS_NONE       = 0,
   SNMP_ACCESS_READ_ONLY  = 1,
   SNMP_ACCESS_WRITE_ONLY = 2,
   SNMP_ACCESS_READ_WRITE = 3
} SnmpAccess;


/**
 * SNMP authentication protocols
 **/

typedef enum
{
   SNMP_AUTH_PROTOCOL_NONE   = 0, ///<No authentication
   SNMP_AUTH_PROTOCOL_MD5    = 1, ///<HMAC-MD5-96
   SNMP_AUTH_PROTOCOL_SHA1   = 2, ///<HMAC-SHA-1-96
   SNMP_AUTH_PROTOCOL_SHA224 = 3, ///<HMAC-SHA-224-128
   SNMP_AUTH_PROTOCOL_SHA256 = 4, ///<HMAC-SHA-256-192
   SNMP_AUTH_PROTOCOL_SHA384 = 5, ///<HMAC-SHA-384-256
   SNMP_AUTH_PROTOCOL_SHA512 = 6  ///<HMAC-SHA-512-384
} SnmpAuthProtocol;


/**
 * SNMP privacy protocols
 **/

typedef enum
{
   SNMP_PRIV_PROTOCOL_NONE = 0, ///<No privacy
   SNMP_PRIV_PROTOCOL_DES  = 1, ///<DES-CBC
   SNMP_PRIV_PROTOCOL_AES  = 2  ///<AES-128-CFB
} SnmpPrivProtocol;

char Query_Cut(char * query_from, unsigned short length_Buffer);
char Value_Query(char * Param_Name, char * Param_Value);
unsigned char hex2dec(unsigned char ucHex);
void unescape(char * pFormIn);
unsigned char TraduceSNMP(char * pucParam, char * version_snmp,
		         char * USMuser, char * AthAlgorithm,
				 char * AuthPassword, char * PrivacyAlgorithm,
				 char * PrivacyPassword);
unsigned char TraduceBACNET(char * pucParam, char * version_bacnet);
#endif /* QUERY_H_ */
