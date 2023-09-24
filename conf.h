/*
 * conf.h
 *
 *  Created on: 19 sept. 2023
 *      Author: gege
 */

#ifndef CONF_H_
#define CONF_H_

void conf_init(struct scep_configure * configure, struct context *ctx);
int32_t conf_read_file(char * conf_filename, struct scep_configure * configure, struct context *ctx);
int32_t conf_save_file(char * conf_filename, struct scep_configure * configure, struct context *ctx);

#endif /* CONF_H_ */
