#ifndef DEFINITIONS_H
#define DEFINITIONS_H

#define BLOCK_SIZE 512
#define TAR_NAME_LENGTH 100

#define TAR_MAGIC "ustar"
#define TAR_VERSION "00"

#define REGTYPE  '0'

#define DELETE_SUCCESS "False"

//Modes
#define TSUID    04000          /* set UID on execution */
#define TSGID    02000          /* set GID on execution */
#define TSVTX    01000          /* reserved */
                                /* file permissions */
#define TUREAD   00400          /* read by owner */
#define TUWRITE  00200          /* write by owner */
#define TUEXEC   00100          /* execute/search by owner */
#define TGREAD   00040          /* read by group */
#define TGWRITE  00020          /* write by group */
#define TGEXEC   00010          /* execute/search by group */
#define TOREAD   00004          /* read by other */
#define TOWRITE  00002          /* write by other */
#define TOEXEC   00001          /* execute/search by other */

#endif