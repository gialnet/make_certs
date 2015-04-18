/* ---------------------------------------------------------------------------*
 * file:        webcert.h                                                     *
 * ---------------------------------------------------------------------------*/

#include "openssl/asn1.h"
#include "openssl/bn.h"

/*********** the main URL where the webcert application resides ***************/
#define HOMELINK	"/webcert/"
/*********** the application entry URL which is seen first ********************/
#define REQLINK		"/webcert/cgi-bin/certrequest.cgi"
/*********** where is the ca certificate .pem file ****************************/
#define CACERT 		"/mypool/fs1/antonio/OpenSSL/TetburyCA/ca2013/cacert.pem"
/*********** where is the ca's private key file *******************************/
#define CAKEY           "/mypool/fs1/antonio/OpenSSL/TetburyCA/ca2013/privado/cakey.pem"
/*********** The password for the ca's private key ****************************/
#define PASS            "tetbury2"
/*********** The directory where the generated certificates are stored ********/
#define CACERTSTORE	"/mypool/fs1/antonio/OpenSSL/TetburyCA/ca2013/certificados_myEmpresa"
/*********** The directory to write the exported certificates into ************/
#define CERTEXPORTDIR   "/mypool/fs1/antonio/OpenSSL/TetburyCA/ca2013/export"
/*********** The export directory URL to download the certificates from *******/
#define CERTEXPORTURL   "/mypool/fs1/antonio/OpenSSL/TetburyCA/ca2013/export"
/*********** where the ca's serial file is ************************************/
#define SERIALFILE      "/mypool/fs1/antonio/OpenSSL/TetburyCA/ca2013/serial"
/*********** certificate lifetime *********************************************/
#define DAYS_VALID      1095
#define YEARS_VALID     3


/***************** no changes required below this line ************************/


#define REQLEN		4096 /* Max length of a certificate request in bytes.*/
                             /* Often not bigger then 817 bytes with a 1024  */
			     /* bit RSA key, size increases for bigger keys  */
			     /* and when a lot of attributes are generated.  */

#define KEYLEN          4096 /* this is the max length of a private key in   */
                             /* PEM format used for the PKCS12 cert bundle   */
                             /* generation.                                  */

#define P12PASSLEN      41   /* this is the max length for the password used */
                             /* as protection for the PKCS12 cert bundle.    */

#define MAXCERTDISPLAY	8    /* # of certs that will be shown in one webpage */

#define int_error(msg)  handle_error(__FILE__, __LINE__, msg)

BIGNUM *load_serial(char *serialfile, int create, ASN1_INTEGER **retai);
int save_serial(char *serialfile, char *suffix, BIGNUM *serial, ASN1_INTEGER **retai);

#define EXPIRE_SECS     (60*60*24*DAYS_VALID)

/****************************** end webcert.h *********************************/
