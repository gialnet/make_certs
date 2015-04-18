/* -------------------------------------------------------------------------- *
 * file:         certexport.c                                                 *
 * purpose:      provides a download link to the certificate. It loads the    *
 *               certificate from the CA cert store and writes a copy to the  *
 *               web export directory, converting the certificate format if   *
 *               necessary. In the case of PKCS12, it requests the private    *
 *               key along with a passphrase for protection.                  *
 * hint:         call it with ?cfilename=<xxx.pem>&format=[pem|der|p12]       *
 * -------------------------------------------------------------------------- */

// gcc -o cert_export cert_export.c -lcrypto

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include "webcert.h"

int certexport (char certfilestr[]) 
{

   char			format[4]           = "p12";
   X509			*cert               = NULL;
   X509			*cacert             = NULL;
   STACK_OF(X509)	*cacertstack        = NULL;
   PKCS12		*pkcs12bundle       = NULL;
   EVP_PKEY		*cert_privkey       = NULL;
   BIO			*inbio              = NULL;
   BIO			*outbio             = NULL;
   char 		certfilepath[255]   = "";
   char 		certnamestr[81]     = "";
   //char 		certfilestr[81]     = "32.pem";
   FILE 		*cacertfile         = NULL;
   FILE 		*certfile           = NULL;
   char 		exportfilestr[81]   = "[n/a]";
   FILE 		*exportfile         = NULL;
   int			bytes               = 0;
   char 		title[41]           = "Download Certificate";
   char                 beginline[81]       = "";
   char                 endline[81]         = "";
   char 		privkeystr[KEYLEN]  = "";
   char 		privkeytst[KEYLEN]  = "";
   char			p12pass[P12PASSLEN] = "reto";
   char			cainc[4]            = "yes";
   FILE                         *fp;

/* -------------------------------------------------------------------------- *
 * strip off the file format extension from the file name                     *
 * ---------------------------------------------------------------------------*/

   strncpy(certnamestr, certfilestr, sizeof(certnamestr));
   strtok(certnamestr, ".");
   printf("nombre amigable del certificado: %s\n",certnamestr);

/* -------------------------------------------------------------------------- *
 * create the export file name and check if the format was already exported   *
 * ---------------------------------------------------------------------------*/

   snprintf(exportfilestr, sizeof(exportfilestr), "%s/%s.%s",
                           CERTEXPORTDIR, certnamestr, format);

   if (access(exportfilestr, R_OK) == 0) {
      return(0);
   }

/* -------------------------------------------------------------------------- *
 * These function calls are essential to make many PEM + other openssl        *
 * functions work.                                                            *
 * -------------------------------------------------------------------------- */
   OpenSSL_add_all_algorithms();
   ERR_load_crypto_strings();

/* -------------------------------------------------------------------------- *
 * read the certstore certificate and define a BIO output stream              *
 * ---------------------------------------------------------------------------*/

   if (strcmp(certfilestr, "cacert.pem") == 0) 
      snprintf(certfilepath, sizeof(certfilepath), "%s", CACERT);
   else
      snprintf(certfilepath, sizeof(certfilepath), "%s/%s", CACERTSTORE,
                                                                certfilestr);
   if (! (certfile = fopen(certfilepath, "r")))
      printf("Error cant read cert store certificate file");

   if (! (cert = PEM_read_X509(certfile,NULL,NULL,NULL)))
      printf("Error loading cert into memory");

   outbio = BIO_new(BIO_s_file());

/* -------------------------------------------------------------------------- *
 *  write the certificate in the specified export format to the wbcert export *
 *  directory, named after its serial number.                                 *
 * ---------------------------------------------------------------------------*/
   
   if (strcmp(format, "p12") == 0) {
     if (strcmp(certfilestr, "cacert.pem") == 0) 
        printf("Error CA certificate can't be converted to PKCS12.");

     /* initialize the structures */
     if ((pkcs12bundle = PKCS12_new()) == NULL)
        printf("Error creating PKCS12 structure.");
     
     if ((cert_privkey = EVP_PKEY_new()) == NULL)
        printf("Error creating EVP_PKEY structure.");
     
     if ((cacertstack = sk_X509_new_null()) == NULL)
        printf("Error creating STACK_OF(X509) structure.");

     /* ----------------------------------------- *
      * Cargar la clave privada en privkeystr     *
      * ----------------------------------------- */
      
    if (! (fp = fopen ("clave_privada.pem", "r")))
       printf("Error al leer el fichero de la clave privada");

    if (! (cert_privkey = PEM_read_PrivateKey( fp, NULL, NULL, PASS)) )
       printf("Error importando el contenido de la clave desde el archivo");

    fclose(fp);
     
    // incluir la cadena de certificados raiz
    
     if (strcmp(cainc, "yes") == 0) {
         
        /* leer el certificado de la CA*/
        if (! (cacertfile = fopen(CACERT, "r")))
           printf("Error can't open CA certificate file\n");
        
        if (! (cacert = PEM_read_X509(cacertfile,NULL,NULL,NULL)))
           printf("Error loading CA certificate into memory\n");
        
        fclose(cacertfile);
        sk_X509_push(cacertstack, cacert);
     }

     /* values of zero use the openssl default values */
     pkcs12bundle = PKCS12_create( p12pass,     // certbundle access password
                                   certnamestr, // friendly certname
                                   cert_privkey,// the certificate private key
                                   cert,        // the main certificate
                                   cacertstack, // stack of CA cert chain
                                   0,           // int nid_key (default 3DES)
                                   0,           // int nid_cert (40bitRC2)
                                   0,           // int iter (default 2048)
                                   0,           // int mac_iter (default 1)
                                   0            // int keytype (default no flag)
                                 );
     if ( pkcs12bundle == NULL)
        printf("Error generating a valid PKCS12 certificate.\n");

     if (! (exportfile=fopen(exportfilestr, "w")))
        printf("Error open PKCS12 certificate file bundle for writing.\n");
     
     bytes = i2d_PKCS12_fp(exportfile, pkcs12bundle);
     
     if (bytes <= 0)
        printf("Error writing PKCS12 certificate to export directory.\n");

     fclose(exportfile);
     sk_X509_free(cacertstack);
     PKCS12_free(pkcs12bundle);
   }
   BIO_free(outbio);

   return(0);
}
