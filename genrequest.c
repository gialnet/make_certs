/* -------------------------------------------------------------------------- *
 * file:	genrequest.cgi                                                *
 * purpose:	takes the input from buildrequest.cgi and generates request   *
 *              and public/private key pair                                   *

Crea la clave privada, publica, y genera un crs


 * ---------------------------------------------------------------------------*/

// gcc -o genrequest genrequest.c -lcrypto
// -lm -lssl -lcrypto


#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include "webcert.h"


int genrequest(char department[], char cname0[]) {

   X509_REQ 	*webrequest 	 = NULL;
   EVP_PKEY	*pubkey		 = NULL;
   X509_NAME 	*reqname	 = NULL;
   DSA 		*mydsa		 = NULL;
   RSA 		*myrsa		 = NULL;
   BIO 		*outbio		 = NULL;
   X509_NAME_ENTRY      *e;
   int                  i;
   FILE                         *fp, *fp2;

   char         buf[80]		 = "";
   char         country[81]      = "UK";
   char         province[81]     = "Gloucestershire";
   char         locality[81]     = "Tetbury";
   char         organisation[81] = "TETBURY SOFTWARE SERVICES Ltd";
   //char         department[81]   = "myEmpresa-001";
   char 	email_addr[81]   = "secure@retburyss.co.uk";
   //char 	cname0[81]       = "81.45.18.210";
   char 	cname1[81]       = "";
   char 	cname2[81]       = "";
   char 	surname[81]      = "";
   char 	givenname[81]    = "";

   char 	keytype[81]      = "rsa";
   int	 	rsastrength	 = 4096;
   int	 	dsastrength	 = 0;


/* we do not accept requests with no data, i.e. being empty with just a 
   public key. Although technically possible to sign and create a cert,
   they don't make much sense. We require here at least one CN supplied.    */

   if(strlen(cname0) == 0 && strlen(cname1) == 0 && strlen(cname2) == 0)
     printf("Error supply at least one CNAME in request subject");

/* -------------------------------------------------------------------------- *
 * These function calls are essential to make many PEM + other openssl        *
 * functions work. It is not well documented, I found out after looking into  *
 * the openssl source directly.                                               *
 * needed by: PEM_read_PrivateKey(), X509_REQ_verify() ...                    *
 * -------------------------------------------------------------------------- */
   OpenSSL_add_all_algorithms();
   ERR_load_crypto_strings();

/* ------------------------------------------------------------------------- *
 * Generate the key pair based on the selected keytype                       *
 * ------------------------------------------------------------------------- */

   if ((pubkey=EVP_PKEY_new()) == NULL)
      printf("Error creating EVP_PKEY structure.");

   if(strcmp(keytype, "rsa") == 0) {

      myrsa = RSA_new();
      if (! (myrsa = RSA_generate_key(rsastrength, RSA_F4, NULL, NULL)))
         printf("Error generating the RSA key.");

      if (!EVP_PKEY_assign_RSA(pubkey,myrsa))
         printf("Error assigning RSA key to EVP_PKEY structure.");
   }
   else if(strcmp(keytype, "dsa") == 0) {

      mydsa = DSA_new();
      mydsa = DSA_generate_parameters(dsastrength, NULL, 0, NULL, NULL,
                                                                  NULL, NULL);
      if (! (DSA_generate_key(mydsa)))
         printf("Error generating the DSA key.");

      if (!EVP_PKEY_assign_DSA(pubkey,mydsa))
         printf("Error assigning DSA key to EVP_PKEY structure.");
   }
   else
      printf("Error: Wrong keytype - choose either RSA or DSA.");

/* ------------------------------------------------------------------------- *
 * Generate the certificate request from scratch                             *
 * ------------------------------------------------------------------------- */

   if ((webrequest=X509_REQ_new()) == NULL)
      printf("Error creating new X509_REQ structure.");

   if (X509_REQ_set_pubkey(webrequest, pubkey) == 0)
      printf("Error setting public key for X509_REQ structure.");

   if ((reqname=X509_REQ_get_subject_name(webrequest)) == NULL)
      printf("Error setting public key for X509_REQ structure.");

   /* The following functions create and add the entries, working out  *
    * the correct string type and performing checks on its length.     *
    * We also check the return value for errors...                     */

   if(strlen(country) != 0)
      X509_NAME_add_entry_by_txt(reqname,"C", MBSTRING_ASC, 
                           (unsigned char*) country, -1, -1, 0);
   if(strlen(province) != 0)
      X509_NAME_add_entry_by_txt(reqname,"ST", MBSTRING_ASC,
                           (unsigned char *) province, -1, -1, 0);
   if(strlen(locality) != 0)
      X509_NAME_add_entry_by_txt(reqname,"L", MBSTRING_ASC,
                          (unsigned char *) locality, -1, -1, 0);
   if(strlen(organisation) != 0)
      X509_NAME_add_entry_by_txt(reqname,"O", MBSTRING_ASC,
                      (unsigned char *) organisation, -1, -1, 0);
   if(strlen(department) != 0)
      X509_NAME_add_entry_by_txt(reqname,"OU", MBSTRING_ASC,
                         (unsigned char *) department, -1, -1, 0);
   if(strlen(email_addr) != 0)
      X509_NAME_add_entry_by_txt(reqname,"emailAddress", MBSTRING_ASC,
			(unsigned char *)  email_addr, -1, -1, 0);
   if(strlen(cname0) != 0)
      X509_NAME_add_entry_by_txt(reqname,"CN", MBSTRING_ASC,
                                   (unsigned char *) cname0, -1, -1, 0);
   if(strlen(cname1) != 0)
      X509_NAME_add_entry_by_txt(reqname,"CN", MBSTRING_ASC,
                                   (unsigned char *) cname1, -1, -1, 0);
   if(strlen(cname2) != 0)
      X509_NAME_add_entry_by_txt(reqname,"CN", MBSTRING_ASC,
                                   (unsigned char *) cname2, -1, -1, 0);
   if(strlen(surname) != 0)
      X509_NAME_add_entry_by_txt(reqname,"SN", MBSTRING_ASC,
                                   (unsigned char *) surname, -1, -1, 0);
   if(strlen(givenname) != 0)
      X509_NAME_add_entry_by_txt(reqname,"GN", MBSTRING_ASC,
                                 (unsigned char *) givenname, -1, -1, 0);

/* ------------------------------------------------------------------------- *
 * Sign the certificate request: md5 for RSA keys, dss for DSA keys          *
 * ------------------------------------------------------------------------- */

   if(strcmp(keytype, "rsa") == 0) {
      if (!X509_REQ_sign(webrequest,pubkey,EVP_md5()))
         printf("Error MD5 signing X509_REQ structure.");
   }
   else if(strcmp(keytype, "dsa") == 0) {
      if (!X509_REQ_sign(webrequest,pubkey,EVP_dss()))
         printf("Error DSS signing X509_REQ structure.");
   }

/* ------------------------------------------------------------------------- *
 *  and sort out the content plus start the html output                      *
 * ------------------------------------------------------------------------- */

   if (! (fp=fopen("clave_publica.pem", "w")))
        printf("No puedo crear el fichero de la request");

   if (! (fp2=fopen("clave_privada.pem", "w")))
        printf("No puedo crear el fichero de la clave privada");

   outbio = BIO_new(BIO_s_file());
   BIO_set_fp(outbio, fp, BIO_NOCLOSE);

   if (! PEM_write_bio_X509_REQ(outbio, webrequest))
      printf("Error printing the request");

   for (i = 0; i < X509_NAME_entry_count(reqname); i++) {
      e = X509_NAME_get_entry(reqname, i);
      OBJ_obj2txt(buf, 80, e->object, 0);
   }

   PEM_write_PrivateKey(fp2,pubkey,NULL,NULL,0,0,NULL);


   BIO_free(outbio);
   fclose(fp);
   fclose(fp2);
   return(0);
}
