/* -------------------------------------------------------------------------- *
 * file:	certsign.cgi                                                  *
 * purpose:	sign the certificate request                                  *
 * ---------------------------------------------------------------------------*/

// gcc -o certsign serial.c certsign.c -lcrypto
// -lm -lssl -lcrypto
// serial.c certsign.c


#include <stdio.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "webcert.h"

int certsign () {

   BIGNUM			*bserial;
   ASN1_INTEGER			*aserial = NULL;
   EVP_PKEY                     *ca_privkey, *req_pubkey;
   EVP_MD                       const *digest = NULL;
   X509                         *newcert, *cacert;
   X509_REQ                     *certreq;
   X509_NAME                    *name;
   X509V3_CTX                   ctx;
   FILE                         *fp;
   BIO                          *inbio, *outbio, *savbio;
   static char			title[]         = "Signed Certificate";
   char 			formreq[REQLEN] = "";
   char 			reqtest[REQLEN] = "";
   char				beginline[81]   = "";
   char				endline[81]     = "";
   char				certfile[81]    = "";
   char				email_head[255] = "email:";
   char				email_name[248] = "";
   char				certfilestr[255]= "";
   char				validdaystr[255]= "";
   char				*typelist[] = { "sv","cl","em","os","ca" };
   int				type_res = 1; // cambiado
   char				extkeytype[81]  = "tlscl";
   long				valid_days = 0;
   long				valid_secs = 0;

/* -------------------------------------------------------------------------- *
 * These function calls are essential to make many PEM + other openssl        *
 * functions work. It is not well documented, I found out after looking into  *
 * the openssl source directly.                                               *
 * needed by: PEM_read_PrivateKey(), X509_REQ_verify() ...                    *
 * -------------------------------------------------------------------------- */
   OpenSSL_add_all_algorithms();
   ERR_load_crypto_strings();


   valid_days = 3650;

/* -------------------------------------------------------------------------- *
 * What happens if a very large value is given as the expiration date?        *
 * The date rolls over to the old century (1900) and the expiration date      *
 * becomes invalid. We do a check here to prevent that.                       *
 * The max is 11663 days on Feb 12, 2006 and points to Jan 18th, 2038         *
 * The value is stored in type long, but somewhere lower the stuff fails      *
 * if valid_secs is bigger then 1007683200 (i.e. 1007769600). ca 32 years.    *
 * -------------------------------------------------------------------------- */
   if (valid_days > 11663)
      printf("Error expiration date set to far in the future.");
   
   valid_secs = valid_days*60*60*24;
 

   
  if ( !(fp = fopen ("clave_publica.pem", "r") ) )
    printf("Error reading request file");

   
  if (!(certreq = PEM_read_X509_REQ (fp, NULL, NULL, NULL)))
    printf ("Error reading request in file");

  fclose (fp);


/* -------------------------------------------------------------------------- *
 * Certificate request public key verification                                * 
 * ---------------------------------------------------------------------------*/

   req_pubkey = EVP_PKEY_new();
   if ( (certreq->req_info == NULL) ||
        (certreq->req_info->pubkey == NULL) ||
        (certreq->req_info->pubkey->public_key == NULL) ||
        (certreq->req_info->pubkey->public_key->data == NULL))
        {
           printf("Error missing public key in request");
        }
   
   if (! (req_pubkey=X509_REQ_get_pubkey(certreq)))
           printf("Error unpacking public key from request");
   
   if (X509_REQ_verify(certreq,req_pubkey) != 1)
      printf("Error verifying signature on request");

/* -------------------------------------------------------------------------- *
 * Load CA Certificate from file for signer info                              *
 * ---------------------------------------------------------------------------*/

   if (! (fp=fopen(CACERT, "r")))
      printf("Error reading CA cert file");
   
   if(! (cacert = PEM_read_X509(fp,NULL,NULL,NULL)))
      printf("Error loading CA cert into memory");
   
   fclose(fp);

/* -------------------------------------------------------------------------- *
 * Import CA private key for signing                                          *
 * ---------------------------------------------------------------------------*/

   ca_privkey = EVP_PKEY_new();
   
   if (! (fp = fopen (CAKEY, "r")))
      printf("Error reading CA private key file");
   
   if (! (ca_privkey = PEM_read_PrivateKey( fp, NULL, NULL, PASS)))
      printf("Error importing key content from file");
   
   fclose(fp);

/* -------------------------------------------------------------------------- *
 * Build Certificate with data from request                                   *
 * ---------------------------------------------------------------------------*/

   if (! (newcert=X509_new()))
      printf("Error creating new X509 object");

   if (X509_set_version(newcert, 2L) != 1)
      printf("Error setting certificate version");

/* -------------------------------------------------------------------------- *
 * load the serial number from SERIALFILE                                     *
 * ---------------------------------------------------------------------------*/

   if (! (bserial = load_serial(SERIALFILE, 1, NULL)))
      printf("Error getting serial # from serial file");

/* -------------------------------------------------------------------------- *
 * increment the serial number                                                *
 * ---------------------------------------------------------------------------*/

   if (! (BN_add_word(bserial,1)))
      printf("Error incrementing serial number"); 

/* -------------------------------------------------------------------------- *
 * save the serial number back to SERIALFILE                                  *
 * ---------------------------------------------------------------------------*/

   if ( save_serial(SERIALFILE, 0, bserial, &aserial) == 0 )
      printf("Error writing serial number to file");

/* -------------------------------------------------------------------------- *
 * set the certificate serial number here                                     *
 * ---------------------------------------------------------------------------*/

   if (! X509_set_serialNumber(newcert, aserial))
      printf("Error setting serial number of the certificate");

   if (! (name = X509_REQ_get_subject_name(certreq)))
      printf("Error getting subject from cert request");
   if (X509_set_subject_name(newcert, name) != 1)
   if (! (name = X509_REQ_get_subject_name(certreq)))
      printf("Error getting subject from cert request");
   if (X509_set_subject_name(newcert, name) != 1)
      printf("Error setting subject name of certificate");
   if (! (name = X509_get_subject_name(cacert)))
      printf("Error getting subject from CA certificate");
   if (X509_set_issuer_name(newcert, name) != 1)
      printf("Error setting issuer name of certificate");

   if (X509_set_pubkey(newcert, req_pubkey) != 1)
      printf("Error setting public key of certificate");
   EVP_PKEY_free(req_pubkey);

/* -------------------------------------------------------------------------- *
 * Set X509V3 start date and expiration date here                             *
 * ---------------------------------------------------------------------------*/

   if (! (X509_gmtime_adj(X509_get_notBefore(newcert),0)))
      printf("Error setting beginning time of certificate");

   if(! (X509_gmtime_adj(X509_get_notAfter(newcert), valid_secs)))
      printf("Error setting expiration time of certificate");

/* -------------------------------------------------------------------------- *
 * Add X509V3 extensions                                                      *
 * ---------------------------------------------------------------------------*/

   X509V3_set_ctx(&ctx, cacert, newcert, NULL, NULL, 0);
   X509_EXTENSION *ext;

   /* Unless we sign a CA cert, always add the CA:FALSE constraint */
   if (strcmp(typelist[type_res], "ca") != 0) {
      if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                                  "basicConstraints", "critical,CA:FALSE"))) {
         printf("Error creating X509 extension object");
      }
   if (! X509_add_ext(newcert, ext, -1))
      printf("Error adding X509 extension to certificate");
   X509_EXTENSION_free(ext);
   } else {
      if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                                  "basicConstraints", "critical,CA:TRUE"))) {
         printf("Error creating X509 extension object");
      }
   if (! X509_add_ext(newcert, ext, -1))
      printf("Error adding X509 extension to certificate");
   X509_EXTENSION_free(ext);
   }

   /* If we sign a server cert, add the nsComment extension */
   if (strcmp(typelist[type_res], "sv") == 0) {
      if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                     "nsComment", "SSL enabling server cert")))
         printf("Error creating X509 extension object");
   if (! X509_add_ext(newcert, ext, -1))
      printf("Error adding X509 extension to certificate");
   X509_EXTENSION_free(ext);
   }

   if (strcmp(typelist[type_res], "sv") == 0) {
      if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                     "keyUsage", "digitalSignature,keyEncipherment"))) {
         printf("Error creating X509 keyUsage extension object");
      }

     if (! X509_add_ext(newcert, ext, -1))
        printf("Error adding X509 extension to certificate");
     X509_EXTENSION_free(ext);
   }

   if (strcmp(typelist[type_res], "cl") == 0) {
      if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                     "keyUsage", "digitalSignature"))) {
         printf("Error creating X509 keyUsage extension object");
      }
     if (! X509_add_ext(newcert, ext, -1))
        printf("Error adding X509 extension to certificate");
     X509_EXTENSION_free(ext);
   }

   if (strcmp(typelist[type_res], "em") == 0) {
      if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                     "keyUsage", "digitalSignature,keyEncipherment"))) {
         printf("Error creating X509 keyUsage extension object");
      }
     if (! X509_add_ext(newcert, ext, -1))
        printf("Error adding X509 extension to certificate");
     X509_EXTENSION_free(ext);
   }

   if (strcmp(typelist[type_res], "os") == 0) {
      if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                     "keyUsage", "digitalSignature"))) {
         printf("Error creating X509 keyUsage extension object");
      }
     if (! X509_add_ext(newcert, ext, -1))
        printf("Error adding X509 extension to certificate");
     X509_EXTENSION_free(ext);
   }

   if (strcmp(typelist[type_res], "ca") == 0) {
      if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                     "keyUsage", "keyCertSign,cRLSign"))) {
         printf("Error creating X509 keyUsage extension object");
      }
     if (! X509_add_ext(newcert, ext, -1))
        printf("Error adding X509 extension to certificate");
     X509_EXTENSION_free(ext);
   }

   if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                  "subjectKeyIdentifier", "hash"))) {
       printf("Error creating X509 subjectKeyIdentifier extension object");
   }
   if (! X509_add_ext(newcert, ext, -1))
      printf("Error adding X509 extension to certificate");
   X509_EXTENSION_free(ext);

   if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                  "authorityKeyIdentifier", "keyid, issuer:always"))) {
      printf("Error creating X509 authorityKeyIdentifier extension object");
   }
   if (! X509_add_ext(newcert, ext, -1))
      printf("Error adding X509 extension to certificate");
   X509_EXTENSION_free(ext);

  
 
     if (strcmp(extkeytype, "tlsws") == 0) {
       if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                      "extendedKeyUsage", "serverAuth"))) {
          printf("Error creating X509 keyUsage extension object");
       }
     }
     if (strcmp(extkeytype, "tlscl") == 0) {
       if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                      "extendedKeyUsage", "clientAuth"))) {
          printf("Error creating X509 keyUsage extension object");
       }
     }
     if (strcmp(extkeytype, "cs") == 0) {
       if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                      "extendedKeyUsage", "codeSigning"))) {
          printf("Error creating X509 keyUsage extension object");
       }
     }
     if (strcmp(extkeytype, "ep") == 0) {
       if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                      "extendedKeyUsage", "emailProtection"))) {
          printf("Error creating X509 keyUsage extension object");
       }
     }
     if (strcmp(extkeytype, "ts") == 0) {
       if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                      "extendedKeyUsage", "timeStamping"))) {
          printf("Error creating X509 keyUsage extension object");
       }
     }
     if (strcmp(extkeytype, "ocsp") == 0) {
       if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                      "extendedKeyUsage", "OCSPSigning"))) {
          printf("Error creating X509 keyUsage extension object");
       }
     }
     if (! X509_add_ext(newcert, ext, -1))
         printf("Error adding X509 extension to certificate");
     X509_EXTENSION_free(ext);


/* -------------------------------------------------------------------------- *
 * Firmar el nuevo certificado con la clave privada de la CA                  *
 * ---------------------------------------------------------------------------*/

   if (EVP_PKEY_type(ca_privkey->type) == EVP_PKEY_DSA)
      digest = EVP_dss1();
   else if (EVP_PKEY_type(ca_privkey->type) == EVP_PKEY_RSA)
      digest = EVP_sha1();
   else
      printf("Error checking CA private key for valid digest");
   if (! X509_sign(newcert, ca_privkey, digest))
      printf("Error signing the new certificate");
   
/* -------------------------------------------------------------------------- *
 *  write a certificate backup to local disk, named after its serial number   *
 * ---------------------------------------------------------------------------*/

   snprintf(certfilestr, sizeof(certfilestr), "%s/%s.pem", CACERTSTORE,
                                                          BN_bn2hex(bserial));
   if (! (fp=fopen(certfilestr, "w")))
     fprintf(stdout, "Error al abrir el fichero %s para escribir.\n", certfilestr);
   else {
       
     savbio = BIO_new(BIO_s_file());
     BIO_set_fp(savbio, fp, BIO_NOCLOSE);
     if (! PEM_write_bio_X509(savbio, newcert))
        fprintf(stdout, "Error escribiendo fixhero del certificado firmado %s.\n", certfilestr);
     
   BIO_free(savbio);
   
   fclose(fp);
   }

   BIO_free(inbio);
   return(0);
}
