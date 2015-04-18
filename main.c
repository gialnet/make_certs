
/*
 
 * Rutina generadora de los certificados de las bases de datos.
 * Se va a disponer de un certificado para cada base de datos PostgreSQL 9.3
 * exitente en la nube bajo el dominio myEmpresa.eu compuesto por servidores
 * con sistema operativo Unix System V SmartOS. 

 * Se mantine uan relación constante de cantidad de memoria RAM por usuario
 * con su valor de 34.13 MegaBytes por usuario. Este valor será menor a este 
 * máximo teorico ya que el propio sistema necesita también sus propios recursos
 * más los del motor de la JVM jdk 7 el servidor de aplicaciones Glassfish v4 y 
 * el PostgreSQL v 9.3
 * Si lo dejamos con un 50% estaríamos cerca de 17 MegaBytes de RAM por usuario.
 * 
 * Con estos números doto con un 1GB de almacenamiento por usuario, por lo 
 * tanto arrancamos con 30 usuarios y vamos saltando en la siguiente secuencia:
 * inicio con 30, 15, 15, 60, 120 = 240 usuarios.
 
 */

#include <stdio.h>
#include <string.h>
#include "webcert.h"
#include <openssl/ossl_typ.h>
BIGNUM *bserial;

int certexport (char certfilestr[]);
int certsign (void);
int genrequest(char department[], char cname0[]);

void getNextNumber()
{   
    
    /* -------------------------------------------------------------------------- *
     * leer el número de serie del valor indicado en SERIALFILE webcert.h         *
     * ---------------------------------------------------------------------------*/

   if (! (bserial = load_serial(SERIALFILE, 1, NULL)))
      printf("Error getting serial # from serial file");

    /* -------------------------------------------------------------------------- *
     * incrementar el número de serie                                             *
     * ---------------------------------------------------------------------------*/

   if (! (BN_add_word(bserial,1)))
      printf("Error incrementing serial number");
    
}

/*
 
 * Como parametros de entrada cname0[81] y el número de certificados
 
 */

int main (int argc, char ** argv)
{
    
    int numCert = 1;
    char department[81]="myEmpresa";
    char cname0[81]="cdp001.myEmpresa.eu"; // es mejor un nombre DNS que una IP, ya que podemos cambiar de proveedor de servicio
                                           // o en caso de caida de una máquina y el proveedor nos cambia la IP
    char certfilestr[81];
    
    
    
    // bucle para hacer un número determinado de certificados
    
    for (int i=0; i <= numCert; i++)
    {
        
        
    // Leer el próximo número de serie es un número en hexadecimal
    getNextNumber();
    snprintf(department, sizeof(department), "myEmpresa%s", BN_bn2hex(bserial));
    printf("Departamento-PoolConn: %s\n",department);
    
    // vamos a usar este campo para relacionarlo con el Pool de conexiones
    // de Glassfish v4 ejemplo jdbc/myEmpresa-001 relacionando una base con
    // un certificado.
    
    
    //
    // generar las claves clave_publica.pem y clave_privada.pem
    //
    if ( genrequest(department, cname0) !=0 )
        return -1;
    
    // firmar la petición de certificado con el certificado de la CA
    // se incrementa el contador de número de certificado fichero serial
    // con este número se crea el nombre del archivo de salida
    // ejemplo: /mypool/fs1/antonio/OpenSSL/TetburyCA/ca2013/certificados_myEmpresa/33.pem
    //
    if (certsign() != 0)
        return -2;
    
    // exportar a formato p12:
    // el certificado, la clave privada y la cadena de certificados raiz de la CA
    // crea el archivo /mypool/fs1/antonio/OpenSSL/TetburyCA/ca2013/export/33.p12

    snprintf(certfilestr, sizeof(certfilestr), "%s.pem", BN_bn2hex(bserial));
    
    printf("Certificado: %s\n",certfilestr);
    
    certexport(certfilestr);
    
    }
    
}
