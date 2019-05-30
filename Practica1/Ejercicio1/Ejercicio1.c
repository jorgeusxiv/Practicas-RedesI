/***************************************************************************
################################################################################
# Autores: Jose Benjumeda Rubio, Jorge Santisteban Rivas
# Grupo 1301 Pareja 09
#
################################################################################
***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#define ERROR 1
#define OK 0

#define ETH_FRAME_MAX 1514	// Tamano maximo trama ethernet

pcap_t *descr=NULL,*descr2=NULL;
pcap_dumper_t *pdumper=NULL;
int N = 0 ,contador=0;

void handle(int nsignal){
	printf("Control C pulsado\n");
	printf("Numero de elementos capturados: %d \n", contador);
	if(descr)
		pcap_close(descr);
	if(descr2)
		pcap_close(descr2);
	if(pdumper)
		pcap_dump_close(pdumper);
	exit(OK);
 }

void fa_nuevo_paquete(uint8_t *usuario, const struct pcap_pkthdr* cabecera, const uint8_t* paquete){

	int* num_paquete=(int *)usuario;
	int i;

	//Creamos una cabecera copia para modificar el tiempo

	struct pcap_pkthdr *cabecera_modificada;

	(*num_paquete)++;

	printf("Nuevo paquete capturado a las %s\n",ctime((const time_t*)&(cabecera->ts.tv_sec)));

	//Tenemos que imprimir los N primeros bits de cada paquete en haxadecimal

	for(i = 0 ; i < cabecera->len && i < N; i++){
		printf("%02X ", paquete[i]);

	}
	printf("\n");

	if(pdumper){
		cabecera_modificada = (struct pcap_pkthdr*) cabecera ; //Igualamos la copia modificada con el original
		cabecera_modificada->ts.tv_sec += 1800; //Modificamos la fecha de captura
		pcap_dump((uint8_t *)pdumper,cabecera_modificada,paquete);
	}
}

int main(int argc, char **argv){

	int retorno=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	char file_name[256];
	struct timeval time;

	N = atoi(argv[1]);


	if(argc >= 4){
		perror("El numero de argumentos no es el indicado\n");
		exit(ERROR);
	}
	else if(argc <= 1){
		perror("El formato de argumentos debe ser el siguiente:\n 1. El número de bytes que queremos mostrar de cada paquete capturado \n 2. Traza a analizar (opcional)\n");
		exit(ERROR);
	}

	else if (argc == 2){


		if(signal(SIGINT,handle)==SIG_ERR){
			printf("Error: Fallo al capturar la senal SIGINT.\n");
			exit(ERROR);
		}
			//Apertura de interface
	   	if ((descr = pcap_open_live("eth0",ETH_FRAME_MAX,0,100, errbuf)) == NULL){
			printf("Error: pcap_open_live(): %s, %s %d.\n",errbuf,__FILE__,__LINE__);
			exit(ERROR);
		}
			//Para volcado de traza
		descr2=pcap_open_dead(DLT_EN10MB,ETH_FRAME_MAX);
		if (!descr2){
			printf("Error al abrir el dump.\n");
			pcap_close(descr);
			exit(ERROR);
		}
		gettimeofday(&time,NULL);
		sprintf(file_name,"eth0.%lld.pcap",(long long)time.tv_sec);
		pdumper=pcap_dump_open(descr2,file_name);
		if(!pdumper){
			printf("Error al abrir el dumper: %s, %s %d.\n",pcap_geterr(descr2),__FILE__,__LINE__);
			pcap_close(descr);
			pcap_close(descr2);
			exit(ERROR);
		}

	}else{

		descr = pcap_open_offline(argv[2], errbuf);

	}

		//Se pasa el contador como argumento, pero sera mas comodo y mucho mas habitual usar variables globales
	retorno = pcap_loop (descr,-1,fa_nuevo_paquete, (uint8_t*)&contador);
	if(retorno == -1){ 		//En caso de error
		printf("Error al capturar un paquete %s, %s %d.\n",pcap_geterr(descr),__FILE__,__LINE__);
		pcap_close(descr);
		pcap_close(descr2);
		pcap_dump_close(pdumper);
		exit(ERROR);
	}
	else if(retorno==-2){ //pcap_breakloop() no asegura la no llamada a la funcion de atencion para paquetes ya en el buffer
		printf("Llamada a %s %s %d.\n","pcap_breakloop()",__FILE__,__LINE__);
	}
	else if(retorno == 0){
		printf("No mas paquetes o limite superado %s %d.\n",__FILE__,__LINE__);
		printf("Numero de elementos capturados: %d\n", contador);
	}

	pcap_dump_close(pdumper);
	pcap_close(descr);
	pcap_close(descr2);

	return OK;
}
