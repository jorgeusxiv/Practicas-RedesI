/***************************************************************************
 practica2.c

 Compila: gcc -Wall -o practica2 practica2.c -lpcap, make
 Autor: Jose Benjumeda Rubio, Jorge Santisteban Rivas
 Grupo 1301_P9
 2018 EPS-UAM
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <inttypes.h>

/*Definicion de constantes *************************************************/
#define ETH_ALEN      6      /* Tamanio de la direccion ethernet           */
#define ETH_HLEN      14     /* Tamanio de la cabecera ethernet            */
#define ETH_TLEN      2      /* Tamanio del campo tipo ethernet            */
#define ETH_FRAME_MAX 1514   /* Tamanio maximo la trama ethernet (sin CRC) */
#define ETH_FRAME_MIN 60     /* Tamanio minimo la trama ethernet (sin CRC) */
#define ETH_DATA_MAX  (ETH_FRAME_MAX - ETH_HLEN) /* Tamano maximo y minimo de los datos de una trama ethernet*/
#define ETH_DATA_MIN  (ETH_FRAME_MIN - ETH_HLEN)
#define IP_ALEN 4			/* Tamanio de la direccion IP					*/
#define OK 0
#define ERROR 1
#define PACK_READ 1
#define PACK_ERR -1
#define BREAKLOOP -2
#define NO_FILTER 0
#define NO_LIMIT -1
void analizar_paquete(u_char *user,const struct pcap_pkthdr *hdr, const uint8_t *pack);



void handleSignal(int nsignal);

pcap_t *descr = NULL;
uint64_t contador = 0;
uint8_t ipsrc_filter[IP_ALEN] = {NO_FILTER};
uint8_t ipdst_filter[IP_ALEN] = {NO_FILTER};
uint16_t sport_filter= NO_FILTER;
uint16_t dport_filter = NO_FILTER;
uint8_t ipv4[2] = {8,0};

void handleSignal(int nsignal)
{
	(void) nsignal; // indicamos al compilador que no nos importa que nsignal no se utilice

	printf("Control C pulsado\n");
	pcap_breakloop(descr);
}

int main(int argc, char **argv)
{


	char errbuf[PCAP_ERRBUF_SIZE];

	int long_index = 0, retorno = 0;
	char opt;

	(void) errbuf; //indicamos al compilador que no nos importa que errbuf no se utilice. Esta linea debe ser eliminada en la entrega final.

	if (signal(SIGINT, handleSignal) == SIG_ERR) {
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		exit(ERROR);
	}

	if (argc == 1) {
		printf("Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]\n", argv[0]);
		exit(ERROR);
	}

	static struct option options[] = {
		{"f", required_argument, 0, 'f'},
		{"i",required_argument, 0,'i'},
		{"ipo", required_argument, 0, '1'},
		{"ipd", required_argument, 0, '2'},
		{"po", required_argument, 0, '3'},
		{"pd", required_argument, 0, '4'},
		{"h", no_argument, 0, '5'},
		{0, 0, 0, 0}
	};

	//Simple lectura por parametros por completar casos de error, ojo no cumple 100% los requisitos del enunciado!
	while ((opt = getopt_long_only(argc, argv, "f:i:1:2:3:4:5", options, &long_index)) != -1) {
		switch (opt) {
		case 'i' :
			if(descr) { // comprobamos que no se ha abierto ninguna otra interfaz o fichero
				printf("Ha seleccionado más de una fuente de datos\n");
				pcap_close(descr);
				exit(ERROR);
			}


			if ((descr = pcap_open_live(optarg, ETH_FRAME_MAX, 1, 100, errbuf)) == NULL){ //modo promiscuo
			     printf("Error: pcap_open_live(): Interface: %s, %s %s %d.\n", optarg,errbuf,__FILE__,__LINE__);
				exit(ERROR);
			}
			break;

		case 'f' :
			if(descr) { // comprobamos que no se ha abierto ninguna otra interfaz o fichero
				printf("Ha seleccionado más de una fuente de datos\n");
				pcap_close(descr);
				exit(ERROR);
			}

			if ((descr = pcap_open_offline(optarg, errbuf)) == NULL) {
				printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", optarg, errbuf, __FILE__, __LINE__);
				exit(ERROR);
			}

			break;

		case '1' :
			if (sscanf(optarg, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"", &(ipsrc_filter[0]), &(ipsrc_filter[1]), &(ipsrc_filter[2]), &(ipsrc_filter[3])) != IP_ALEN) {
				printf("Error ipo_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '2' :
			if (sscanf(optarg, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"", &(ipdst_filter[0]), &(ipdst_filter[1]), &(ipdst_filter[2]), &(ipdst_filter[3])) != IP_ALEN) {
				printf("Error ipd_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '3' :
			if ((sport_filter= atoi(optarg)) == 0) {
				printf("Error po_filtro.Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '4' :
			if ((dport_filter = atoi(optarg)) == 0) {
				printf("Error pd_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '5' :
			printf("Ayuda. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
			exit(ERROR);
			break;

		case '?' :
		default:
			printf("Error. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
			exit(ERROR);
			break;
		}
	}

	if (!descr) {
		printf("No selecciono ningún origen de paquetes.\n");
		return ERROR;
	}

	//Simple comprobacion de la correcion de la lectura de parametros
	printf("Filtro:");
	if(ipsrc_filter[0]!=0)
	printf("ipsrc_filter:%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\t", ipsrc_filter[0], ipsrc_filter[1], ipsrc_filter[2], ipsrc_filter[3]);
	if(ipdst_filter[0]!=0)
	printf("ipdst_filter:%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\t", ipdst_filter[0], ipdst_filter[1], ipdst_filter[2], ipdst_filter[3]);

	if (sport_filter!= NO_FILTER) {
		printf("po_filtro=%"PRIu16"\t", sport_filter);
	}

	if (dport_filter != NO_FILTER) {
		printf("pd_filtro=%"PRIu16"\t", dport_filter);
	}

	printf("\n\n");

	retorno=pcap_loop(descr,NO_LIMIT,analizar_paquete,NULL);
	switch(retorno)	{
		case OK:
			printf("Traza leída\n");
			break;
		case PACK_ERR:
			printf("Error leyendo paquetes\n");
			break;
		case BREAKLOOP:
			printf("pcap_breakloop llamado\n");
			break;
	}
	printf("Se procesaron %"PRIu64" paquetes.\n\n", contador);
	pcap_close(descr);
	return OK;
}



void analizar_paquete(u_char *user,const struct pcap_pkthdr *hdr, const uint8_t *pack)
{
	(void)user;
	printf("Nuevo paquete capturado el %s\n", ctime((const time_t *) & (hdr->ts.tv_sec)));
	contador++;
	int i = 0;
  uint8_t aux8 = 0;
  uint16_t aux16 = 0;
  uint8_t protocolo = 0;
	uint8_t ihl = 0;
	uint16_t desplazamiento = 0;

	printf("\n NIVEL 2\n");


	printf("Direccion ETH destino= ");
	printf("%02X", pack[0]);

	for (i = 1; i < ETH_ALEN; i++) {
		printf("-%02X", pack[i]);
	}

	printf("\n");
	pack += ETH_ALEN;

	printf("Direccion ETH origen = ");
	printf("%02X", pack[0]);

	for (i = 1; i < ETH_ALEN; i++) {
		printf("-%02X", pack[i]);
	}

	printf("\n");

	pack += ETH_ALEN;

  printf("Tipo de protocolo que encapsula = ");
  printf("%02X%02X \n", pack[0],pack[1]);

  if(pack[0] != ipv4[0] || pack[1] != ipv4[1]){
    printf("El protocolo no es el esperado (IPV4)\n");
    printf("\n\n");
    return;
  }

	pack += ETH_TLEN;


  //Nivel 3

	printf("\n NIVEL 3\n");

  printf("Version IP = ");
  aux8 = pack[0] >> 4;
  printf("%d\n", aux8);

  printf("Longitud de cabecera = ");
  aux8 = pack[0] << 4;
  aux8 = aux8 >> 4;
	ihl = aux8;
  printf("%d\n", aux8);

  pack += IP_ALEN / 2;

  printf("Longitud total = ");
  aux16 = pack[0] << 8;
  aux16 = pack[1] | aux16;
  printf("%d\n", aux16);

  pack += IP_ALEN;


  printf("Posicion/Desplazamiento = ");
  aux8 = pack[0] & 0x1F;
  aux16 = aux8 << 8;
  aux16 = pack[1] | aux16;
  printf("%d\n", aux16);

	//Guardamos el desplazamiento

	desplazamiento = aux16;

  pack += IP_ALEN / 2;

  printf("Tiempo de vida = ");
  printf("%d\n", pack[0]);

  protocolo = pack[1];

  printf("Protocolo = ");
  printf("%d\n", pack[1]);


  pack += IP_ALEN;

	if(((ipsrc_filter[0] != pack[0]) || (ipsrc_filter[1] != pack[1]) || (ipsrc_filter[2] != pack[2]) || (ipsrc_filter[3] != pack[3])) && (ipsrc_filter[0] != 0)){

		printf("El filtro para la direccion IP Origen no ha sido superado\n");
		return;
	}

  printf("Direccion origen = ");
  printf("%d.%d.%d.%d\n", pack[0], pack[1], pack[2], pack[3]);


  pack += IP_ALEN;

	if(((ipdst_filter[0] != pack[0]) || (ipdst_filter[1] != pack[1]) || (ipdst_filter[2] != pack[2]) || (ipdst_filter[3] != pack[3])) && (ipdst_filter[0] != 0)){

		printf("El filtro para la direccion IP Destino no ha sido superado\n");
		return;
	}

  printf("Direccion destino = ");
  printf("%d.%d.%d.%d\n", pack[0], pack[1], pack[2], pack[3]);

  if(protocolo != 0x06 && protocolo != 0x11){
    printf("El protocolo no es TCP ni UDP\n");
    return;
  }

	//Comprobamos que el desplazamiento sea distinto de 0

	if(desplazamiento != 0){
		printf("El paquete IP leido no es el primer fragmento\n");
		return;
	}

  //Nivel 4


	pack += (IP_ALEN + (ihl - 0x05)*4) ;


	aux16 = pack[0] << 8;
	aux16 = pack[1] | aux16;

	if(sport_filter != aux16 && sport_filter != NO_FILTER){

			printf("El filtro para el puerto origen no ha sido superado\n");
			return;

	}

	printf("\n NIVEl 4\n");
	printf("Puerto de origen = ");
	printf("%d\n", aux16);

	pack += 2;



	aux16 = pack[0] << 8;
	aux16 = pack[1] | aux16;

	if(dport_filter != aux16 && dport_filter != NO_FILTER){

			printf("El filtro para el puerto destino no ha sido superado\n");
			return;

	}

	printf("Puerto de destino = ");
	printf("%d\n", aux16);

	if(protocolo == 0x11){
		printf("Protocolo UDP\n");

		pack += 2;

		printf("Longitud = ");
		aux16 = pack[0] << 8;
		aux16 = pack[1] | aux16;
		printf("%d\n",aux16);

	}else{
		printf("Protocolo TCP\n");

		pack += 11;

		printf("Bandera SYN = ");
		aux8 = pack[0] << 6;
		aux8 = aux8 >> 7;
		printf("%d\n",aux8);

		printf("Bandera FIN = ");
		aux8 = pack[0] << 7;
		aux8 = aux8 >> 7;
		printf("%d\n",aux8);


	}

	printf("\n\n");

}
