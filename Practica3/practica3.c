/***************************************************************************
 practica3.c
 Inicio, funciones auxiliares y modulos de transmision implmentados y a implementar de la practica 4.
Compila con warning pues falta usar variables y modificar funciones

 Compila: make
 Autor: Jose Benjumeda Rubio, Jorge Santisteban Rivas
 2018 EPS-UAM v1
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "interface.h"
#include "practica3.h"

/***************************Variables globales utiles*************************************************/
pcap_t* descr, *descr2; //Descriptores de la interface de red
pcap_dumper_t * pdumper;//y salida a pcap
uint64_t cont=0;	//Contador numero de mensajes enviados
char interface[10];	//Interface donde transmitir por ejemplo "eth0"
uint16_t ID=1;		//Identificador IP
char flag_mostrar = 0; //Flag para mostrar en hexadecimal


void handleSignal(int nsignal){
	printf("Control C pulsado (%"PRIu64")\n", cont);
	pcap_close(descr);
	exit(OK);
}

int main(int argc, char **argv){

	char errbuf[PCAP_ERRBUF_SIZE];
	char fichero_pcap_destino[CADENAS];
	uint8_t IP_destino_red[IP_ALEN];
	uint16_t MTU;
	uint16_t datalink;
	uint16_t puerto_destino;
	char data[IP_DATAGRAM_MAX];
	uint16_t pila_protocolos[CADENAS];

	char *data_aux = NULL;
	FILE *f = NULL;
	uint64_t size_f = 0;


	int long_index=0;
	char opt;
	char flag_iface = 0, flag_ip = 0, flag_port = 0, flag_file = 0, flag_dontfrag = 0;

	static struct option options[] = {
		{"if",required_argument,0,'1'},
		{"ip",required_argument,0,'2'},
		{"pd",required_argument,0,'3'},
		{"f",required_argument,0,'4'},
		{"d",no_argument,0,'5'},
		{"m",no_argument,0,'6'},
		{"h",no_argument,0,'7'},
		{0,0,0,0}
	};

		//Dos opciones: leer de stdin o de fichero, adicionalmente para pruebas si no se introduce argumento se considera que el mensaje es "Payload "
	while ((opt = getopt_long_only(argc, argv,"1:2:3:4:5:6:7", options, &long_index )) != -1) {
		switch (opt) {

			case '1' :

				flag_iface = 1;
				//Por comodidad definimos interface como una variable global
				sprintf(interface,"%s",optarg);
				break;

			case '2' :

				flag_ip = 1;
				//Leemos la IP a donde transmitir y la almacenamos en orden de red
				if (sscanf(optarg,"%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"",
				                   &(IP_destino_red[0]),&(IP_destino_red[1]),&(IP_destino_red[2]),&(IP_destino_red[3])) != IP_ALEN){
					printf("Error: Fallo en la lectura IP destino %s\n", optarg);
					exit(ERROR);
				}

				break;

			case '3' :

				flag_port = 1;
				//Leemos el puerto a donde transmitir y la almacenamos en orden de hardware
				puerto_destino=atoi(optarg);
				break;

			case '4' :

				if(strcmp(optarg,"stdin")==0) {
					if (fgets(data, sizeof data, stdin)==NULL) {
						  	printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
						return ERROR;
					}
					sprintf(fichero_pcap_destino,"%s%s","stdin",".pcap");
				} else {
					sprintf(fichero_pcap_destino,"%s%s",optarg,".pcap");
					f = fopen(optarg,"r");
					if(f == NULL){
						perror("El fichero no existe");
						exit(ERROR);
					}
					if((strlen(data)<1) && (fgets(data, sizeof data, f)==NULL)){
						fclose(f);
						perror("Error leyendo desde el fichero");
						exit(ERROR);
					}

					fseek(f,0,SEEK_END);
					size_f = ftell(f);

					if(size_f >= IP_DATAGRAM_MAX){
						fclose(f);
						perror("Supera el tamanio maxiimo para el datagrama de UDP");
						return(ERROR);
					}

					fseek(f,0,SEEK_SET);

					data_aux = (char*)malloc((size_f+1)*sizeof(char));
					fread(data_aux,size_f,1,f);
					data_aux[size_f]=0;
					fclose(f);

					strcpy(data,data_aux);
					free(data_aux);

				}
				flag_file = 1;
				break;

			case '5' :
				flag_dontfrag =1; // El usuario solicita que los paquetes se envien con el bit DF=1.
				break;

			case '6' :
				flag_mostrar =1; // El usuario solicita que se muestren en hexadecimal las tramas enviadas.
				break;

			case '7' : printf("Ayuda. Ejecucion: %s -if interface -ip direccion_IP -pd puerto [-f /ruta/fichero_a_transmitir o stdin] [-d] [-m]: %d\n",argv[0],argc); exit(ERROR);
				break;

			case '?' :
			default: printf("Error. Ejecucion: %s -if interface -ip direccion_IP -pd puerto [-f /ruta/fichero_a_transmitir o stdin] [-d] [-m]: %d\n",argv[0],argc); exit(ERROR);
				break;
        }
    }

	if ((flag_iface == 0) || (flag_ip == 0) || (flag_port == 0)){
		printf("Error. Ejecucion: %s -if interface -ip direccion_IP -pd puerto [-f /ruta/fichero_a_transmitir o stdin] [-d] [-m]: %d\n",argv[0],argc);
		exit(ERROR);
	} else {
		printf("Interface:\n\t%s\n",interface);
		printf("IP:\n\t%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\n",IP_destino_red[0],IP_destino_red[1],IP_destino_red[2],IP_destino_red[3]);
		printf("Puerto destino:\n\t%"PRIu16"\n",puerto_destino);
		if (flag_dontfrag) printf("Se solicita enviar paquete con bit DF=1\n");
		if (flag_mostrar) printf("Se solicita mostrar las tramas enviadas en hexadecimal\n");
	}

	if (flag_file == 0) {
		sprintf(data,"%s","Payload "); //Deben ser pares!
		sprintf(fichero_pcap_destino,"%s%s","debugging",".pcap");
	}

	if(signal(SIGINT,handleSignal)==SIG_ERR){
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		return ERROR;
	}
	//Inicializamos las tablas de protocolos
	if(inicializarPilaEnviar()==ERROR){
      	printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	//Leemos el tamano maximo de transmision del nivel de enlace
	if(obtenerMTUInterface(interface, &MTU)==ERROR)
		return ERROR;
	//Descriptor de la interface de red donde inyectar trafico
	if ((descr = pcap_open_live(interface,MTU+ETH_HLEN,0, 0, errbuf)) == NULL){
		printf("Error: pcap_open_live(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}

	datalink=(uint16_t)pcap_datalink(descr); //DLT_EN10MB==Ethernet

	//Descriptor del fichero de salida pcap para debugging
	descr2=pcap_open_dead(datalink,MTU+ETH_HLEN);
	pdumper=pcap_dump_open(descr2,fichero_pcap_destino);

	//Formamos y enviamos el trafico, debe enviarse un unico segmento por llamada a enviar() aunque luego se traduzca en mas de un datagrama
	//Primero, un paquete ICMP; en concreto, un ping
	pila_protocolos[0]=ICMP_PROTO; pila_protocolos[1]=IP_PROTO; pila_protocolos[2]=0;
	Parametros parametros_icmp; parametros_icmp.tipo=PING_TIPO; parametros_icmp.codigo=PING_CODE; parametros_icmp.bit_DF=flag_dontfrag; memcpy(parametros_icmp.IP_destino,IP_destino_red,IP_ALEN);
	if(enviar((uint8_t*)ICMP_DATA,strlen(ICMP_DATA),pila_protocolos,&parametros_icmp)==ERROR ){
		printf("Error: enviar(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	else	cont++;
	printf("Enviado mensaje %"PRIu64", ICMP almacenado en %s\n\n", cont,fichero_pcap_destino);

	//Luego, un paquete UDP
	//Definimos la pila de protocolos que queremos seguir
	pila_protocolos[0]=UDP_PROTO; pila_protocolos[1]=IP_PROTO; pila_protocolos[2]=ETH_PROTO;
	//Rellenamos los parametros necesario para enviar el paquete a su destinatario y proceso
	Parametros parametros_udp; memcpy(parametros_udp.IP_destino,IP_destino_red,IP_ALEN); parametros_udp.bit_DF=flag_dontfrag; parametros_udp.puerto_destino=puerto_destino;
	//Enviamos
	if(enviar((uint8_t*)data,strlen(data),pila_protocolos,&parametros_udp)==ERROR ){
		printf("Error: enviar(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	else	cont++;

	printf("Enviado mensaje %"PRIu64", almacenado en %s\n\n\n", cont,fichero_pcap_destino);

		//Cerramos descriptores
	pcap_close(descr);
	pcap_dump_close(pdumper);
	pcap_close(descr2);
	return OK;
}


/****************************************************************************************
 * Nombre: enviar                                                                       *
 * Descripcion: Esta funcion envia un mensaje                                           *
 * Argumentos:                                                                          *
 *  -mensaje: mensaje a enviar                                                          *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -longitud: bytes que componen mensaje                                               *
 *  -parametros: parametros necesario para el envio (struct parametros)                 *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t enviar(uint8_t* mensaje, uint32_t longitud,uint16_t* pila_protocolos,void *parametros){
	uint16_t protocolo=pila_protocolos[0];
printf("Enviar(%"PRIu16") %s %d.\n",protocolo,__FILE__,__LINE__);
	if(protocolos_registrados[protocolo]==NULL){
		printf("Protocolo %"PRIu16" desconocido\n",protocolo);
		return ERROR;
	}
	else {
		return protocolos_registrados[protocolo](mensaje,longitud,pila_protocolos,parametros);
	}
	return ERROR;
}


/***************************TODO Pila de protocolos a implementar************************************/


/****************************************************************************************
 * Nombre: moduloICMP                                                                   *
 * Descripcion: Esta funcion implementa el modulo de envio ICMP                         *
 * Argumentos:                                                                          *
 *  -mensaje: mensaje a anadir a la cabecera ICMP                                       *
 *  -longitud: bytes que componen el mensaje                                            *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -parametros: parametros necesario para el envio este protocolo                      *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t moduloICMP(uint8_t* mensaje, uint32_t longitud, uint16_t* pila_protocolos, void *parametros){
	uint8_t segmento[ICMP_DATAGRAM_MAX]={0};
	uint8_t *checksum = NULL;
	uint8_t aux8;
	uint16_t aux16;
	uint16_t suma_control=0;
	uint32_t pos=0, pos_control;
	Parametros estructura=*(Parametros*)parametros;
	uint8_t protocolo_inferior=pila_protocolos[1];
	printf("modulo ICMP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);

	//Tenemos en cuenta que la longitud del mensaje no sea mayor que la posible

	if(longitud > (ICMP_DATAGRAM_MAX - ICMP_HLEN)){
		perror("Mensaje muy grande para ICMP");
		return(ERROR);
	}

	//Metemos el tipo
	aux8=estructura.tipo;
	memcpy(segmento+pos,&aux8,sizeof(uint8_t));

	//Metemos el código
	pos+=sizeof(uint8_t);
	aux8=estructura.codigo;
	memcpy(segmento+pos,&aux8,sizeof(uint8_t));

	//Metemos el checksum
	pos+=sizeof(uint8_t);
	pos_control = pos;
	memcpy(segmento+pos,&suma_control,sizeof(uint16_t));

	//Metemos el identificador
	pos+=sizeof(uint16_t);
	aux16=htons(getpid());
	memcpy(segmento+pos,&aux16,sizeof(uint16_t));

	//Metemos el numero de secuencia
	pos+=sizeof(uint16_t);
	aux16=htons(1);
	memcpy(segmento+pos,&aux16,sizeof(uint16_t));

	//Copiamos el mensaje
	pos+=sizeof(uint16_t);
	memcpy(segmento+pos,mensaje,longitud*sizeof(uint8_t));

	//Calculamos el checksum

	checksum = (uint8_t*) malloc((sizeof(uint16_t)));
	if(calcularChecksum(segmento, longitud+pos, checksum) == ERROR){
		perror("Error al calcular el checksum");
		return(ERROR);
	}

	//Guardamos el checksum
	memcpy(segmento+pos_control,checksum,sizeof(uint16_t));

	//Liberamos checksum

	free(checksum);

//Se llama al protocolo definido de nivel inferior a traves de los punteros registrados en la tabla de protocolos registrados
	return protocolos_registrados[protocolo_inferior](segmento,longitud+pos,pila_protocolos,parametros);
}


/****************************************************************************************
 * Nombre: moduloUDP                                                                    *
 * Descripcion: Esta funcion implementa el modulo de envio UDP                          *
 * Argumentos:                                                                          *
 *  -mensaje: mensaje a enviar                                                          *
 *  -longitud: bytes que componen mensaje                                               *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -parametros: parametros necesario para el envio este protocolo                      *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t moduloUDP(uint8_t* mensaje, uint32_t longitud, uint16_t* pila_protocolos, void *parametros){
	uint8_t segmento[UDP_SEG_MAX]={0};
	uint16_t puerto_origen = 0, suma_control=0;
	uint16_t aux16;
	uint32_t pos=0;
	uint8_t protocolo_inferior=pila_protocolos[1];
	printf("modulo UDP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);

	if (longitud>UDP_SEG_MAX){
		printf("Error: mensaje demasiado grande para UDP (%d).\n",UDP_SEG_MAX);
		return ERROR;
	}

	Parametros udpdatos=*((Parametros*)parametros);
	uint16_t puerto_destino=udpdatos.puerto_destino;

	//Obtenemos el puerto origen
	if(obtenerPuertoOrigen(&puerto_origen) == ERROR){
		perror("Error calculando el puerto origen");
		return(ERROR);
	}
	//Escribimos el puerto origen
	aux16=htons(puerto_origen);
	memcpy(segmento+pos,&aux16,sizeof(uint16_t));

	//Escribimos el puerto destino
	pos+=sizeof(uint16_t);
	aux16=htons(puerto_destino);
	memcpy(segmento+pos,&aux16,sizeof(uint16_t));

	//Escribimos la longitud
	pos+=sizeof(uint16_t);
	aux16=htons(UDP_HLEN + longitud);
	memcpy(segmento+pos,&aux16,sizeof(uint16_t));

	//Escribimos en checksum 0
	pos+=sizeof(uint16_t);
	memcpy(segmento+pos,&suma_control,sizeof(uint16_t));


	//Escribimos el mensaje

	pos+=sizeof(uint16_t);
	memcpy(segmento+pos,mensaje,longitud);

	return protocolos_registrados[protocolo_inferior](segmento,longitud+pos,pila_protocolos,parametros);
}


/****************************************************************************************
 * Nombre: moduloIP                                                                     *
 * Descripcion: Esta funcion implementa el modulo de envio IP                           *
 * Argumentos:                                                                          *
 *  -segmento: segmento a enviar                                                        *
 *  -longitud: bytes que componen el segmento                                           *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -parametros: parametros necesario para el envio este protocolo                      *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t moduloIP(uint8_t* segmento, uint32_t longitud, uint16_t* pila_protocolos, void *parametros){
	uint8_t datagrama[IP_DATAGRAM_MAX]={0};
	uint16_t aux16;
	uint8_t aux8;
	uint32_t pos=0,pos_control=0;
	uint8_t IP_origen[IP_ALEN];
	uint8_t protocolo_superior=pila_protocolos[0];
	uint8_t protocolo_inferior=pila_protocolos[2];
	pila_protocolos++;
	uint8_t mascara[IP_ALEN],IP_rango_origen[IP_ALEN],IP_rango_destino[IP_ALEN];

	uint16_t mtu;
	uint8_t *gateway;
	int numero_paquetes,i;
	uint16_t longitud_frag;
	uint16_t suma_control=0;
	uint8_t *checksum;
	uint32_t posicion_frag=0;


	printf("modulo IP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);

	Parametros ipdatos=*((Parametros*)parametros);
	uint8_t* IP_destino=ipdatos.IP_destino;

	//Tenemos que obtener el MTU, el IP_origen y la mascara, además de aplicarla despues

	if(obtenerMTUInterface(interface,&mtu) == ERROR){
		return ERROR;
	}

	if(obtenerMascaraInterface(interface,mascara) == ERROR){
		return ERROR;
	}

	if(obtenerIPInterface(interface, IP_origen) == ERROR){
		return ERROR;
	}

	if(aplicarMascara(IP_origen, mascara, IP_ALEN, IP_rango_origen) == ERROR){
		return ERROR;
	}

	if(aplicarMascara(IP_destino, mascara, IP_ALEN, IP_rango_destino) == ERROR){
		return ERROR;
	}

	//Comprobamos si esta en la misma subred

	if((IP_rango_origen[0] == IP_rango_destino[0]) && (IP_rango_origen[1] == IP_rango_destino[1]) && (IP_rango_origen[2] == IP_rango_destino[2]) && (IP_rango_origen[3] == IP_rango_destino[3])){

		//ESTAN en la misma subred y realizamos el ARPREQUEST

		if(solicitudARP(interface, IP_destino, ipdatos.ETH_destino) == ERROR){
			return ERROR;
		}

	}else{

		//NO ESTAN en la misma subred

		gateway = (uint8_t*) malloc(IP_ALEN*sizeof(uint8_t));

		if(obtenerGateway(interface,gateway) == ERROR){
			return(ERROR);
		}

		if(solicitudARP(interface, gateway, ipdatos.ETH_destino) == ERROR){
			return(ERROR);
		}

		free(gateway);

	}

	//Ahora tenemos que comprobar si esta fragmentado o no

	if(longitud > (mtu - IP_HLEN)){

		 //Fragmentado

		 printf("El paquete requiere fragmentacion\n");

		 //Obtenemos el numero de paquetes necesarios

		 if(ipdatos.bit_DF == 1){
			 perror("El paquete requiere fragmentacion pero no esta permitida");
			 return(ERROR);
		 }

		 numero_paquetes = ceil((longitud*1.0)/(mtu-IP_HLEN));

		 //Empezamos a generar los paquetes

		 for(i=0; i < numero_paquetes; i++){

			 //Para cada paquete tenemos que "reiniciar" el datagrama y la posicion

			 memset(datagrama,0,IP_DATAGRAM_MAX);
			 pos = 0;

			 //En primer lugar guardamos la version y el IHL
			 //La version siempre va a ser 4 = 0x4
			 //El ihl (longitud en palabras de 32 bits), que seran 5=0x5

			 aux8 = 0x45;
			 memcpy(datagrama+pos,&aux8,sizeof(uint8_t));

			 //Tipo de servicio

			 pos+=sizeof(uint8_t);
			 aux8=0; //Siempre es 0
			 memcpy(datagrama+pos,&aux8,sizeof(uint8_t));

			 //Longitud total

			 pos+=sizeof(uint8_t);

			 //Todos menos el ultimo paquete van a tener la longitud maxima

			 if(i == numero_paquetes - 1){

				 longitud_frag = longitud - (numero_paquetes-1)*(floor((mtu-IP_HLEN)/8)*8) + IP_HLEN;

			 }else{

				 longitud_frag = floor((mtu-IP_HLEN)/8)*8 + IP_HLEN;

			 }

			 aux16=htons(longitud_frag);
			 memcpy(datagrama+pos,&aux16,sizeof(uint16_t));

			 //Identificador

			pos+=sizeof(uint16_t);
			aux16=htons(getpid());
		 	memcpy(datagrama+pos,&aux16,sizeof(uint16_t));

			//Flags y offset
			//Para las flags en todos los framgmentos menos el ultimo va a ser 001, mientras que para el ultimo sera 010
			//El offset será "el número de partes de 64 bits (no se cuentan los bytes de la cabecera) contenidas en fragmentos anteriores. En el primer (o único) fragmento el valor es siempre cero."

			pos+=sizeof(uint16_t);

			aux16 = (floor((mtu - IP_HLEN)/8)*8*i)/8;
			if(i == numero_paquetes - 1){

				aux16 = htons(aux16 | 0x0000);

			}else{

				aux16 = htons(aux16 | 0x2000);

			}

			memcpy(datagrama+pos, &aux16, sizeof(uint16_t));

			//Tiempo de vida

			pos+=sizeof(uint16_t);
			aux8=64;
			memcpy(datagrama+pos, &aux8, sizeof(uint8_t));

			//Protocolo

			pos+=sizeof(uint8_t);
			memcpy(datagrama+pos, &protocolo_superior, sizeof(uint8_t));

			//Checksum (igual que para UCP e ICMP)

			pos+=sizeof(uint8_t);
			pos_control=pos;
			memcpy(datagrama+pos,&suma_control,sizeof(uint16_t));


			//Direccion de IP origen e IP destino

			pos+=sizeof(uint16_t);
			memcpy(datagrama+pos,IP_origen,sizeof(uint32_t));
			pos+=sizeof(uint32_t);
			memcpy(datagrama+pos,IP_destino,sizeof(uint32_t));

			pos+=sizeof(uint32_t);

			//Calculamos el checksum

			checksum = (uint8_t*)malloc(sizeof(uint16_t));
			if(calcularChecksum(datagrama, IP_HLEN, checksum) == ERROR){
				perror("Error calculando el checksum");
				return(ERROR);
			}
			memcpy(datagrama + pos_control,checksum, sizeof(uint16_t));
			free(checksum);

			posicion_frag=(mtu-IP_HLEN)*i;
			memcpy(datagrama+pos,segmento+posicion_frag,longitud_frag - IP_HLEN);
			pos=pos+longitud_frag-IP_HLEN;

			if(i != (numero_paquetes - 1)){
				if(protocolos_registrados[protocolo_inferior](datagrama, longitud_frag, pila_protocolos,&ipdatos) == ERROR){
					return (ERROR);
				}
			}else{
				return protocolos_registrados[protocolo_inferior](datagrama,longitud_frag,pila_protocolos,&ipdatos);
			}


		 }



	}else{

		//NO ESTA FRAGMENTADO

		printf("El paquete no requiere fragmentacion\n");


		 //En primer lugar guardamos la version y el IHL
		 //La version siempre va a ser 4 = 0x4
		 //El ihl (longitud en palabras de 32 bits), que seran 5=0x5

		 aux8 = 0x45;
		 memcpy(datagrama+pos,&aux8,sizeof(uint8_t));

		 //Tipo de servicio

		 pos+=sizeof(uint8_t);
		 aux8=0; //Siempre es 0
		 memcpy(datagrama+pos,&aux8,sizeof(uint8_t));

		 //Longitud total

		 pos+=sizeof(uint8_t);
		 aux16=htons(longitud+IP_HLEN);
		 memcpy(datagrama+pos,&aux16,sizeof(uint16_t));


		 //Identificador

		pos+=sizeof(uint16_t);
		aux16=htons(getpid());
		memcpy(datagrama+pos,&aux16,sizeof(uint16_t));

		//Flags y offset

		//El offset será "el número de partes de 64 bits .En el primer (o único) fragmento el valor es siempre cero."

		pos+=sizeof(uint16_t);
		aux16 = 0;
		if(ipdatos.bit_DF == 1){
			aux16 = htons(aux16 | 0x4000);
		}else{
			aux16 = htons(aux16 | 0x0000);
		}

		memcpy(datagrama+pos, &aux16, sizeof(uint16_t));

		//Tiempo de vida

		pos+=sizeof(uint16_t);
		aux8=64;
		memcpy(datagrama+pos, &aux8, sizeof(uint8_t));

		//Protocolo

		pos+=sizeof(uint8_t);
		memcpy(datagrama+pos, &protocolo_superior, sizeof(uint8_t));

		//Checksum (igual que para UCP e ICMP)

		pos+=sizeof(uint8_t);
		pos_control=pos;
		memcpy(datagrama+pos,&suma_control,sizeof(uint16_t));


		//Direccion de IP origen e IP destino

		pos+=sizeof(uint16_t);
		memcpy(datagrama+pos,IP_origen,sizeof(uint32_t));
		pos+=sizeof(uint32_t);
		memcpy(datagrama+pos,IP_destino,sizeof(uint32_t));


		pos+=sizeof(uint32_t);

		//Calculamos el checksum

		checksum = (uint8_t*)malloc(sizeof(uint16_t));
		if(calcularChecksum(datagrama, IP_HLEN, checksum) == ERROR){
			perror("Error calculando el checksum");
			return(ERROR);
		}
		memcpy(datagrama + pos_control,checksum, sizeof(uint16_t));
		free(checksum);


		//Añadimos el segmento al datagrama

		memcpy(datagrama+pos,segmento,longitud);

		return protocolos_registrados[protocolo_inferior](datagrama,longitud+pos,pila_protocolos,&ipdatos);


	}

	return(ERROR);

}


/****************************************************************************************
 * Nombre: moduloETH                                                                    *
 * Descripcion: Esta funcion implementa el modulo de envio Ethernet                     *
 * Argumentos:                                                                          *
 *  -datagrama: datagrama a enviar                                                      *
 *  -longitud: bytes que componen el datagrama                                          *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -parametros: Parametros necesario para el envio este protocolo                      *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t moduloETH(uint8_t* datagrama, uint32_t longitud, uint16_t* pila_protocolos,void *parametros){

uint8_t trama[ETH_FRAME_MAX]={0};
uint8_t pos = 0;
uint8_t * ETH_origen;
uint8_t * ETH_destino;
uint16_t aux16;
Parametros estructura=*(Parametros*)parametros;
struct pcap_pkthdr camposCabecera;
struct timeval time;

pila_protocolos++;

ETH_destino = estructura.ETH_destino;

printf("\nmodulo ETH(fisica) %s %d.\n",__FILE__,__LINE__);

if (obtenerMTUInterface(interface,&aux16) == ERROR){

	perror("Error en funcion obtenerMTUInterface.\n");
	return(ERROR);

}

if (longitud > aux16){

	perror("Maximum transfering unit superado.");
	return(ERROR);

}

// Metemos la direccion ethernet de destino
memcpy(trama + pos, ETH_destino, ETH_ALEN*sizeof(uint8_t));

// Metemos la direccion ethernet de destino
pos+=ETH_ALEN*sizeof(uint8_t);

//Obtenemos la direccion ETH_origen
ETH_origen = (uint8_t *) malloc(ETH_ALEN*sizeof(uint8_t));
if (obtenerMACdeInterface(interface, ETH_origen) == ERROR){

	perror("Error en funcion obtenerMACdeInterface.");
	return(ERROR);

}

memcpy(trama + pos, ETH_origen, ETH_ALEN*sizeof(uint8_t));
free(ETH_origen);



//Ahora metemos el tipo Ethernet.
pos+=ETH_ALEN*sizeof(uint8_t);
aux16 = htons(0x0800);
memcpy(trama + pos, &aux16, sizeof(uint16_t));

//Añadimos el datagrama
pos+=sizeof(uint16_t);
memcpy(trama + pos, datagrama, longitud*sizeof(uint8_t));

pcap_inject(descr,(const void *)trama, (pos+longitud)*sizeof(uint8_t));

gettimeofday(&time,NULL);

//Guardamos los datos del tiempo
camposCabecera.len = longitud + pos;
camposCabecera.ts = time;
camposCabecera.caplen = longitud + pos;

pcap_dump((uint8_t*) pdumper, &camposCabecera, trama);


if(flag_mostrar == 1){
	mostrarHex(trama, (uint32_t )(longitud + pos));
}

	return OK;
}



/***************************Funciones auxiliares a implementar***********************************/

/****************************************************************************************
 * Nombre: aplicarMascara                                                               *
 * Descripcion: Esta funcion aplica una mascara a una vector                            *
 * Argumentos:                                                                          *
 *  -IP: IP a la que aplicar la mascara en orden de red                                 *
 *  -mascara: mascara a aplicar en orden de red                                         *
 *  -longitud: bytes que componen la direccion (IPv4 == 4)                              *
 *  -resultado: Resultados de aplicar mascara en IP en orden red                        *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t aplicarMascara(uint8_t* IP, uint8_t* mascara, uint8_t longitud, uint8_t* resultado){

	int i;

	if(IP==NULL || mascara==NULL){
		perror("Error al insertar parametros");
		return(ERROR);
	}

	for(i=0; i<longitud;i++){
		resultado[i] = (IP[i]&mascara[i]);
	}

	return OK;
}


/***************************Funciones auxiliares implementadas**************************************/

/****************************************************************************************
 * Nombre: mostrarHex                                                                   *
 * Descripcion: Esta funcion imprime por pantalla en hexadecimal un vector              *
 * Argumentos:                                                                          *
 *  -datos: bytes que conforman un mensaje                                              *
 *  -longitud: Bytes que componen el mensaje                                            *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t mostrarHex(uint8_t * datos, uint32_t longitud){
	uint32_t i;
	printf("Datos:\n");
	for (i=0;i<longitud;i++){
		printf("%02"PRIx8" ", datos[i]);
	}
	printf("\n");
	return OK;
}


/****************************************************************************************
 * Nombre: calcularChecksum                                                             *
 * Descripcion: Esta funcion devuelve el ckecksum tal como lo calcula IP/ICMP           *
 * Argumentos:                                                                          *
 *   -datos: datos sobre los que calcular el checksum                                   *
 *   -longitud: numero de bytes de los datos sobre los que calcular el checksum         *
 *   -checksum: checksum de los datos (2 bytes) en orden de red!                        *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t calcularChecksum(uint8_t *datos, uint16_t longitud, uint8_t *checksum) {
    uint16_t word16;
    uint32_t sum=0;
    int i;
    // make 16 bit words out of every two adjacent 8 bit words in the packet
    // and add them up
    for (i=0; i<longitud; i=i+2){
        word16 = (datos[i]<<8) + datos[i+1];
        sum += (uint32_t)word16;
    }
    // take only 16 bits out of the 32 bit sum and add up the carries
    while (sum>>16) {
        sum = (sum & 0xFFFF)+(sum >> 16);
    }
    // one's complement the result
    sum = ~sum;
    checksum[0] = sum >> 8;
    checksum[1] = sum & 0xFF;
    return OK;
}


/***************************Funciones inicializacion implementadas*********************************/

/****************************************************************************************
 * Nombre: inicializarPilaEnviar                                                        *
 * Descripcion: inicializar la pila de red para enviar registrando los distintos modulos*
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t inicializarPilaEnviar() {
	bzero(protocolos_registrados,MAX_PROTOCOL*sizeof(pf_notificacion));
	if(registrarProtocolo(ETH_PROTO, moduloETH, protocolos_registrados)==ERROR)
		return ERROR;
	if(registrarProtocolo(IP_PROTO, moduloIP, protocolos_registrados)==ERROR)
		return ERROR;
	if(registrarProtocolo(UDP_PROTO, moduloUDP, protocolos_registrados)==ERROR)
		return ERROR;
	if(registrarProtocolo(ICMP_PROTO, moduloICMP, protocolos_registrados)==ERROR)
		return ERROR;


	return OK;
}


/****************************************************************************************
 * Nombre: registrarProtocolo                                                           *
 * Descripcion: Registra un protocolo en la tabla de protocolos                         *
 * Argumentos:                                                                          *
 *  -protocolo: Referencia del protocolo (ver RFC 1700)                                 *
 *  -handleModule: Funcion a llamar con los datos a enviar                              *
 *  -protocolos_registrados: vector de funciones registradas                            *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t registrarProtocolo(uint16_t protocolo, pf_notificacion handleModule, pf_notificacion* protocolos_registrados){
	if(protocolos_registrados==NULL ||  handleModule==NULL){
		printf("Error: registrarProtocolo(): entradas nulas.\n");
		return ERROR;
	}
	else
		protocolos_registrados[protocolo]=handleModule;
	return OK;
}
