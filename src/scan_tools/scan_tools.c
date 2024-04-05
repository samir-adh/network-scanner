#include "scan_tools.h" // Inclure les outils de balayage personnalisés
#include <arpa/inet.h> // Inclure les fonctions pour la manipulation des adresses IP
#include <bits/getopt_core.h> // Inclure les fonctions pour le traitement des options en ligne de commande
#include <netinet/in.h> // Inclure les définitions de structures pour les adresses IP
#include <stdbool.h> // Inclure le type booléen et les valeurs true et false
#include <stdint.h>  // Inclure les types de données entiers de taille fixe
#include <stdio.h>   // Inclure les fonctions d'entrée/sortie standard
#include <stdlib.h>  // Inclure les fonctions standard de gestion de la mémoire

// Fonction pour obtenir l'adresse IP suivante dans le réseau
uint32_t get_next_ip(uint32_t current_ip) {
  return htonl(ntohl(current_ip) + 1); // Convertir l'adresse IP en réseau,
                                       // incrémenter et reconvertir en hôte
}

// Fonction pour balayer un réseau d'adresses IP et analyser les ports ouverts
void scan_network(in_addr_t host_ip, int netmask_len, int *ports_list,
                  int ports_list_size, bool break_if_unreachable) {
  // Calcul des limites du réseau à balayer
  in_addr_t start_ip = get_next_ip(get_net_addr(
      host_ip, netmask_len)); // Calculer l'adresse de début du réseau
  in_addr_t stop_ip = get_brd_addr(
      host_ip, netmask_len); // Calculer l'adresse de diffusion du réseau
  char ipStr[16];            // Pour stocker l'adresse IP en format texte
  if (DEBUG) {
    // Affichage des informations sur le réseau à balayer
    inet_ntop(AF_INET, &start_ip, ipStr,
              INET_ADDRSTRLEN); // Convertir l'adresse de début en format texte
    fprintf(stdout, "Balayage du réseau de %s ",
            ipStr); // Afficher l'adresse de début du réseau
    inet_ntop(
        AF_INET, &stop_ip, ipStr,
        INET_ADDRSTRLEN); // Convertir l'adresse de diffusion en format texte
    fprintf(stdout, "à %s\n",
            ipStr); // Afficher l'adresse de diffusion du réseau
    fprintf(stdout, "Début : %d, Fin : %d, ", ntohl(start_ip),
            ntohl(stop_ip)); // Afficher les adresses de début et de fin en
                             // format décimal
  }
  // Affichage du nombre d'adresses IP à balayer
  fprintf(stdout, "%d hôtes à balayer\n",
          ntohl(stop_ip) - ntohl(start_ip)); // Calculer et afficher le nombre
                                             // d'adresses IP dans le réseau
  // Boucle de balayage de chaque adresse IP dans le réseau
  for (in_addr_t ip = start_ip; ntohl(ip) < ntohl(stop_ip);
       ip = get_next_ip(ip)) { // Itérer sur chaque adresse IP dans le réseau
    // Analyse de l'adresse IP actuelle
    int scan_address_res = scan_address(
        ip, ports_list, ports_list_size,
        break_if_unreachable); // Analyser les ports de l'adresse IP actuelle
    if (DEBUG) {
      // Affichage de l'adresse IP en cours de balayage
      inet_ntop(AF_INET, &ip, ipStr,
                INET_ADDRSTRLEN); // Convertir l'adresse IP en format texte
      fprintf(stdout, "Balayage : %s\n",
              ipStr); // Afficher l'adresse IP en cours de balayage
      // Affichage si l'hôte est en ligne
      if (scan_address_res == 0 || scan_address_res == 1) {
        fprintf(stdout, "Hôte %s est en ligne\n",
                ipStr); // Afficher si l'hôte est en ligne
      }
    }
  }
}

// Fonction pour balayer un seul hôte et analyser les ports ouverts
int scan_address(in_addr_t host_ip, int *ports_list, int ports_list_size,
                 bool stop_if_unreachable) {
  // Configuration de l'adresse de l'hôte à balayer
  struct sockaddr_in host_address; // Structure pour l'adresse de l'hôte
  bzero(
      (char *)&host_address,
      sizeof(
          host_address)); // Initialiser à zéro la structure d'adresse de l'hôte
  host_address.sin_family = AF_INET; // Spécifier la famille d'adresses (IPv4)
  host_address.sin_addr.s_addr = host_ip; // Spécifier l'adresse IP de l'hôte
  int result;
  char *ip_p = (char *)malloc(
      256 * sizeof(char)); // Buffer pour stocker l'adresse IP en format texte
  inet_ntop(AF_INET, &host_ip, ip_p,
            INET_ADDRSTRLEN); // Convertir l'adresse IP en format texte
  // Boucle pour balayer chaque port de l'hôte
  for (int index = 0; index < ports_list_size; index++) {
    int port = ports_list[index]; // Obtenir le port à balayer
    if (DEBUG) {
      // Affichage des informations sur le port en cours de balayage
      fprintf(stdout, "Balayage %s:%d...\n", ip_p,
              port); // Afficher le port en cours de balayage
    }
    // Analyse du port
    int scan_result =
        scan_port(&host_address, port); // Analyser le port de l'hôte
    if (scan_result == 0) {
      fprintf(stdout, "Hôte %s:%d est en ligne\n", ip_p,
              port); // Afficher si le port est ouvert
      result = 0;
    } else if (scan_result == 1) {
      if (DEBUG) {
        fprintf(stdout, "Hôte %s:%d a refusé la connexion\n", ip_p,
                port); // Afficher si la connexion est refusée
      }
      result = 1;
    } else if (scan_result == 2) {
      if (DEBUG) {
        fprintf(stdout, "Hôte %s:%d est inaccessible\n", ip_p,
                port); // Afficher si l'hôte est inaccessible
      }
      result = 2;
      if (stop_if_unreachable) { // Vérifier s'il faut arrêter si l'hôte est
                                 // inaccessible
        break; // Arrêter le balayage si l'hôte est inaccessible
      }
    } else {
      fprintf(stdout, "Balayage de l'hôte %s:%d a retourné errno %d\n ", ip_p,
              port, scan_result); // Afficher si une erreur s'est produite lors
                                  // du balayage
    }
  }
  free(ip_p);    // Libération de la mémoire allouée pour ip_p
  return result; // Retourner le résultat du balayage de l'hôte
}

/* Fonction qui envoie une requête de connexion TCP, renvoie :
 * 0 si la connexion est acceptée,
 * 1 si elle est refusée,
 * 2 si le délai d'attente dépasse TIMEOUT
 */
int scan_port(struct sockaddr_in *host_address, int port) {
  // Création d'une socket pour le balayage
  int scanner_socket = socket(AF_INET, SOCK_STREAM, 0); // Créer une socket TCP
  // Configuration du timeout pour la connexion
  struct timeval tv;    // Structure pour spécifier le timeout
  tv.tv_sec = 0;        // Spécifier les secondes du timeout
  tv.tv_usec = TIMEOUT; // Spécifier les microsecondes du timeout
  setsockopt(scanner_socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv,
             sizeof tv); // Paramétrer le timeout pour la socket
  int result;
  if (scanner_socket < 0) {
    perror("Erreur de socket\n"); // Afficher une erreur si la création de la
                                  // socket échoue
    exit(EXIT_FAILURE); // Quitter le programme en cas d'échec de la création de
                        // la socket
  }
  // Configuration du port à balayer
  host_address->sin_port =
      htons(port); // Spécifier le port à scanner dans la structure d'adresse
  // Tentative de connexion au port
  int conn_status =
      connect(scanner_socket, (struct sockaddr *)host_address,
              sizeof(struct sockaddr)); // Tenter de se connecter au port
  if (conn_status == 0)                 // Le port est ouvert
  {
    result = 0; // Définir le résultat à 0 pour indiquer que la connexion est
                // acceptée
  } else if (errno == 111) /* Connexion refusée */ {
    result =
        1; // Définir le résultat à 1 pour indiquer que la connexion est refusée
  } else if (errno == 115) /* Connexion avortée */ {
    result = 2; // Définir le résultat à 2 pour indiquer que la connexion a été
                // avortée
  } else {
    result = errno; // Renvoyer le code d'erreur système si la connexion échoue
                    // pour une autre raison
  }
  shutdown(scanner_socket, SHUT_RDWR); // Fermeture de la socket
  close(scanner_socket);               // Fermeture de la connexion
  return result; // Retourner le résultat du balayage du port
}

/* Fonction pour déterminer l'adresse réseau à partir de l'adresse ip et du
 * netmask_len */
in_addr_t get_net_addr(in_addr_t host_ip, int netmask_len) {
  // Calcul de l'adresse réseau à partir de l'adresse IP et de la longueur du
  // masque de sous-réseau
  uint32_t host_ip_hl = ntohl(host_ip); // Convertir l'adresse IP en format hôte
  uint32_t uint_netmask_len =
      (uint32_t)(~0) << (32 - netmask_len); // Calculer le masque de sous-réseau
  uint32_t net_addr =
      host_ip_hl &
      uint_netmask_len; // Appliquer le masque de sous-réseau à l'adresse IP
  return (in_addr_t)htonl(
      net_addr); // Convertir l'adresse réseau en format réseau et la retourner
}

/* Fonction pour déterminer l'adresse de diffusion à partir de l'adresse IP et
 * du netmask_len */
in_addr_t get_brd_addr(in_addr_t host_ip, int netmask_len) {
  // Calcul de l'adresse de diffusion à partir de l'adresse IP et de la longueur
  // du masque de sous-réseau
  uint32_t host_ip_hl = ntohl(host_ip); // Convertir l'adresse IP en format hôte
  uint32_t uint_netmask_len =
      ((uint32_t)(~0) >>
       netmask_len); // Calculer le masque de sous-réseau complémenté
  uint32_t brd_addr =
      (host_ip_hl | uint_netmask_len); // Appliquer le masque de sous-réseau
                                       // complémenté à l'adresse IP
  return (in_addr_t)htonl(brd_addr);   // Convertir l'adresse de diffusion en
                                       // format réseau et la retourner
}
