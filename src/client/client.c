/*
 * Ce programme contient des fonctions qui sont plus liées à l'interface
 * utilisateur du scanner plutôt qu'à son implémentation interne.
 */

#include "client.h" // Inclut les déclarations de fonctions propres au client
#include <arpa/inet.h> // Inclut les fonctions pour la manipulation des adresses IP
#include <netinet/in.h> // Inclut les définitions de structures pour les adresses IP
#include <stdio.h>      // Inclut les fonctions d'entrée/sortie standard
#include <stdlib.h> // Inclut les fonctions standard de gestion de la mémoire

// Définition des ports par défaut à scanner
int default_port_list[] = {80, 443}; // Liste des ports par défaut
int default_port_list_size = 2;      // Taille de la liste des ports par défaut

// Définition des options de ligne de commande
static struct option long_options[] = {
    {"help", no_argument, 0, 'h'}, // Option pour afficher l'aide
    {"ip", required_argument, 0,
     'i'}, // Option pour spécifier l'adresse IP à scanner
    {"netmask", required_argument, 0,
     'n'}, // Option pour spécifier la longueur du masque de sous-réseau
    {"ports", required_argument, 0,
     'p'}, // Option pour spécifier une liste de ports à scanner
    {"ports-range", required_argument, 0,
     'r'}, // Option pour spécifier une plage de ports à scanner
    {"try-hard", no_argument, 0, 't'}, // Option pour continuer à scanner même
                                       // si le premier port est inaccessible
    {0, 0, 0, 0} // Fin de la liste des options (obligatoire)
};

// Fonction principale du programme
int main(int argc, char const *argv[]) {
  // Déclaration des indicateurs de présence d'options
  bool address_flag = false; // Indique si l'adresse IP a été spécifiée
  bool netmask_flag =
      false; // Indique si la longueur du masque de sous-réseau a été spécifiée
  bool ports_flag =
      false; // Indique si une liste de ports à scanner a été spécifiée
  bool port_range_flag =
      false; // Indique si une plage de ports à scanner a été spécifiée
  bool lazy_flag = false; // Indique si l'option "try-hard" a été activée
  bool break_if_unreachable = true; // Indique si le scan doit s'arrêter si le
                                    // premier port est inaccessible

  // Déclaration des variables pour les options de ligne de commande
  int *ports_list = NULL;  // Liste des ports à scanner
  int ports_list_size = 0; // Taille de la liste des ports à scanner
  int ports_range_start;   // Début de la plage de ports à scanner
  int ports_range_stop;    // Fin de la plage de ports à scanner

  int opt;              // Variable pour stocker l'option analysée
  int option_index = 0; // Index de l'option actuellement analysée
  in_addr_t host_ip;    // Adresse IP à scanner
  int host_netmask_len; // Longueur du masque de sous-réseau

  // Analyse des options de ligne de commande
  opt = getopt_long(argc, (char *const *)argv, "hi:n:p:r:t", long_options,
                    &option_index);
  while (opt != -1) {
    switch (opt) {
    case 'h': { // Option pour afficher l'aide
      print_help_msg((char *)argv[0]);
      exit(EXIT_SUCCESS);
    }
    case 'i': { // Option pour spécifier l'adresse IP à scanner
      address_flag = true;
      int ip_parsing = inet_pton(AF_INET, optarg, &host_ip);
      if (ip_parsing < 1) {
        perror("Format d'adresse IP invalide.\n");
        exit(EXIT_FAILURE);
      }
      break;
    }
    case 'n': { // Option pour spécifier la longueur du masque de sous-réseau
      netmask_flag = true;
      host_netmask_len = atoi(optarg);
      break;
    }
    case 'p': { // Option pour spécifier une liste de ports à scanner
      ports_flag = true;
      optind--;
      for (; optind < argc && *argv[optind] != '-'; optind++) {
        ports_list_size++;
      }
      if (ports_list_size < 1) {
        perror("Veuillez entrer au moins 1 port.\n");
        exit(EXIT_FAILURE);
      }
      optind -= ports_list_size;
      ports_list = (int *)malloc(ports_list_size * (sizeof(int)));
      int index = 0;
      for (; optind < argc && *argv[optind] != '-'; optind++) {
        ports_list[index] = atoi(argv[optind]);
        index++;
      }
      break;
    }
    case 'r': { // Option pour spécifier une plage de ports à scanner
      port_range_flag = true;
      int input_count = 1;
      for (; optind < argc && *argv[optind] != '-'; optind++) {
        input_count++;
      }
      if (input_count != 2) {
        fprintf(stderr,
                "Veuillez fournir exactement 2 numéros de port pour l'argument "
                "--ports-range, %d "
                "ont été fournis.\n",
                input_count);
        exit(EXIT_FAILURE);
      }
      ports_range_start = atoi(argv[optind - 2]);
      ports_range_stop = atoi(argv[optind - 1]);
      if (ports_range_start > ports_range_stop) {
        fprintf(stderr, "Plage de ports invalide.\n");
        exit(EXIT_FAILURE);
      }
      ports_list_size = ports_range_stop - ports_range_start;
      break;
    }
    case 't': { // Option pour continuer à scanner même si le premier port est
                // inaccessible
      lazy_flag = true;
      break_if_unreachable = false;
      break;
    }
    default:
      abort();
    }
    opt = getopt_long(argc, (char *const *)argv, "hi:n:p:r:t", long_options,
                      &option_index);
  }

  // Vérification des options de ligne de commande
  if (!address_flag) {
    print_help_msg((char *)argv[0]);
    exit(EXIT_SUCCESS);
  }
  if (port_range_flag && ports_flag) {
    perror("Veuillez fournir soit une liste de ports, soit une plage de ports, "
           "pas les deux.\n");
    exit(EXIT_FAILURE);
  }

  // Affichage des informations d'entrée fournies par l'utilisateur
  if (address_flag) {
    if (netmask_flag) {
      // Affichage des informations d'entrée fournies par l'utilisateur
      if (address_flag) {
        if (netmask_flag) {
          char net_ip_p[INET_ADDRSTRLEN];
          in_addr_t net_ip = get_net_addr(host_ip, host_netmask_len);
          in_addr_t brd_ip = get_brd_addr(host_ip, host_netmask_len);
          inet_ntop(AF_INET, &net_ip, net_ip_p, INET_ADDRSTRLEN);
          char brd_ip_p[INET_ADDRSTRLEN];
          inet_ntop(AF_INET, &brd_ip, brd_ip_p, INET_ADDRSTRLEN);
          printf("Scannage des adresses IP de %s à %s \n", net_ip_p, brd_ip_p);
        } else {
          char ipStr[INET_ADDRSTRLEN];
          inet_ntop(AF_INET, &host_ip, ipStr, INET_ADDRSTRLEN);
          printf("IP scannée : %s, \n", ipStr);
        }
      }
      if (netmask_flag) {
        printf("Longueur du masque de sous-réseau : %d \n", host_netmask_len);
      }
      if (ports_flag) {
        printf("Scannage des ports :");
        for (int i = 0; i < ports_list_size; i++) {
          printf(" %d", ports_list[i]);
        }
        printf(", \n");
      }
      if (port_range_flag) {
        printf("Scannage des ports de %d à %d \n", ports_range_start,
               ports_range_stop);
      }
      if (lazy_flag) {
        printf("Essai-continu : %s \n",
               (break_if_unreachable ? "false" : "true"));
      }

      // Choix de la méthode de balayage en fonction des options fournies
      if (!port_range_flag && !ports_flag) {
        scan_network_default(host_ip, host_netmask_len, break_if_unreachable);
      }
      if (ports_flag) {
        scan_network(host_ip, host_netmask_len, ports_list, ports_list_size,
                     break_if_unreachable);
      }
      if (port_range_flag) {
        ports_list =
            (int *)malloc((ports_range_stop - ports_range_start) * sizeof(int));
        for (int port = ports_range_start; port < ports_range_stop; port++) {
          ports_list[port - ports_range_start] = port;
        }
        scan_network(host_ip, host_netmask_len, ports_list, ports_list_size,
                     break_if_unreachable);
      }

      // Libération de la mémoire allouée pour la liste des ports
      free(ports_list);

      return 0;
    }
  }
}

// Fonction pour afficher le message d'aide
void print_help_msg(char *name) {
  printf("Utilisation: %s [OPTIONS]\n", name);
  printf("Options:\n");
  printf("  -h, --help              Afficher ce message d'aide\n");
  printf("  -i, --input             Adresse IP à scanner\n");
  printf("  -n, --netmask           Longueur du masque de sous-réseau\n");
  printf("  -p, --ports             Liste des ports à scanner, par défaut : 80 "
         "et 443\n");
  printf("  -r, --ports-range       Plage de ports à scanner\n");
  printf("  -t  --try-hard          Continuer à scanner les autres ports même "
         "si le premier est inaccessible\n"); 
}

// Fonction pour balayer un réseau avec les ports par défaut
void scan_network_default(in_addr_t host_ip, int netmask_len,
                          bool stop_if_unreachable) {
  scan_network(host_ip, netmask_len, default_port_list, default_port_list_size,
               stop_if_unreachable);
}
