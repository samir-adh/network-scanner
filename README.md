# Network Scanner

## TO-DO List

### Importance élevée

- [X] Accepter les arguments en ligne de commande
- [X] Support pour netmask -> Mettre la première IP à "zéro"
- [X] Traîter les arguments en ligne de commande
  - [X] Scanner le réseau associé à une adresse IP
  - [X] Spécifier les ports à scanner
  - [X] Scanner une IP spécifique
- [X] Itérer correctement sur les adresses IP
- [X] Fonction qui scanne une liste de ports

### Importance moyenne

- [X] Exclure les addresse réservées (ex: 192.168.31.0 et 192.168.31.255)
- [X] Scan d'adresse part défaut sur les port 80, 443
- [X] Commenter le code (tester ce que ça donne avec ChatGPT)
- [ ] Retourner des listes pour le resultat
- [ ] Ecrire un rapport de scan

### Importance faible

- [ ] Option pour régler le timeout
- [ ] Multi-process
- [ ] Fonction ping_address
- [X] Fix l'erreur avec "0.0.0.0"
- [ ] Ecrire les resultats du scan dans un JSON
