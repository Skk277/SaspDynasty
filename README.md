# SASP Tickets

Lancer en local : `npm install` puis `npm start` (http://localhost:3000).

## Mise en ligne
1. Envoyer ce dossier sur GitHub (le .gitignore exclut la base et les secrets).
2. Créer le service chez l'hébergeur (commande de démarrage : `npm start`), une seule instance.
3. Ajouter un volume monté sur `/data`.
4. Variables : `STAFF_ROLE_IDS` (obligatoire) et `DB_PATH=/data/sasp.db` (voir `.env.example`).
5. Portail Discord → OAuth2 → Redirects : ajouter `https://TON-SITE/` (identique à l'adresse du site, `/` final compris).
6. Tester, puis sauvegarder régulièrement `/data/sasp.db`.
