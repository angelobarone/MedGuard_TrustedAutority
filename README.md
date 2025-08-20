# MedGuard - Thrusted Authority

La Thrusted Authority o **Key Server** è il modulo del progetto **MedGuard** che gestisce la distribuzione delle chiavi di cifratura e decifratura:

- Fornisce la **chiave pubblica** ai client (ospedali)
- Permette ai client autorizzati (ricercatori) di usare la **chiave privata** per decifrare i risultati aggregati

## 🚀 Tecnologie
- **Python 3**
- **Flask** + **Flask-CORS**
- **PyCryptodome** (AES)
- **Implementazione Paillier** (cifratura omomorfica)
- **SQLite** (gestione utenti)

## ⚙️ Funzionalità principali
- Generazione automatica di una coppia di chiavi Paillier (pubblica e privata) all’avvio del server
- Distribuzione della chiave pubblica ai client autorizzati
- Fornitura della chiave privata cifrata solo agli utenti con token valido
- Creazione di utenti autorizzati tramite endpoint dedicato
- Generazione di token temporanei per l’autenticazione dei client
- API RESTful con supporto a richieste JSON
- Protezione della chiave privata tramite cifratura AES-GCM durante il trasferimento

## 📚 Note
- Questo modulo è pensato a scopo didattico: la gestione di chiavi e autenticazione è semplificata.
- La cifratura AES-GCM garantisce integrità e confidenzialità della chiave privata durante il trasferimento.
