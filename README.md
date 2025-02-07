# KAGESCANNER Ultimate

**KAGESCANNER Ultimate** est un outil de scan de ports et de découverte réseau avancé développé en Python.  
Il intègre de nombreuses fonctionnalités avancées telles que :

- **Scan TCP et UDP** avec banner grabbing pour identifier les versions des services.
- **Système de plugins** pour étendre et personnaliser l’analyse des résultats.
- **Interface graphique** avec Tkinter, organisée en onglets :
  - **Scan** : Lancer des scans de ports (avec option asynchrone pour TCP).
  - **Network Discovery** : Découverte d’hôtes sur un sous-réseau via un ping sweep parallélisé.
  - **Advanced Settings** : Personnalisation des paramètres (timeout, nombre de threads, mode furtif, configuration SMTP, etc.).
  - **API Control** : Démarrage et contrôle d’une API REST (basée sur Flask) avec authentification par clé API.
  - **Logs** : Visualisation en temps réel des logs générés par l’outil.
- **Export des résultats** sous plusieurs formats (CSV, JSON, XML, HTML).
- **Notifications par e-mail** en cas de détection de ports ouverts.
- **Support IPv4 et IPv6**.
- **Tests unitaires** intégrés pour valider certaines fonctionnalités clés.

> **Attention** : Ce programme doit être utilisé uniquement sur des machines et réseaux dont vous avez l'autorisation explicite. Toute utilisation non autorisée est illégale et relève de votre responsabilité.

---

## Prérequis

- **Python 3.7** ou version ultérieure.
- Les modules Python suivants (la plupart sont inclus dans la bibliothèque standard) :
  - `socket`, `asyncio`, `concurrent.futures`, `threading`, `queue`, `ipaddress`, `subprocess`, `csv`, `json`, `xml.etree.ElementTree`, `smtplib`, `email`, `logging`, `unittest`
  - **Tkinter** (inclus avec Python sur la plupart des distributions)
  - **Flask** (à installer via pip)

---

## Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/votre-utilisateur/kagescanner-ultimate.git
cd kagescanner-ultimate
