# Agent Guard

Service Linux indépendant pour limiter les travaux locaux lancés par Codex et Claude. Aucun wrapper ou instruction aux agents. Python 3.12 standard, systemd 255, cgroups v2 et proc connector.

## Politique

- Reconnaissance des exécutables réellement installés, filiation vérifiée par `/proc`, événements `fork/exec/exit` lus par un thread dédié avec tampon borné, réconciliation complète toutes les 30 secondes.
- Identité = PID + instant de création, avec état associé au démarrage du noyau. Les noms `node` ou `MainThread` ne prouvent jamais l’origine.
- Un groupe par travail. Budget partagé des travaux : **15 Gio de mémoire PSS**. Le plafond CPU de **50 %** porte sur le groupe parent commun aux agents suivis, helpers et travaux : leurs enfants l'héritent dès le fork, avant toute classification. Un quota de temps CPU est complété par un `cpuset` limité à la moitié des processeurs logiques (8 sur 16), pour empêcher une utilisation simultanée de tous les processeurs. Le nombre de processeurs est arrondi vers le bas, avec un minimum de un ; les fractions inférieures à un processeur restent limitées par le quota temporel.
- Les processus agents, composants MCP/stdio/code-mode et runtimes de plugins reconnus sont protégés des arrêts mémoire et hors budget mémoire des travaux. Ils partagent le plafond CPU. Les helpers inconnus peuvent nécessiter d’étendre la fonction `is_helper` ; vérifier l’inventaire après ajout d’un nouvel outil.
- Le texte d'une commande shell `-c` n'est pas une preuve qu'il s'agit d'un helper : un préambule qui mentionne un plugin ne doit pas exclure les tests du quota. Les vrais helpers sont reconnus lors de leur exécution. Une mise à jour récupère les anciennes exclusions de ce type uniquement lorsque la filiation avec l'agent vivant est vérifiable ; les travaux récupérés restent protégés des arrêts mémoire.
- **Tous les travaux présents à l’activation sont protégés des arrêts mémoire automatiques**, avec protection persistante après redémarrage du service et propagée à leurs descendants. Le quota CPU s’applique aussi à ces travaux.
- **60 secondes d’observation au démarrage du service**, puis 3 mesures complètes consécutives au-dessus du budget. Ce n’est pas une attente de 60 secondes par nouveau travail.
- Arrêt du travail nouveau éligible le plus récent, au moins 64 Mio PSS. Un seul arrêt à la fois, au moins 10 secondes entre décisions. TERM, puis KILL après 3 secondes si nécessaire.
- Avant chaque signal : groupe brièvement gelé, membres et exécutables revérifiés, identité liée à un pidfd. Un agent/helper/membre inconnu provoque l’annulation de l’action. Le journal est écrit et synchronisé avant les signaux. Pas de `pkill`, pas de signal par nom ou PID non vérifié, pas de `cgroup.kill` récursif.
- Une migration ambiguë ou interrompue met le groupe en quarantaine ; les marqueurs de migration sont persistés avant toute écriture. Une mesure incomplète ou une perte d’événement suspend les nouvelles décisions mémoire.

Le budget mémoire est un **seuil de surveillance**, pas un `MemoryMax` global strict : ce dernier autoriserait le noyau à choisir une victime. Un dépassement bref est possible. Si seuls des travaux protégés dépassent le seuil, le service le signale et ne tue personne. La mesure PSS voit aussi les pages allouées avant déplacement dans un cgroup ; le swap est affiché séparément et n’est pas plafonné par cette version. Les limites CPU sont imposées par le noyau : [documentation `cpu.max` et `cpuset`](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html).

## Anciens orphelins

Un processus déjà connu conserve son attribution après disparition du parent. Un enfant dans un groupe de travail root-owned déjà enregistré retrouve son appartenance. Un orphelin inconnu dans un groupe de contrôle reste protégé, car il pourrait appartenir à un composant MCP.

Les anciens processus dont l’origine est seulement suggérée par un fichier `/tmp/claude-UID/...` sont des **candidats signalés**, jamais des victimes automatiques. Le départ d’un agent ne suffit pas à prouver qu’un serveur de développement doit être arrêté. Les vrais zombies (état Z) sont déjà terminés et ne sont pas ciblés.

## Vérification et installation

```bash
git clone https://github.com/AlexMog/agent-guard.git
cd agent-guard
python3 -m unittest discover -s tests -v
python3 -m agent_guard audit --uid "$(id -u)" --orphans
```

Test noyau isolé, uniquement sur les processus enfants du test :

```bash
systemd-run --user --unit=agent-guard-integration-test.service --collect \
  -p Delegate=yes -p RuntimeMaxSec=30 --wait --pipe \
  /usr/bin/python3 "$PWD/tests/integration_cgroups.py" --run
```

Test supplémentaire du plafond CPU partagé, dans un service root temporaire (héritage dans `control`, quota commun avec `work`, tentative d'élargissement d'affinité et restauration) :

```bash
sudo systemd-run --unit=agent-guard-cpu-test.service --collect --wait --pipe \
  -p Delegate=yes -p RuntimeMaxSec=30 \
  /usr/bin/python3 "$PWD/tests/integration_cpu_boundary.py" --run
```

Installer puis activer les nouveaux travaux (les tests d’événements root et un démarrage en observation précèdent automatiquement l’activation) :

```bash
sudo /usr/bin/python3 ./install.py --uid "$(id -u)" --enforce-new
```

Omettre `--enforce-new` pour installer en observation uniquement : aucun rattachement, quota CPU ou signal. L’installateur refuse d’écraser une installation existante. L’authentification peut aussi être fournie par `pkexec`.

## Utilisation

```bash
agent-guard status
agent-guard explain 12345
agent-guard audit --uid "$(id -u)" --orphans
journalctl -u agent-guard.service
sudo systemctl stop agent-guard.service
```

`status` indique le mode, l’état des événements, les groupes, les protections initiales, les quarantaines et l’âge du rapport. `explain` retrouve les raisons d’arrêt et les identités concernées dans les journaux rotatifs. Un signal Unix ne peut pas porter automatiquement cette explication à la sortie standard de l’agent ; elle reste consultable sans modifier l’agent.

Configuration root : `/etc/agent-guard.json`. Après modification, `sudo systemctl restart agent-guard.service`. `mode: "observe"` désactive les interventions. Pour activer après observation, mettre `mode: "enforce"` ; les travaux alors en cours deviennent protégés. L’arrêt normal du superviseur retire le quota CPU, dégèle les groupes et laisse les travaux vivants. `DelegateSubgroup=supervisor` et `KillMode=process` permettent le redémarrage sans arrêter les processus adoptés.

État et journaux : `/var/lib/agent-guard/`, fichiers root non modifiables par les agents, sans arguments bruts ni variables d’environnement. Les journaux tournent sur trois fichiers d’environ 2 Mio ; l’état garde au plus 256 travaux terminés plus les travaux vivants.

## Mise à jour / désactivation

Pour désactiver durablement : `sudo systemctl disable --now agent-guard.service`. Les fichiers peuvent rester en place pour conserver les diagnostics. Ne pas supprimer les cgroups encore peuplés ni effacer l’état : il contient les protections des travaux existants. Pour mettre à jour, arrêter le service, remplacer uniquement les fichiers de code root-owned et l’unité, exécuter `systemctl daemon-reload`, puis redémarrer ; conserver le fichier de configuration et l’état.

L’installateur fournit aussi `sudo python3 install.py --update`, qui reteste les événements, arrête le superviseur, remplace le code et l’unité puis redémarre, sans effacer configuration ni état.

Le rattachement à un cgroup système peut modifier l’association de la session utilisée par Polkit : `pkexec` exécuté depuis un agent suivi peut ne plus trouver son agent d’authentification graphique. Depuis un terminal utilisateur non suivi, l’authentification reste disponible. Pour une commande d’administration initiée par l’agent, un exemple vérifié est :

```bash
systemd-run --user --unit=agent-guard-admin-restart --collect --wait --pipe \
  /usr/bin/pkexec --disable-internal-agent /usr/bin/systemctl restart agent-guard.service
```

Cette commande demande toujours l’authentification administrateur habituelle.

## Limites connues

- La première détection d'un nouvel agent reste postérieure à son lancement. Une fois l'agent rattaché, tous ses descendants héritent immédiatement du plafond CPU, même avant leur classement comme travaux. Les événements ne sont pas un mécanisme de blocage avant exécution ; aucune file d’attente transparente n’est promise.
- Le daemon n’attribue pas rétroactivement avec certitude un processus antérieur au suivi dont tous les parents ont disparu.
- Docker, exécution distante et commandes déléguées à un service externe ne sont pas couverts automatiquement.
- Les agents disposant eux-mêmes de privilèges root ne peuvent pas être contraints par ce service. Le reconnaisseur prend en charge Claude installé sous `~/.local/share/claude/versions/` et Codex installé via npm sous NVM, pour des comptes sous `/home/`. Les autres emplacements nécessitent une adaptation de `is_agent` dans `agent_guard/model.py`.
- La migration Linux utilise encore un PID numérique. Des vérifications avant/après et un journal transactionnel mettent tout résultat ambigu en quarantaine ; les signaux utilisent exclusivement des pidfds pour éviter de cibler un PID réutilisé.
- Ce service n’est pas un outil de nettoyage automatique des vieux serveurs. Les cas douteux restent visibles et protégés.
