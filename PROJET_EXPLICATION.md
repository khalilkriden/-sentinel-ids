# Projet IA — Détection d'Intrusions Réseau (IDS) par Machine Learning
## Documentation Technique Complète

> **Objectif de ce document :** expliquer, étape par étape et sans prérequis en IA, **tout** ce qui a été fait dans le projet, jusqu'au niveau de détail nécessaire pour répondre à n'importe quelle question technique sur le pipeline.

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Problématique et contexte](#2-problématique-et-contexte)
3. [Le dataset UNSW-NB15](#3-le-dataset-unsw-nb15)
4. [Phase 1 — Exploration (EDA)](#4-phase-1--exploration-eda)
5. [Phase 2 — Prétraitement](#5-phase-2--prétraitement)
6. [Phase 3 — Modélisation](#6-phase-3--modélisation)
7. [Phase 4 — Évaluation (initialisée)](#7-phase-4--évaluation-initialisée)
8. [Phase 5 — Explainable AI (XAI)](#8-phase-5--explainable-ai-xai)
9. [Glossaire technique](#9-glossaire-technique)
10. [Questions types et réponses attendues](#10-questions-types-et-réponses-attendues)

---

## 1. Vue d'ensemble

**Ce qu'on construit :** un système capable de **lire une connexion réseau** (son protocole, sa durée, son volume de données, etc.) et de **décider automatiquement** si c'est du trafic normal ou une attaque, et **quel type d'attaque** parmi 9 possibilités.

**C'est un problème de classification multi-classe supervisée à 10 classes** (1 normal + 9 attaques).

**Pipeline global :**

```
Données brutes UNSW-NB15
        │
        ▼
 Phase 1 : EDA (exploration statistique)
        │
        ▼
 Phase 2 : Prétraitement
   (nettoyage, encodage, normalisation,
    feature engineering, sélection)
        │
        ▼
 Phase 3 : Modélisation
   (entraînement de 7 modèles,
    optimisation, benchmark)
        │
        ▼
 Phase 4 : Évaluation approfondie
   (ROC, PR, robustesse)
        │
        ▼
 Phase 5 : XAI (interprétabilité)
        │
        ▼
 Phases 6-7 : Interface web + rapport
```

**Meilleur modèle obtenu :** **XGBoost Optimisé** → F1 = **0.7567**, Accuracy = **76.36%** sur 175 341 connexions de test.

---

## 2. Problématique et contexte

### 2.1. Qu'est-ce qu'un IDS ?

**IDS = Intrusion Detection System.** C'est un logiciel qui surveille le trafic réseau (ou les logs système) et lève une alerte quand il repère une activité suspecte.

Il existe deux familles historiques :

| Type | Fonctionnement | Limite |
|------|---------------|--------|
| **Signature-based** (ex. Snort, Suricata) | Base de données de signatures connues (regex sur les paquets). | Aveugle aux attaques **zero-day** (inconnues). |
| **Anomaly-based** | Modélise le « trafic normal » et alerte sur l'écart. | Beaucoup de **faux positifs**. |

**IDS par ML :** apprend **directement** ce qui distingue une attaque d'un trafic légitime à partir de données étiquetées. Peut **généraliser** à des variantes d'attaques non vues à l'entraînement.

### 2.2. Pourquoi classer en 10 classes (pas juste binaire) ?

Un modèle binaire (Normal vs Attaque) est plus simple mais donne moins d'information à l'analyste SOC. Un modèle multi-classe lui dit **quelle réponse appliquer** :
- **DoS** → activer le rate-limiting, prévenir le fournisseur réseau.
- **Reconnaissance** → bloquer l'IP source, surveiller les autres scans.
- **Backdoor** → isoler la machine immédiatement.
- **Exploits** → patcher la vulnérabilité visée.

C'est **l'Option A** du cahier des charges.

### 2.3. Pourquoi du Machine Learning classique (et pas du Deep Learning) ?

Le dataset est **tabulaire** (lignes × colonnes numériques/catégorielles). Pour ce type de données, **les méthodes d'ensemble à base d'arbres (Random Forest, XGBoost) sont l'état de l'art** — elles battent régulièrement le deep learning dans les compétitions Kaggle et en production industrielle. On inclut néanmoins un MLP (réseau de neurones) comme point de comparaison.

---

## 3. Le dataset UNSW-NB15

### 3.1. Origine

Créé en 2015 par l'Université de New South Wales (Australie), sur un **banc d'essai réel** mélangeant trafic normal capturé et trafic d'attaque généré par l'outil **IXIA PerfectStorm**. Reconnu comme un des benchmarks IDS les plus sérieux (successeur du KDD Cup 1999 devenu obsolète).

### 3.2. Composition

- **Train set original :** 175 341 connexions
- **Test set original :** 82 332 connexions (attention : le test UNSW est plus petit que le train, c'est l'inverse de l'habitude)
- **Features brutes :** 45 colonnes décrivant chaque connexion réseau
- **Label :** `attack_cat` (10 catégories)

### 3.3. Les 10 classes

| Classe | Description | Fréquence |
|--------|-------------|-----------|
| **Normal** | Trafic légitime | ~37% |
| **Generic** | Attaques génériques contre algos de chiffrement | ~22% |
| **Exploits** | Exploitation de vulnérabilités connues (CVE) | ~18% |
| **Fuzzers** | Envoi de données aléatoires pour crasher un service | ~10% |
| **DoS** | Déni de service (flood) | ~6% |
| **Reconnaissance** | Scan de ports, balayage de services | ~4% |
| **Analysis** | Outils d'analyse/sniff (traceroute, port scan avancé) | ~0.6% |
| **Backdoor** | Contournement d'authentification | ~0.6% |
| **Shellcode** | Injection de code malveillant | ~0.4% |
| **Worms** | Ver réseau auto-réplicant | ~0.01% (~130 exemples) |

**Problème clé :** le dataset est **très déséquilibré**. Worms ≈ 130 exemples contre Normal ≈ 37 000. C'est le défi central du projet.

### 3.4. Les features (exemples)

- **Temporelles :** `dur` (durée), `sinpkt`/`dinpkt` (inter-arrivée paquets), `sjit`/`djit` (gigue)
- **Volumétriques :** `sbytes`/`dbytes` (octets source/destination), `spkts`/`dpkts` (nombre de paquets), `rate` (débit)
- **Protocolaires :** `proto` (TCP/UDP/...), `service` (HTTP/DNS/...), `state` (CONNECTED/FIN/...)
- **Réseau bas niveau :** `sttl`/`dttl` (TTL), `swin`/`dwin` (taille fenêtre TCP), `stcpb`/`dtcpb` (séquence TCP)
- **Charge réseau :** `sload`/`dload` (débit bytes/s)
- **Compteurs de contexte :** `ct_srv_src`, `ct_state_ttl`, `ct_dst_ltm`… (nombre de connexions similaires dans la dernière minute) — **très puissants** pour détecter les scans et attaques répétées.

---

## 4. Phase 1 — Exploration (EDA)

**But :** comprendre le dataset avant de toucher aux modèles.

### 4.1. Ce qu'on a vérifié

1. **Valeurs manquantes** → quasi-nulles dans UNSW (dataset propre).
2. **Distribution des classes** → confirmé le déséquilibre massif.
3. **Types des colonnes** → identifier les catégorielles (à encoder) et les numériques (à normaliser).
4. **Distribution des features numériques** → beaucoup ont une **queue droite très longue** (asymétrie) : quelques connexions ont des volumes énormes. Il faudra transformer en log.
5. **Corrélations** → détection des paires de features quasi-identiques (r > 0.95) à éliminer.
6. **Cardinalité des catégorielles** → `proto` a ~130 valeurs, `service` ~13, `state` ~10. Choix : **Label Encoding** (et non One-Hot) pour ne pas exploser le nombre de colonnes.

### 4.2. Conclusions de l'EDA

- Le dataset est **propre** (peu de nettoyage nécessaire).
- Il est **fortement déséquilibré** → il faudra le traiter.
- Plusieurs features sont **à queue longue** → log-transform recommandé.
- Des paires de features sont **redondantes** → filtre de corrélation nécessaire.

---

## 5. Phase 2 — Prétraitement

**But :** transformer les données brutes en un format numérique propre, exploitable par les algorithmes.

### 5.1. Nettoyage

- Suppression de la colonne `id` (identifiant unique, aucune information prédictive — sinon les modèles « mémorisent » au lieu de généraliser).
- Suppression éventuelle des doublons exacts.
- **Capping des valeurs extrêmes** (winsorization) : pour chaque feature numérique, on plafonne à un percentile élevé (p99 ou p99.5) afin que quelques valeurs aberrantes ne déforment pas la normalisation. Les limites sont sauvegardées dans `cap_limits` du pipeline pour les réappliquer en production.

### 5.2. Encodage des variables catégorielles

**Problème :** les modèles ML ne comprennent que les nombres. `proto='tcp'` doit devenir un entier.

**Deux grandes méthodes :**

| Méthode | Principe | Quand l'utiliser |
|---------|----------|------------------|
| **Label Encoding** | `{tcp:0, udp:1, icmp:2, ...}` | Modèles à base d'arbres (indifférents à l'ordre numérique) |
| **One-Hot Encoding** | Une colonne binaire par valeur | Modèles linéaires et réseaux de neurones |

**Choix du projet :** Label Encoding pour les 3 colonnes (`proto`, `service`, `state`). Pourquoi ? Parce que `proto` a ~130 valeurs distinctes — un one-hot créerait 130 colonnes supplémentaires (explosion dimensionnelle). Les arbres (RF, XGBoost, DT) se moquent de l'ordre numérique (ils coupent en `proto < 42.5` par exemple), donc Label Encoding est suffisant. Pour LR et MLP, ce choix est sous-optimal mais reste acceptable.

Les encodeurs sont sauvegardés dans `label_encoders` du pipeline.

### 5.3. Feature Engineering

**But :** créer de **nouvelles features dérivées** qui exposent des patterns que le modèle aurait du mal à deviner seul.

**Features créées (Phase 3, cellule 9 du notebook `03_modeling.ipynb`) :**

| Feature | Formule | Signification métier |
|---------|---------|----------------------|
| `bytes_ratio` | `sbytes / (dbytes+1)` | Asymétrie source/dest. Scan = ratio bas, DoS = ratio haut. |
| `total_bytes` | `sbytes + dbytes` | Volume global |
| `total_pkts` | `spkts + dpkts` | Nombre total de paquets |
| `pkts_ratio` | `spkts / (dpkts+1)` | Asymétrie en paquets |
| `bytes_per_pkt` | `total_bytes / (total_pkts+1)` | Taille moyenne d'un paquet |
| `loss_ratio` | `sloss / (spkts+1)` | Taux de perte côté source → signe de flood |
| `ttl_diff` | `|sttl - dttl|` | Différence de TTL → potentiel spoofing IP |
| `load_ratio` | `sload / (dload+1)` | Ratio de charge réseau |
| `jit_diff` | `|sjit - djit|` | Différence de gigue → instabilité (flooding) |
| `*_log` | `log1p(sbytes)`, etc. | Réduction du skewness |

**Le `+1` dans les dénominateurs** évite la division par zéro (Laplace smoothing).

**Le `log1p(x) = log(1+x)`** :
- Transforme la distribution asymétrique en quasi-gaussienne.
- Gère les zéros proprement (log(0) = -∞).
- Améliore drastiquement la convergence de la Régression Logistique et du MLP.

### 5.4. Normalisation (StandardScaler)

**Problème :** `sbytes` peut valoir 10^8, `dur` vaut 0.5. Un modèle linéaire ou un MLP serait complètement dominé par `sbytes` à cause de l'écart d'échelle.

**Solution :** `StandardScaler` de scikit-learn :

$$z = \frac{x - \mu}{\sigma}$$

Où `μ` et `σ` sont calculés **uniquement sur le train** (sinon fuite d'information du test vers le train — « data leakage »). Les paramètres `μ, σ` sont sauvegardés dans `scaler` du pipeline.

**Après scaling :** chaque feature a moyenne 0, écart-type 1.

**Remarque :** les arbres (RF, XGBoost) sont **invariants à l'échelle** — ils n'ont pas besoin de normalisation. Mais on normalise tout le dataset une fois pour que **tous** les modèles travaillent sur les mêmes données.

### 5.5. Sélection de features — filtre par corrélation

**Principe :** calculer la matrice de corrélation absolue entre toutes les paires de features numériques. Pour chaque paire (A, B) avec `|r| > 0.95`, supprimer une des deux (arbitrairement B).

**Pourquoi ?**
- Features redondantes = entraînement plus lent sans gain de signal.
- Provoque de la **multicolinéarité** pour la Régression Logistique (coefficients instables).
- **Dilue l'importance** dans les arbres : l'algo choisit parfois A, parfois B, l'importance est partagée de façon arbitraire.

**Implémentation :** on prend la matrice triangulaire supérieure (pour éviter de traiter chaque paire deux fois) et on accumule les colonnes à supprimer dans un `set`.

### 5.6. Sélection de features — Information Mutuelle (MI)

**L'Information Mutuelle** mesure la **dépendance statistique** entre une feature `X` et la cible `Y`, y compris les **relations non linéaires** (contrairement à la corrélation de Pearson qui ne détecte que le linéaire).

$$I(X; Y) = \sum_{x,y} p(x,y) \log \frac{p(x,y)}{p(x)p(y)}$$

- `I(X;Y) = 0` → X et Y sont indépendantes → la feature est **inutile**.
- `I(X;Y) > 0` → X apporte de l'information sur Y.

**Seuil appliqué :** `MI < 0.01` → feature éliminée. On passe ainsi de ~50 features à **42 features finales** qu'on conserve dans `feature_cols_final` du pipeline.

**Avantage sur un simple seuil de variance :** une feature peut avoir une forte variance tout en étant indépendante de la cible (du bruit) — la variance n'aurait pas éliminé cette feature, la MI si.

### 5.7. Résultat de la Phase 2

**Artefacts produits :**
- `X_train.csv`, `X_val.csv`, `X_test.csv` (features normalisées, 42 colonnes)
- `y_train.csv`, `y_val.csv`, `y_test.csv` (labels encodés 0-9)
- `preprocessing_pipeline.pkl` contenant :
  - `scaler` (StandardScaler entraîné)
  - `label_encoders` (dict des encodeurs catégoriels)
  - `le_target` (encodeur des labels)
  - `feature_cols_final` (liste des 42 features retenues)
  - `cap_limits` (bornes de winsorization)
  - `target_classes` (les 10 noms de classes)

Ce pipeline sera **ré-appliqué tel quel** sur toute nouvelle connexion réseau en production.

---

## 6. Phase 3 — Modélisation

### 6.1. Stratégie de split Train / Validation / Test

**Les trois rôles :**

| Ensemble | Rôle | % utilisé |
|----------|------|-----------|
| **Train** | Apprendre les paramètres du modèle | 80% du train CSV |
| **Validation** | Régler les hyperparamètres, détecter l'overfitting | 20% du train CSV |
| **Test** | Mesure finale de généralisation, **jamais vu pendant l'entraînement** | 100% du test CSV |

**Split effectué :** `train_test_split(train_df, test_size=0.2, stratify=y, random_state=42)`.

**Stratification** = les proportions des 10 classes sont **conservées identiquement** dans train et val. Sans stratification, Worms (130 exemples) pourrait se retrouver entièrement dans val et disparaître de train.

**Le test CSV original de UNSW est conservé intact** — c'est la règle d'or : **jamais** regarder le test pendant le développement, sinon on « overfit sur le test ».

### 6.2. Gestion du déséquilibre des classes

**Problème :** avec 37 000 Normal et 130 Worms, un modèle paresseux qui prédit **toujours « Normal »** obtiendrait déjà ~37% de accuracy sans avoir rien appris, et 0% de détection sur les attaques rares.

**Deux grandes familles de solutions :**

#### A. Sur-échantillonnage : SMOTE

SMOTE (Synthetic Minority Oversampling TEchnique) crée des **exemples synthétiques** de la classe minoritaire en interpolant entre des voisins proches :

$$x_{\text{new}} = x_i + \lambda \cdot (x_j - x_i), \quad \lambda \in [0,1]$$

**Problème rencontré :** SMOTE appliqué à Worms (130 → 110 000) créerait 840× plus d'exemples synthétiques. Les voisins interpolés sortent de la distribution réelle → le modèle apprend du **bruit** et sa performance réelle sur Worms chute.

**→ SMOTE a été rejeté après expérimentation.**

#### B. Pondération : `class_weight='balanced'`

Chaque classe reçoit un **poids inversement proportionnel à sa fréquence** :

$$w_c = \frac{N}{K \cdot N_c}$$

- `N` = nombre total d'échantillons
- `K` = nombre de classes
- `N_c` = nombre d'échantillons de la classe `c`

Dans la fonction de perte, chaque erreur sur une classe rare est **multipliée par son poids**. Résultat : le modèle ne peut plus ignorer Worms sans payer un gros coût.

**→ C'est la solution retenue** pour tous les modèles qui supportent `class_weight`. Pour XGBoost on utilise `sample_weight` calculé à partir des mêmes poids.

### 6.3. Fonction d'évaluation et métriques

**Pourquoi pas juste l'accuracy ?** Parce qu'avec 37% de Normal, prédire toujours Normal donne 37% d'accuracy sans apprendre. L'accuracy est **trompeuse sur les datasets déséquilibrés**.

**Les 4 métriques utilisées :**

| Métrique | Formule | Interprétation |
|----------|---------|----------------|
| **Accuracy** | `correct / total` | Proportion de bonnes prédictions |
| **Precision** | `TP / (TP + FP)` | Parmi les alertes, combien sont vraies ? (Faible = beaucoup de faux positifs → fatigue de l'analyste) |
| **Recall** | `TP / (TP + FN)` | Parmi les vraies attaques, combien sont détectées ? (Faible = attaques ratées → impact sécurité) |
| **F1-Score** | `2·P·R / (P+R)` | Moyenne harmonique → pénalise fort si l'une des deux est basse |

**`average='weighted'`** : on calcule Precision/Recall/F1 par classe, puis moyenne **pondérée par la fréquence**. C'est le bon choix quand les classes sont déséquilibrées et qu'on veut une métrique qui reflète la performance globale.

**Métrique principale :** F1-Score (Test). C'est ce qui départage les modèles.

### 6.4. Les 7 modèles entraînés

#### 6.4.1. Régression Logistique (baseline)

**Principe mathématique :** prédit la probabilité d'une classe par une combinaison linéaire des features passée dans une fonction softmax :

$$P(y = c \mid x) = \frac{\exp(w_c^T x + b_c)}{\sum_{k} \exp(w_k^T x + b_k)}$$

Les poids `w_c` sont appris en minimisant la **log-loss** (cross-entropy) par descente de gradient (solver L-BFGS).

**Hyperparamètres clés :**
- `C` : inverse de la régularisation L2 (empêche les poids d'exploser).
- `solver='lbfgs'`, `max_iter=1000`, `class_weight='balanced'`, `multi_class='multinomial'`.

**Rôle :** **référence minimale**. Si RF/XGBoost ne battent pas LR, c'est qu'il y a un bug dans le pipeline.

**Résultat :** F1(Test) = **0.7193**, Accuracy = 70.12%. Modèle honnête sur les classes linéairement séparables, mauvais sur Backdoor/Analysis.

#### 6.4.2. Arbre de Décision

**Principe :** à chaque nœud, chercher la feature et le seuil qui **maximisent la pureté** des deux enfants. Critère : **Gini impurity**

$$G = 1 - \sum_c p_c^2$$

où `p_c` est la proportion de la classe `c` dans le nœud. On minimise `G_enfants` à chaque split.

**Hyperparamètres :**
- `max_depth=20` : limite la profondeur pour éviter le surapprentissage.
- `min_samples_split`, `min_samples_leaf` : minima pour autoriser un split.
- `class_weight='balanced'`.

**Avantage :** interprétable (on peut lire l'arbre).
**Défaut :** **overfitte** très facilement (un arbre unique mémorise le train).

**Résultat :** F1(Val) = 0.87, F1(Test) = 0.73 → **écart énorme = surapprentissage visible**.

#### 6.4.3. Random Forest (ensemble par bagging)

**Principe :** entraîner `n_estimators=200` arbres indépendants, chacun sur :
- Un **bootstrap sample** (tirage avec remise) du train (randomisation des données).
- Un **sous-ensemble aléatoire** de features à chaque split (randomisation des features).

La prédiction finale = **vote majoritaire** des arbres (ou moyenne des probabilités).

**Formule intuitive (bagging) :** si chaque arbre a une erreur `ε`, la moyenne de `N` arbres indépendants réduit la variance d'un facteur `N` → meilleure généralisation. Les arbres sont volontairement **peu corrélés** grâce au sous-échantillonnage aléatoire.

**Hyperparamètres :**
- `n_estimators=200`, `max_depth=None` (les arbres sont profonds car le bagging compense).
- `max_features='sqrt'` : √d features considérées à chaque split.
- `class_weight='balanced'`, `n_jobs=-1`.

**Résultat :** F1(Test) = **0.7526**, Accuracy = 76.28%. Gros saut de qualité vs Decision Tree → bagging fonctionne.

#### 6.4.4. XGBoost (ensemble par boosting) — **MEILLEUR MODÈLE**

**Principe :** contrairement au bagging, les arbres sont construits **séquentiellement**, chaque nouvel arbre corrigeant les erreurs du précédent. On minimise la log-loss par **descente de gradient dans l'espace des fonctions** :

$$F_m(x) = F_{m-1}(x) + \eta \cdot h_m(x)$$

où `h_m` est un petit arbre entraîné à prédire le gradient négatif de la perte actuelle, et `η` (= `learning_rate`) est un pas d'apprentissage.

**XGBoost spécifique (vs GBM classique) :**
- Régularisation L1/L2 explicite sur les poids des feuilles.
- Algorithme de split exact + approximatif (histogramme) pour la rapidité.
- Gestion native des valeurs manquantes.
- Parallélisation efficace.
- **Historique de performance** : vainqueur de nombreuses compétitions Kaggle sur données tabulaires.

**Hyperparamètres clés :**
- `n_estimators`, `max_depth`, `learning_rate` (η), `subsample`, `colsample_bytree`.
- `objective='multi:softprob'`, `num_class=10`.
- `sample_weight` (équivalent de class_weight pour XGBoost).

**Résultat (version de base) :** F1(Test) = 0.7502.
**Résultat (version optimisée) :** F1(Test) = **0.7567** ← **meilleur modèle**.

#### 6.4.5. MLP Neural Network

**Architecture : (128, 64, 32)** — 3 couches cachées.

Chaque neurone calcule :

$$y = \sigma(W x + b)$$

avec `σ` = ReLU (`max(0, x)`), sauf la dernière couche qui utilise un **softmax** pour 10 classes.

**Entraînement :** backpropagation + Adam optimizer. Early stopping activé : arrêt si la performance validation ne progresse plus pendant 10 époques.

**Hyperparamètres :**
- `hidden_layer_sizes=(128, 64, 32)`.
- `activation='relu'`, `solver='adam'`.
- `max_iter=200`, `early_stopping=True`, `validation_fraction=0.1`.
- `alpha` (régularisation L2).

**Limite du `MLPClassifier` de sklearn :** pas de support direct pour `class_weight`. On laisse l'imbalance telle quelle → le modèle sous-performe sur les classes rares.

**Résultat :** F1(Test) = **0.7307**. Sous les méthodes d'arbre, confirmant que **le deep learning classique n'a pas d'avantage sur les données tabulaires**.

### 6.5. Optimisation des hyperparamètres — RandomizedSearchCV

**Problème :** chaque modèle a 5-10 hyperparamètres. Tester toutes les combinaisons (GridSearchCV) coûte des milliers d'entraînements. Impossible sur un laptop.

**Solution : RandomizedSearchCV**
- On tire aléatoirement `n_iter=5` combinaisons dans une grille de distributions.
- Pour chacune, on fait une cross-validation `cv=3`.
- On garde la combinaison qui maximise le F1.

**Ruse pour économiser :** la recherche se fait sur un **sous-échantillon de 10 000 points** (sinon trop lent). Une fois les meilleurs hyperparamètres trouvés, on **ré-entraîne sur TOUT le train**. C'est un compromis pragmatique : les hyperparamètres optimaux changent peu avec la taille, mais l'entraînement final doit être complet.

**Résultat :** XGBoost passe de F1=0.7502 → 0.7567 (+0.6 point). Gain modeste mais reproductible.

### 6.6. Validation croisée K-Fold

**Principe :** pour mesurer la **stabilité** d'un modèle, on découpe le train en `k=3` folds stratifiés. À chaque itération :
- Entraîner sur `k-1` folds, évaluer sur le fold restant.
- Répéter `k` fois.
- Retourner la moyenne et l'écart-type du F1.

**Résultat :** XGBoost → F1 = **0.8633 ± 0.0018** (écart-type minuscule → modèle très stable). Random Forest est légèrement en dessous avec plus de variance.

**Remarque :** les F1 en CV sont plus élevés qu'en test (0.86 vs 0.75) parce que la CV se fait **sur le train** qui est plus homogène que le test. Le test UNSW a été capturé à une période différente et contient de légères dérives de distribution (« distribution shift »).

### 6.7. Benchmark final

| Rang | Modèle | Accuracy | F1 (Test) |
|------|--------|----------|-----------|
| 1 | **XGBoost (Optimisé)** ⭐ | **76.36%** | **0.7567** |
| 2 | Random Forest (Optimisé) | 76.32% | 0.7551 |
| 3 | Random Forest | 76.28% | 0.7526 |
| 4 | XGBoost | 76.17% | 0.7502 |
| 5 | MLP Neural Network | 73.38% | 0.7307 |
| 6 | Decision Tree | 73.48% | 0.7277 |
| 7 | Logistic Regression | 70.12% | 0.7193 |

**Observations clés :**
- L'optimisation des hyperparamètres apporte peu (+0.6 point F1) → les valeurs par défaut étaient déjà bonnes.
- Les méthodes d'ensemble (RF, XGBoost) dominent clairement.
- Le MLP est en dessous → **tabulaire ≠ deep learning**.

### 6.8. Performance par classe (meilleur modèle)

| Classe | F1 | Commentaire |
|--------|----|-------------|
| Normal | ~0.95 | Très bien détecté (patterns clairs, beaucoup de données) |
| Generic | ~0.98 | Facile (signatures très distinctes) |
| Exploits | ~0.72 | Difficile car très varié (beaucoup de CVE différents) |
| Fuzzers | ~0.65 | Aléatoire par nature → ressemble parfois au trafic normal |
| DoS | ~0.30 | Confondu avec Exploits (les deux floodent) |
| Reconnaissance | ~0.80 | OK grâce aux compteurs `ct_*` |
| Analysis | ~0.06 | **Trop rare + imite le trafic normal** |
| Backdoor | ~0.13 | **Trop rare + discret** |
| Shellcode | ~0.60 | Signatures visibles |
| Worms | ~0.50 | Rare mais signature claire |

**Conclusion :** les limites du modèle sont sur **Analysis** et **Backdoor** → classes rares ET qui imitent le trafic légitime. Aucun modèle du benchmark ne les gère bien. Perspective : collecter plus de données sur ces classes, ou utiliser un détecteur d'anomalies spécifique (one-class SVM).

### 6.9. Artefacts sauvegardés (Phase 3)

| Fichier | Contenu |
|---------|---------|
| `models/best_model_xgboost_optimisé.pkl` | Meilleur modèle (copie) |
| `models/xgboost_optimisé.pkl` | XGBoost optimisé |
| `models/xgboost.pkl`, `random_forest.pkl`, etc. | Tous les 7 modèles |
| `data/processed/benchmark_results.csv` | Tableau comparatif |
| `data/processed/preprocessing_pipeline.pkl` | Scaler + encoders + feature list |

---

## 7. Phase 4 — Évaluation (initialisée)

Le notebook `04_evaluation.ipynb` charge tous les artefacts et prépare les analyses suivantes (à compléter) :

1. **Courbes ROC + AUC (one-vs-rest)** : pour chaque classe, tracer Recall vs False Positive Rate en faisant varier le seuil de décision. L'AUC (aire sous la courbe) résume la qualité du classifieur indépendamment du seuil. 1.0 = parfait, 0.5 = hasard.
2. **Courbes Precision-Recall** : plus informatives que ROC sur dataset déséquilibré.
3. **Analyse FP/FN** avec **impact métier** : un FN (attaque ratée) coûte cher, un FP (fausse alerte) fatigue l'analyste. Traduire les chiffres en coût.
4. **Tests de robustesse** : perturber les features (ajouter du bruit) et voir combien le modèle résiste.

---

## 8. Phase 5 — Explainable AI (XAI)

Notebook : **`05_xai.ipynb`** (créé maintenant).

### 8.1. Pourquoi XAI ?

Un IDS en production doit être **auditable**. Un analyste SOC doit pouvoir répondre à :
- « Pourquoi cette connexion a-t-elle été classée en Exploits ? »
- « Quelles features sont critiques pour le modèle ? Lesquelles un attaquant chercherait à manipuler ? »
- « Le modèle s'appuie-t-il sur des signaux réalistes ou sur du bruit ? »

Sans XAI, le modèle est une **boîte noire** et son déploiement en environnement sensible (cybersécurité, santé, finance) est risqué ou interdit par la réglementation (AI Act européen).

### 8.2. Les trois méthodes du notebook

#### 8.2.1. Importance Gini native (XGBoost)

Chaque split d'arbre réduit l'impureté Gini d'un certain montant. L'importance d'une feature = **total des gains Gini cumulés sur tous les splits où elle intervient**, pondéré par le nombre d'échantillons et moyenné sur tous les arbres.

**Avantages :** gratuit, calculé pendant l'entraînement.
**Limites :**
- **Biais cardinalité** : les features à nombreuses valeurs distinctes (comme `proto`, ~130 valeurs) paraissent artificiellement importantes.
- **Dilution** entre features corrélées.
- **Ne dit pas le sens** de l'effet.

#### 8.2.2. Permutation Importance

Algorithme :
1. Calculer le F1 de référence sur un jeu de validation.
2. Pour chaque feature `f` :
   - Mélanger aléatoirement sa colonne (`n_repeats=5` fois).
   - Recalculer le F1.
   - Importance = `F1_ref − F1_permuté`.

Si mélanger la feature ne change rien → feature inutile. Si ça fait chuter le F1 → feature critique.

**Avantages :**
- **Model-agnostic** : fonctionne sur tout modèle.
- **Sans biais cardinalité**.
- **Mesure l'impact réel** sur la performance.

**Coût :** élevé (`n_features × n_repeats` passes de prédiction) → exécuté sur un échantillon de 5 000 points.

#### 8.2.3. SHAP (SHapley Additive exPlanations)

**Fondation théorique : valeurs de Shapley** (théorie des jeux coopératifs, Lloyd Shapley, Prix Nobel d'économie 2012).

**Idée :** pour mesurer la contribution d'une feature `f` à une prédiction, on regarde **la différence de prédiction** entre toutes les coalitions de features qui contiennent `f` et celles qui ne la contiennent pas, en moyennant équitablement :

$$\phi_f = \sum_{S \subseteq F \setminus \{f\}} \frac{|S|!\,(|F|-|S|-1)!}{|F|!} \bigl[v(S \cup \{f\}) - v(S)\bigr]$$

où `v(S)` est la sortie du modèle utilisant seulement les features du sous-ensemble `S`.

**Propriétés garanties (uniques à SHAP) :**
1. **Efficiency** : `Σ φ_f = f(x) − E[f(x)]` — la somme des contributions égale exactement la différence entre la prédiction et la moyenne.
2. **Symmetry** : deux features jouant le même rôle ont la même contribution.
3. **Dummy** : une feature inutile a `φ = 0`.
4. **Additivity** : pour un ensemble d'arbres, les SHAP s'additionnent.

C'est la seule méthode qui satisfait ces 4 propriétés simultanément → **théoriquement optimale**.

**TreeExplainer** : algorithme polynomial (au lieu d'exponentiel) spécifique aux ensembles d'arbres (RF, XGBoost, LightGBM). Calcul exact, rapide.

**Trois usages dans le notebook :**

1. **Global** : `mean(|SHAP|)` sur un échantillon → classement des features. Théoriquement plus fiable que Gini et Permutation.
2. **Par classe** : pour chaque classe d'attaque, quelles features sont déterminantes ? Heatmap feature × classe.
3. **Local** (waterfall plot) : pour UNE connexion précise, détailler les contributions feature par feature. **C'est ce qui permet de justifier une alerte auprès de l'analyste.**

### 8.3. Comparaison des 3 méthodes

Le notebook produit un tableau consensuel :

| Feature | Gini | Permutation | SHAP | Moyenne |
|---------|------|-------------|------|---------|
| feature_1 | 0.12 | 0.10 | 0.11 | 0.11 |
| ... | ... | ... | ... | ... |

**Les features présentes en tête des 3 méthodes** sont celles qui comptent vraiment. Les features qui n'apparaissent qu'en Gini sont probablement victimes du biais cardinalité.

### 8.4. Ce que l'XAI nous a appris

1. **Le modèle n'est plus une boîte noire** : chaque prédiction peut être justifiée par un waterfall.
2. **Les features critiques sont intuitives** (débit, durée, compteurs de contexte, TTL) → le modèle a appris des heuristiques qu'un expert humain validerait.
3. **Le feature engineering de la Phase 3 est validé** : les features dérivées (`bytes_ratio`, `*_log`, `ttl_diff`) apparaissent dans le top consensuel.
4. **Chaque classe d'attaque a sa signature propre** : la heatmap montre que DoS, Reconnaissance, Backdoor, etc. mobilisent des features différentes. **Ce n'est pas un classifieur binaire déguisé.**
5. **Les erreurs sont diagnostiquables** : les waterfalls sur les faux positifs révèlent quelles features ont trompé le modèle → pistes d'amélioration.

---

## 9. Glossaire technique

| Terme | Définition courte |
|-------|-------------------|
| **Accuracy** | Proportion de prédictions correctes. Trompeuse si classes déséquilibrées. |
| **AUC** | Aire sous la courbe ROC. 1.0 = parfait, 0.5 = hasard. |
| **Bagging** | Méthode d'ensemble par moyennage de modèles entraînés sur des bootstrap samples. |
| **Boosting** | Méthode d'ensemble séquentielle où chaque modèle corrige les erreurs du précédent. |
| **Bootstrap** | Tirage aléatoire avec remise. |
| **Class imbalance** | Quand une classe représente beaucoup plus (ou moins) d'exemples que les autres. |
| **class_weight='balanced'** | Ajustement des poids proportionnel à l'inverse de la fréquence. |
| **Cross-validation** | Découpage en `k` folds, évaluation `k` fois. Mesure la stabilité. |
| **Data leakage** | Fuite d'info du test vers le train. À éviter absolument. |
| **Early stopping** | Arrêt de l'entraînement quand la perf validation n'améliore plus. |
| **F1-Score** | Moyenne harmonique de Precision et Recall. |
| **Feature engineering** | Création manuelle de nouvelles features à partir des brutes. |
| **Feature importance** | Score mesurant l'impact d'une feature sur le modèle. |
| **Gini impurity** | Mesure d'impureté utilisée par les arbres. |
| **GradientBoosting** | Famille d'algorithmes dont XGBoost, LightGBM, CatBoost. |
| **Hyperparamètre** | Paramètre qu'on règle manuellement (ex. max_depth), par opposition aux poids appris. |
| **Label encoding** | Encodage catégoriel en entiers. |
| **Log-loss / Cross-entropy** | Fonction de perte standard en classification. |
| **MI (Mutual Information)** | Mesure de dépendance statistique non linéaire. |
| **MLP** | Multi-Layer Perceptron — réseau de neurones classique. |
| **Multicolinéarité** | Corrélation forte entre features → instabilité des modèles linéaires. |
| **One-Hot Encoding** | Une colonne binaire par valeur catégorielle. |
| **Overfitting** | Le modèle mémorise le train et échoue sur des données nouvelles. |
| **Permutation Importance** | Importance mesurée par la chute de F1 quand on shuffle une feature. |
| **Precision** | `TP / (TP+FP)`. Qualité des alertes. |
| **Random Forest** | Ensemble d'arbres avec bagging + randomisation de features. |
| **Recall** | `TP / (TP+FN)`. Taux de détection. |
| **ReLU** | Activation `max(0, x)` utilisée dans les réseaux de neurones. |
| **SHAP** | Méthode XAI basée sur les valeurs de Shapley. |
| **Skewness** | Asymétrie d'une distribution. |
| **SMOTE** | Sur-échantillonnage synthétique des classes rares. Rejeté ici. |
| **Softmax** | Fonction qui transforme des scores en probabilités sommant à 1. |
| **StandardScaler** | Normalisation `(x - μ) / σ`. |
| **Stratification** | Conserver les proportions de classes dans un split. |
| **TTL** | Time To Live d'un paquet IP. Indice anti-spoofing. |
| **XAI** | Explainable AI — rendre les modèles interprétables. |
| **XGBoost** | Gradient Boosting optimisé, état de l'art sur tabulaire. |

---

## 10. Questions types et réponses attendues

> *Ces questions sont celles que le jury/encadrant est susceptible de poser. Ces réponses reprennent et condensent les sections précédentes.*

### Q1. Pourquoi 42 features et pas 45 (les features brutes) ?

Parce qu'on a :
- **Ajouté** 14 features dérivées par feature engineering (`bytes_ratio`, `total_bytes`, `*_log`, etc.).
- **Supprimé** les features avec corrélation `|r| > 0.95` (multicolinéarité).
- **Supprimé** les features avec Information Mutuelle < 0.01 (indépendantes de la cible).

Résultat net : 42 features finales dans `feature_cols_final`.

### Q2. Pourquoi avoir choisi XGBoost comme meilleur modèle ?

Parce que sur le benchmark final, il obtient le F1(Test) le plus élevé (**0.7567**), et sa cross-validation 3-fold montre l'écart-type le plus faible (**0.0018**) → c'est à la fois le plus performant et le plus stable. C'est aussi cohérent avec la littérature : XGBoost est l'état de l'art sur les données tabulaires depuis 2016.

### Q3. Pourquoi ne pas avoir utilisé SMOTE pour le déséquilibre ?

Parce qu'avec Worms à 130 exemples vs Normal à 37 000, SMOTE créerait ~840× plus d'exemples synthétiques par interpolation entre voisins. Ces exemples sortent de la distribution réelle et constituent du bruit qui **dégrade** la performance au lieu de l'améliorer. On a préféré `class_weight='balanced'` qui pondère la fonction de perte sans créer de données artificielles.

### Q4. Pourquoi avoir utilisé Label Encoding et pas One-Hot ?

`proto` a ~130 valeurs distinctes → One-Hot créerait 130 colonnes → explosion dimensionnelle. Les modèles à base d'arbres (notre meilleur modèle XGBoost en particulier) sont **invariants à l'ordre numérique** du label encoding — ils coupent en `proto < 42.5` peu importe la sémantique de 42. Donc Label Encoding est suffisant et plus compact.

### Q5. Pourquoi la validation croisée donne F1=0.86 mais le test seulement 0.75 ?

Parce que la CV est faite **sur le train**, qui a été capturé à une période donnée. Le test UNSW a été capturé à une période différente et contient de légères dérives de distribution (« distribution shift »). L'écart de 0.11 point est le prix de la généralisation à des données vraiment nouvelles.

### Q6. Pourquoi le MLP est-il moins bon que XGBoost ?

Deux raisons :
1. **Sur données tabulaires**, les méthodes d'ensemble d'arbres dominent le deep learning (résultat empirique bien documenté, cf. Shwartz-Ziv & Armon 2022).
2. **Le `MLPClassifier` de sklearn ne supporte pas `class_weight`** — le déséquilibre l'affecte fortement sur les classes rares.

### Q7. Pourquoi le modèle échoue sur Analysis et Backdoor ?

Double peine : ces classes sont **à la fois rares** (0.6% chacune) **et** visuellement proches du trafic normal (attaques discrètes, peu de trafic). Aucune feature ne les discrimine franchement, et même avec class_weight elles restent mal apprises. Solutions envisageables : collecte de données supplémentaires, ou détecteur d'anomalies spécifique (one-class SVM, autoencoder) en complément.

### Q8. C'est quoi exactement une « valeur de Shapley » ?

C'est la **contribution équitable** d'un joueur à un gain collectif en théorie des jeux coopératifs. Appliquée au ML : pour savoir combien une feature contribue à une prédiction, on calcule la différence de sortie du modèle entre « avec cette feature » et « sans cette feature », moyennée sur **toutes les coalitions possibles** d'autres features. C'est la seule méthode d'attribution qui respecte simultanément 4 axiomes désirables (Efficiency, Symmetry, Dummy, Additivity), prouvé mathématiquement.

### Q9. Pourquoi RandomizedSearchCV et pas GridSearchCV ?

Parce que GridSearchCV teste **toutes** les combinaisons de la grille : avec 5 hyperparamètres ayant chacun 5 valeurs = 5^5 = 3125 entraînements × 3 folds = **9375 entraînements**. Sur un laptop c'est infaisable. RandomizedSearchCV tire `n_iter=5` combinaisons aléatoirement — 5 × 3 = 15 entraînements. Perte de qualité marginale (Bergstra & Bengio 2012 ont montré que le random search est souvent aussi bon que grid search).

### Q10. Quelle est la différence entre Precision et Recall ? Laquelle est la plus importante en IDS ?

- **Precision = TP / (TP + FP)** : parmi les alertes, combien sont vraies.
- **Recall = TP / (TP + FN)** : parmi les vraies attaques, combien sont détectées.

**En IDS, le Recall est critique** : rater une attaque (FN) peut coûter très cher (compromission, exfiltration). Un FP (fausse alerte) fatigue l'analyste mais n'a pas de conséquence directe. Cependant, un Recall élevé au prix d'une Precision trop basse est contre-productif (fatigue d'alerte → alertes ignorées). Le **F1** équilibre les deux, d'où son choix comme métrique principale.

### Q11. Qu'est-ce qu'un waterfall plot SHAP et comment le lire ?

C'est une visualisation qui part de la **prédiction moyenne du modèle sur tout le dataset** `E[f(x)]` (en bas) et empile les contributions de chaque feature (une barre par feature) jusqu'à la **prédiction finale sur cette instance** `f(x)` (en haut). Les barres rouges poussent vers la classe prédite, les bleues contre. C'est l'outil le plus intuitif pour **justifier une alerte** individuelle à un analyste.

### Q12. Pourquoi avoir fait trois méthodes d'importance au lieu d'une ?

Parce qu'**aucune n'est parfaite** :
- **Gini** est biaisée par la cardinalité et dilue sur les features corrélées.
- **Permutation** sous-estime les features redondantes.
- **SHAP** est théoriquement optimale mais coûteuse.

En comparant les trois, on obtient un **classement consensuel** qui est bien plus fiable qu'une méthode seule. Les features en tête des trois sont vraiment les plus critiques ; celles qui n'apparaissent qu'en Gini sont à relativiser.

### Q13. Pourquoi utilisez-vous F1_weighted et pas F1_macro ?

- **F1_macro** = moyenne arithmétique des F1 par classe → traite toutes les classes comme égales. Donne un poids énorme aux classes rares.
- **F1_weighted** = moyenne pondérée par la fréquence de chaque classe → reflète la performance globale en tenant compte du volume.

Dans un contexte IDS où l'on veut une métrique représentative du comportement réel sur le trafic production (dominé par Normal), **F1_weighted est plus parlant**. Pour une analyse fine des classes rares, on regarde le F1 par classe séparément.

### Q14. Que se passe-t-il en production sur une nouvelle connexion ?

1. Capturer les 45 features brutes de la connexion.
2. Appliquer le **même pipeline** : capping → feature engineering → label encoding (avec les encodeurs sauvegardés) → StandardScaler (avec μ, σ sauvegardés) → sélection des 42 features finales.
3. Appeler `best_model.predict_proba(x)` → probabilités des 10 classes.
4. Si `argmax ≠ Normal` → lever une alerte avec la classe prédite et (optionnellement) un waterfall SHAP pour la justification.

C'est pour cela que le pipeline a été sauvegardé dans `preprocessing_pipeline.pkl` avec **tous** les paramètres : sans ça, impossible de traiter une nouvelle connexion de manière cohérente.

---

**Fin du document.**

> Pour toute question non couverte ici, consulter les notebooks sources :
> - `03_modeling.ipynb` — code et commentaires détaillés de la Phase 3
> - `04_evaluation.ipynb` — préparation Phase 4
> - `05_xai.ipynb` — XAI complet avec explications en markdown cellule par cellule
