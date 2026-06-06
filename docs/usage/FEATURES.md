# contextcrawler - Documentation fonctionnelle complete

> **contextcrawler (Rust Token Killer)** -- Proxy CLI haute performance qui reduit la consommation de tokens LLM de 60 a 90%.

Binaire Rust unique, zero dependances externes, overhead < 10ms par commande.

---

## Table des matieres

1. [Vue d'ensemble](#vue-densemble)
2. [Drapeaux globaux](#drapeaux-globaux)
3. [Commandes Fichiers](#commandes-fichiers)
4. [Commandes Git](#commandes-git)
5. [Commandes GitHub CLI](#commandes-github-cli)
6. [Commandes Test](#commandes-test)
7. [Commandes Build et Lint](#commandes-build-et-lint)
8. [Commandes Formatage](#commandes-formatage)
9. [Gestionnaires de paquets](#gestionnaires-de-paquets)
10. [Conteneurs et orchestration](#conteneurs-et-orchestration)
11. [Donnees et reseau](#donnees-et-reseau)
12. [Cloud et bases de donnees](#cloud-et-bases-de-donnees)
13. [Stacked PRs (Graphite)](#stacked-prs-graphite)
14. [Analytique et suivi](#analytique-et-suivi)
15. [Systeme de hooks](#systeme-de-hooks)
16. [Configuration](#configuration)
17. [Systeme Tee (recuperation de sortie)](#systeme-tee)
18. [Telemetrie](#telemetrie)

---

## Vue d'ensemble

contextcrawler agit comme un proxy entre un LLM (Claude Code, Gemini CLI, etc.) et les commandes systeme. Quatre strategies de filtrage sont appliquees selon le type de commande :

| Strategie | Description | Exemple |
|-----------|-------------|---------|
| **Filtrage intelligent** | Supprime le bruit (commentaires, espaces, boilerplate) | `ls -la` -> arbre compact |
| **Regroupement** | Agregation par repertoire, par type d'erreur, par regle | Tests groupes par fichier |
| **Troncature** | Conserve le contexte pertinent, supprime la redondance | Diff condense |
| **Deduplication** | Fusionne les lignes de log repetees avec compteurs | `error x42` |

### Mecanisme de fallback

Si contextcrawler ne reconnait pas une sous-commande, il execute la commande brute (passthrough) et enregistre l'evenement dans la base de suivi. Cela garantit que contextcrawler est **toujours sur** a utiliser -- aucune commande ne sera bloquee.

---

## Drapeaux globaux

Ces drapeaux s'appliquent a **toutes** les sous-commandes :

| Drapeau | Court | Description |
|---------|-------|-------------|
| `--verbose` | `-v` | Augmenter la verbosite (-v, -vv, -vvv). Montre les details de filtrage. |
| `--ultra-compact` | `-u` | Mode ultra-compact : icones ASCII, format inline. Economies supplementaires. |
| `--skip-env` | -- | Definit `SKIP_ENV_VALIDATION=1` pour les processus enfants (Next.js, tsc, lint, prisma). |

**Exemples :**

```bash
contextcrawler -v git status          # Status compact + details de filtrage sur stderr
contextcrawler -vvv cargo test        # Verbosite maximale (debug)
contextcrawler -u git log             # Log ultra-compact, icones ASCII
contextcrawler --skip-env next build  # Desactive la validation d'env de Next.js
```

---

## Commandes Fichiers

### `contextcrawler ls` -- Listage de repertoire

**Objectif :** Remplace `ls` et `tree` avec une sortie optimisee en tokens.

**Syntaxe :**
```bash
contextcrawler ls [args...]
```

Tous les drapeaux natifs de `ls` sont supportes (`-l`, `-a`, `-h`, `-R`, etc.).

**Economies :** ~80% de reduction de tokens

**Avant / Apres :**
```
# ls -la (45 lignes, ~800 tokens)          # contextcrawler ls (12 lignes, ~150 tokens)
drwxr-xr-x  15 user staff 480 ...          my-project/
-rw-r--r--   1 user staff 1234 ...          +-- src/ (8 files)
-rw-r--r--   1 user staff 567 ...           |   +-- main.rs
...40 lignes de plus...                     +-- Cargo.toml
                                            +-- README.md
```

---

### `contextcrawler tree` -- Arbre de repertoire

**Objectif :** Proxy vers `tree` natif avec sortie filtree.

**Syntaxe :**
```bash
contextcrawler tree [args...]
```

Supporte tous les drapeaux natifs de `tree` (`-L`, `-d`, `-a`, etc.).

**Economies :** ~80%

---

### `contextcrawler read` -- Lecture de fichier

**Objectif :** Remplace `cat`, `head`, `tail` avec un filtrage intelligent du contenu.

**Syntaxe :**
```bash
contextcrawler read <fichier> [options]
contextcrawler read - [options]          # Lecture depuis stdin
```

**Options :**

| Option | Court | Defaut | Description |
|--------|-------|--------|-------------|
| `--level` | `-l` | `minimal` | Niveau de filtrage : `none`, `minimal`, `aggressive` |
| `--max-lines` | `-m` | illimite | Nombre maximum de lignes |
| `--line-numbers` | `-n` | non | Afficher les numeros de ligne |

**Niveaux de filtrage :**

| Niveau | Description | Economies |
|--------|-------------|-----------|
| `none` | Aucun filtrage, sortie brute | 0% |
| `minimal` | Supprime commentaires et lignes vides excessives | ~30% |
| `aggressive` | Signatures uniquement (supprime les corps de fonctions) | ~74% |

**Avant / Apres (mode aggressive) :**
```
# cat main.rs (~200 lignes)                # contextcrawler read main.rs -l aggressive (~50 lignes)
fn main() -> Result<()> {                   fn main() -> Result<()> { ... }
    let config = Config::load()?;           fn process_data(input: &str) -> Vec<u8> { ... }
    let data = process_data(&input);        struct Config { ... }
    for item in data {                      impl Config { fn load() -> Result<Self> { ... } }
        println!("{}", item);
    }
    Ok(())
}
...
```

**Langages supportes pour le filtrage :** Rust, Python, JavaScript, TypeScript, Go, C, C++, Java, Ruby, Shell.

---

### `contextcrawler smart` -- Resume heuristique

**Objectif :** Genere un resume technique de 2 lignes pour un fichier source.

**Syntaxe :**
```bash
contextcrawler smart <fichier> [--model heuristic] [--force-download]
```

**Economies :** ~95%

**Exemple :**
```
$ contextcrawler smart src/tracking.rs
SQLite-based token tracking system for command executions.
Records input/output tokens, savings %, execution times with 90-day retention.
```

---

### `contextcrawler find` -- Recherche de fichiers

**Objectif :** Remplace `find` et `fd` avec une sortie compacte groupee par repertoire.

**Syntaxe :**
```bash
contextcrawler find [args...]
```

Supporte a la fois la syntaxe contextcrawler et la syntaxe native `find` (`-name`, `-type`, etc.).

**Economies :** ~80%

**Avant / Apres :**
```
# find . -name "*.rs" (30 lignes)           # contextcrawler find "*.rs" . (8 lignes)
./src/main.rs                                src/ (12 .rs)
./src/git.rs                                   main.rs, git.rs, config.rs
./src/config.rs                                tracking.rs, filter.rs, utils.rs
./src/tracking.rs                              ...6 more
./src/filter.rs                              tests/ (3 .rs)
./src/utils.rs                                 test_git.rs, test_ls.rs, test_filter.rs
...24 lignes de plus...
```

---

### `contextcrawler grep` -- Recherche dans le contenu

**Objectif :** Remplace `grep` et `rg` avec une sortie groupee par fichier, tronquee.

**Syntaxe :**
```bash
contextcrawler grep <pattern> [chemin] [options]
```

**Options :**

| Option | Court | Defaut | Description |
|--------|-------|--------|-------------|
| `--max-len` | `-l` | 80 | Longueur maximale de ligne |
| `--max` | `-m` | 50 | Nombre maximum de resultats |
| `--context-only` |  | non | Afficher uniquement le contexte du match (pas de raccourci, `-c` est reserve a `grep --count`) |
| `--file-type` | `-t` | tous | Filtrer par type (ts, py, rust, etc.) |
| `--line-numbers` | `-n` | oui | Numeros de ligne (toujours actif) |

Les arguments supplementaires sont transmis a `rg` (ripgrep). Les flags qui changent le format de sortie (`-c`, `-l`, `-L`, `-o`, `-Z`) passent directement a `rg`/`grep` sans filtrage contextcrawler.

**Economies :** ~80%

**Avant / Apres :**
```
# rg "fn run" (20 lignes)                   # contextcrawler grep "fn run" (10 lignes)
src/git.rs:45:pub fn run(...)                src/git.rs
src/git.rs:120:fn run_status(...)              45: pub fn run(...)
src/ls.rs:12:pub fn run(...)                   120: fn run_status(...)
src/ls.rs:25:fn run_tree(...)                src/ls.rs
...                                            12: pub fn run(...)
                                               25: fn run_tree(...)
```

---

### `contextcrawler diff` -- Diff condense

**Objectif :** Diff ultra-condense entre deux fichiers (uniquement les lignes modifiees).

**Syntaxe :**
```bash
contextcrawler diff <fichier1> <fichier2>
contextcrawler diff <fichier1>              # Stdin comme second fichier
```

**Economies :** ~60%

---

### `contextcrawler wc` -- Comptage compact

**Objectif :** Remplace `wc` avec une sortie compacte (supprime les chemins et le padding).

**Syntaxe :**
```bash
contextcrawler wc [args...]
```

Supporte tous les drapeaux natifs de `wc` (`-l`, `-w`, `-c`, etc.).

---

## Commandes Git

### Vue d'ensemble

Toutes les sous-commandes git sont supportees. Les commandes non reconnues sont transmises directement a git (passthrough).

**Options globales git :**

| Option | Description |
|--------|-------------|
| `-C <path>` | Changer de repertoire avant execution |
| `-c <key=value>` | Surcharger une config git |
| `--git-dir <path>` | Chemin vers le repertoire .git |
| `--work-tree <path>` | Chemin vers le working tree |
| `--no-pager` | Desactiver le pager |
| `--no-optional-locks` | Ignorer les locks optionnels |
| `--bare` | Traiter comme repo bare |
| `--literal-pathspecs` | Pathspecs literals |

---

### `contextcrawler git status` -- Status compact

**Economies :** ~80%

```bash
contextcrawler git status [args...]    # Supporte tous les drapeaux git status
```

**Avant / Apres :**
```
# git status (~20 lignes, ~400 tokens)      # contextcrawler git status (~5 lignes, ~80 tokens)
On branch main                               main | 3M 1? 1A
Your branch is up to date with               M src/main.rs
  'origin/main'.                              M src/git.rs
                                              M tests/test_git.rs
Changes not staged for commit:                ? new_file.txt
  (use "git add <file>..." to update)        A staged_file.rs
  modified:   src/main.rs
  modified:   src/git.rs
  ...
```

---

### `contextcrawler git log` -- Historique compact

**Economies :** ~80%

```bash
contextcrawler git log [args...]    # Supporte --oneline, --graph, --all, -n, etc.
```

**Avant / Apres :**
```
# git log (50+ lignes)                      # contextcrawler git log -n 5 (5 lignes)
commit abc123def... (HEAD -> main)           abc123 Fix token counting bug
Author: User <user@email.com>               def456 Add vitest support
Date:   Mon Jan 15 10:30:00 2024            789abc Refactor filter engine
                                             012def Update README
    Fix token counting bug                   345ghi Initial commit
...
```

---

### `contextcrawler git diff` -- Diff compact

**Economies :** ~75%

```bash
contextcrawler git diff [args...]    # Supporte --stat, --cached, --staged, etc.
```

**Avant / Apres :**
```
# git diff (~100 lignes)                    # contextcrawler git diff (~25 lignes)
diff --git a/src/main.rs b/src/main.rs      src/main.rs (+5/-2)
index abc123..def456 100644                    +  let config = Config::load()?;
--- a/src/main.rs                              +  config.validate()?;
+++ b/src/main.rs                              -  // old code
@@ -10,6 +10,8 @@                              -  let x = 42;
   fn main() {                               src/git.rs (+1/-1)
+    let config = Config::load()?;              ~  format!("ok {}", branch)
...30 lignes de headers et contexte...
```

---

### `contextcrawler git show` -- Show compact

**Economies :** ~80%

```bash
contextcrawler git show [args...]
```

Affiche le resume du commit + stat + diff compact.

---

### `contextcrawler git add` -- Add ultra-compact

**Economies :** ~92%

```bash
contextcrawler git add [args...]    # Supporte -A, -p, --all, etc.
```

**Sortie :** `ok` (un seul mot)

---

### `contextcrawler git commit` -- Commit ultra-compact

**Economies :** ~92%

```bash
contextcrawler git commit -m "message" [args...]    # Supporte -a, --amend, --allow-empty, etc.
```

**Sortie :** `ok abc1234` (confirmation + hash court)

---

### `contextcrawler git push` -- Push ultra-compact

**Economies :** ~92%

```bash
contextcrawler git push [args...]    # Supporte -u, remote, branch, etc.
```

**Avant / Apres :**
```
# git push (15 lignes, ~200 tokens)         # contextcrawler git push (1 ligne, ~10 tokens)
Enumerating objects: 5, done.                ok main
Counting objects: 100% (5/5), done.
Delta compression using up to 8 threads
...
```

---

### `contextcrawler git pull` -- Pull ultra-compact

**Economies :** ~92%

```bash
contextcrawler git pull [args...]
```

**Sortie :** `ok 3 files +10 -2`

---

### `contextcrawler git branch` -- Branches compact

```bash
contextcrawler git branch [args...]    # Supporte -d, -D, -m, etc.
```

Affiche branche courante, branches locales, branches distantes de facon compacte.

---

### `contextcrawler git fetch` -- Fetch compact

```bash
contextcrawler git fetch [args...]
```

**Sortie :** `ok fetched (N new refs)`

---

### `contextcrawler git stash` -- Stash compact

```bash
contextcrawler git stash [list|show|pop|apply|drop|push] [args...]
```

---

### `contextcrawler git worktree` -- Worktree compact

```bash
contextcrawler git worktree [add|remove|prune|list] [args...]
```

---

### Passthrough git

Toute sous-commande git non listee ci-dessus est executee directement :

```bash
contextcrawler git rebase main        # Execute git rebase main
contextcrawler git cherry-pick abc    # Execute git cherry-pick abc
contextcrawler git tag v1.0.0         # Execute git tag v1.0.0
```

---

## Commandes GitHub CLI

### `contextcrawler gh` -- GitHub CLI compact

**Objectif :** Remplace `gh` avec une sortie optimisee.

**Syntaxe :**
```bash
contextcrawler gh <sous-commande> [args...]
```

**Sous-commandes supportees :**

| Commande | Description | Economies |
|----------|-------------|-----------|
| `contextcrawler gh pr list` | Liste des PRs compacte | ~80% |
| `contextcrawler gh pr view <num>` | Details d'une PR + checks | ~87% |
| `contextcrawler gh pr checks` | Status des checks CI | ~79% |
| `contextcrawler gh issue list` | Liste des issues compacte | ~80% |
| `contextcrawler gh run list` | Status des workflow runs | ~82% |
| `contextcrawler gh api <endpoint>` | Reponse API compacte | ~26% |

**Avant / Apres :**
```
# gh pr list (~30 lignes)                   # contextcrawler gh pr list (~10 lignes)
Showing 10 of 15 pull requests in org/repo   #42 feat: add vitest (open, 2d)
                                              #41 fix: git diff crash (open, 3d)
#42  feat: add vitest support                 #40 chore: update deps (merged, 5d)
  user opened about 2 days ago                #39 docs: add guide (merged, 1w)
  ... labels: enhancement
...
```

---

## Commandes Test

### `contextcrawler test` -- Wrapper de tests generique

**Objectif :** Execute n'importe quelle commande de test et affiche uniquement les echecs.

**Syntaxe :**
```bash
contextcrawler test <commande...>
```

**Economies :** ~90%

**Exemple :**
```bash
contextcrawler test cargo test
contextcrawler test npm test
contextcrawler test bun test
contextcrawler test pytest
```

**Avant / Apres :**
```
# cargo test (200+ lignes en cas d'echec)   # contextcrawler test cargo test (~20 lignes)
running 15 tests                             FAILED: 2/15 tests
test utils::test_parse ... ok                  test_edge_case: assertion failed
test utils::test_format ... ok                 test_overflow: panic at utils.rs:18
test utils::test_edge_case ... FAILED
...150 lignes de backtrace...
```

---

### `contextcrawler err` -- Erreurs/avertissements uniquement

**Objectif :** Execute une commande et ne montre que les erreurs et avertissements.

**Syntaxe :**
```bash
contextcrawler err <commande...>
```

**Economies :** ~80%

**Exemple :**
```bash
contextcrawler err npm run build
contextcrawler err cargo build
```

---

### `contextcrawler cargo test` -- Tests Rust

**Economies :** ~90%

```bash
contextcrawler cargo test [args...]
```

N'affiche que les echecs. Supporte tous les arguments de `cargo test`.

---

### `contextcrawler cargo nextest` -- Tests Rust (nextest)

```bash
contextcrawler cargo nextest [run|list|--lib] [args...]
```

Filtre la sortie de `cargo nextest` pour n'afficher que les echecs.

---

### `contextcrawler jest` / `contextcrawler vitest` -- Tests Jest/Vitest

**Economies :** ~99.5%

```bash
contextcrawler jest [args...]
contextcrawler vitest [args...]
```

---

### `contextcrawler playwright test` -- Tests E2E Playwright

**Economies :** ~94%

```bash
contextcrawler playwright [args...]
```

---

### `contextcrawler pytest` -- Tests Python

**Economies :** ~90%

```bash
contextcrawler pytest [args...]
```

---

### `contextcrawler go test` -- Tests Go

**Economies :** ~90%

```bash
contextcrawler go test [args...]
```

Utilise le streaming JSON NDJSON de Go pour un filtrage precis.

---

## Commandes Build et Lint

### `contextcrawler cargo build` -- Build Rust

**Economies :** ~80%

```bash
contextcrawler cargo build [args...]
```

Supprime les lignes "Compiling...", ne conserve que les erreurs et le resultat final.

---

### `contextcrawler cargo check` -- Check Rust

**Economies :** ~80%

```bash
contextcrawler cargo check [args...]
```

Supprime les lignes "Checking...", ne conserve que les erreurs.

---

### `contextcrawler cargo clippy` -- Clippy Rust

**Economies :** ~80%

```bash
contextcrawler cargo clippy [args...]
```

Regroupe les avertissements par regle de lint.

---

### `contextcrawler cargo install` -- Install Rust

```bash
contextcrawler cargo install [args...]
```

Supprime la compilation des dependances, ne conserve que le resultat d'installation et les erreurs.

---

### `contextcrawler tsc` -- TypeScript Compiler

**Economies :** ~83%

```bash
contextcrawler tsc [args...]
```

Regroupe les erreurs TypeScript par fichier et par code d'erreur.

**Avant / Apres :**
```
# tsc --noEmit (50 lignes)                  # contextcrawler tsc (15 lignes)
src/api.ts(12,5): error TS2345: ...          src/api.ts (3 errors)
src/api.ts(15,10): error TS2345: ...           TS2345: Argument type mismatch (x2)
src/api.ts(20,3): error TS7006: ...            TS7006: Parameter implicitly has 'any'
src/utils.ts(5,1): error TS2304: ...         src/utils.ts (1 error)
...                                            TS2304: Cannot find name 'foo'
```

---

### `contextcrawler lint` -- ESLint / Biome

**Economies :** ~84%

```bash
contextcrawler lint [args...]
contextcrawler lint biome [args...]
```

Regroupe les violations par regle et par fichier. Auto-detecte le linter.

---

### `contextcrawler prettier` -- Verification du formatage

**Economies :** ~70%

```bash
contextcrawler prettier [args...]    # ex: contextcrawler prettier --check .
```

Affiche uniquement les fichiers necessitant un formatage.

---

### `contextcrawler format` -- Formateur universel

```bash
contextcrawler format [args...]
```

Auto-detecte le formateur du projet (prettier, black, ruff format) et applique un filtre compact.

---

### `contextcrawler next build` -- Build Next.js

**Economies :** ~87%

```bash
contextcrawler next [args...]
```

Sortie compacte avec metriques de routes.

---

### `contextcrawler ruff` -- Linter/formateur Python

**Economies :** ~80%

```bash
contextcrawler ruff check [args...]
contextcrawler ruff format --check [args...]
```

Sortie JSON compressee.

---

### `contextcrawler mypy` -- Type checker Python

```bash
contextcrawler mypy [args...]
```

Regroupe les erreurs de type par fichier.

---

### `contextcrawler golangci-lint` -- Linter Go

**Economies :** ~85%

```bash
contextcrawler golangci-lint run [args...]
```

Sortie JSON compressee.

---

## Commandes Formatage

### `contextcrawler prettier` -- Prettier

```bash
contextcrawler prettier --check .
contextcrawler prettier --write src/
```

---

### `contextcrawler format` -- Detecteur universel

```bash
contextcrawler format [args...]
```

Detecte automatiquement : prettier, black, ruff format, rustfmt. Applique un filtre compact unifie.

---

## Gestionnaires de paquets

### `contextcrawler pnpm` -- pnpm

| Commande | Description | Economies |
|----------|-------------|-----------|
| `contextcrawler pnpm list [-d N]` | Arbre de dependances compact | ~70% |
| `contextcrawler pnpm outdated` | Paquets obsoletes : `pkg: old -> new` | ~80% |
| `contextcrawler pnpm install` | Filtre les barres de progression | ~60% |
| `contextcrawler pnpm build` | Delegue au filtre Next.js | ~87% |
| `contextcrawler pnpm typecheck` | Delegue au filtre tsc | ~83% |

Les sous-commandes non reconnues sont transmises directement a pnpm (passthrough).

---

### `contextcrawler npm` -- npm

```bash
contextcrawler npm [args...]    # ex: contextcrawler npm run build
```

Filtre le boilerplate npm (barres de progression, en-tetes, etc.).

---

### `contextcrawler npx` -- npx avec routage intelligent

```bash
contextcrawler npx [args...]
```

Route intelligemment vers les filtres specialises :
- `contextcrawler npx tsc` -> filtre tsc
- `contextcrawler npx eslint` -> filtre lint
- `contextcrawler npx prisma` -> filtre prisma
- Autres -> passthrough filtre

---

### `contextcrawler pip` -- pip / uv

```bash
contextcrawler pip list              # Liste des paquets (auto-detecte uv)
contextcrawler pip outdated          # Paquets obsoletes
contextcrawler pip install <pkg>     # Installation
```

Auto-detecte `uv` si disponible et l'utilise a la place de `pip`.

---

### `contextcrawler deps` -- Resume des dependances

**Objectif :** Resume compact des dependances du projet.

```bash
contextcrawler deps [chemin]    # Defaut: repertoire courant
```

Auto-detecte : `Cargo.toml`, `package.json`, `pyproject.toml`, `go.mod`, `Gemfile`, etc.

**Economies :** ~70%

---

### `contextcrawler prisma` -- ORM Prisma

| Commande | Description |
|----------|-------------|
| `contextcrawler prisma generate` | Generation du client (supprime l'ASCII art) |
| `contextcrawler prisma migrate dev [--name N]` | Creer et appliquer une migration |
| `contextcrawler prisma migrate status` | Status des migrations |
| `contextcrawler prisma migrate deploy` | Deployer en production |
| `contextcrawler prisma db-push` | Push du schema |

---

## Conteneurs et orchestration

### `contextcrawler docker` -- Docker

| Commande | Description | Economies |
|----------|-------------|-----------|
| `contextcrawler docker ps` | Liste compacte des conteneurs | ~80% |
| `contextcrawler docker images` | Liste compacte des images | ~80% |
| `contextcrawler docker logs <conteneur>` | Logs dedupliques | ~70% |
| `contextcrawler docker compose ps` | Services Compose compacts | ~80% |
| `contextcrawler docker compose logs [service]` | Logs Compose dedupliques | ~70% |
| `contextcrawler docker compose build [service]` | Resume du build | ~60% |

Les sous-commandes non reconnues sont transmises directement (passthrough).

**Avant / Apres :**
```
# docker ps (lignes longues, ~30 tokens/ligne)    # contextcrawler docker ps (~10 tokens/ligne)
CONTAINER ID   IMAGE          COMMAND     ...      web  nginx:1.25 Up 2d (healthy)
abc123def456   nginx:1.25     "/dock..."  ...      db   postgres:16 Up 2d (healthy)
789012345678   postgres:16    "docker..."           redis redis:7 Up 1d
```

---

### `contextcrawler kubectl` -- Kubernetes

| Commande | Description | Options |
|----------|-------------|---------|
| `contextcrawler kubectl pods [-n ns] [-A]` | Liste compacte des pods | Namespace ou tous |
| `contextcrawler kubectl services [-n ns] [-A]` | Liste compacte des services | Namespace ou tous |
| `contextcrawler kubectl logs <pod> [-c container]` | Logs dedupliques | Container specifique |

Les sous-commandes non reconnues sont transmises directement (passthrough).

---

## Donnees et reseau

### `contextcrawler json` -- Structure JSON

**Objectif :** Affiche la structure d'un fichier JSON sans les valeurs.

```bash
contextcrawler json <fichier> [--depth N]    # Defaut: profondeur 5
contextcrawler json -                         # Depuis stdin
```

**Economies :** ~60%

**Avant / Apres :**
```
# cat package.json (50 lignes)              # contextcrawler json package.json (10 lignes)
{                                            {
  "name": "my-app",                            name: string
  "version": "1.0.0",                         version: string
  "dependencies": {                            dependencies: { 15 keys }
    "react": "^18.2.0",                        devDependencies: { 8 keys }
    "next": "^14.0.0",                         scripts: { 6 keys }
    ...15 dependances...                     }
  },
  ...
}
```

---

### `contextcrawler env` -- Variables d'environnement

```bash
contextcrawler env                    # Toutes les variables (sensibles masquees)
contextcrawler env -f AWS             # Filtrer par nom
contextcrawler env --show-all         # Inclure les valeurs sensibles
```

Les variables sensibles (tokens, secrets, mots de passe) sont masquees par defaut : `AWS_SECRET_ACCESS_KEY=***`.

---

### `contextcrawler log` -- Logs dedupliques

**Objectif :** Filtre et deduplique la sortie de logs.

```bash
contextcrawler log <fichier>     # Depuis un fichier
contextcrawler log               # Depuis stdin (pipe)
```

Les lignes repetees sont fusionnees : `[ERROR] Connection refused (x42)`.

**Economies :** ~60-80% (selon la repetitivite)

---

### `contextcrawler curl` -- HTTP avec troncature

```bash
contextcrawler curl [args...]
```

Tronque les reponses longues et sauvegarde la sortie complete dans un fichier pour recuperation.

---

### `contextcrawler wget` -- Telechargement compact

```bash
contextcrawler wget <url> [args...]
contextcrawler wget -O - <url>           # Sortie vers stdout
```

Supprime les barres de progression et le bruit.

---

### `contextcrawler summary` -- Resume heuristique

**Objectif :** Execute une commande et genere un resume heuristique de la sortie.

```bash
contextcrawler summary <commande...>
```

Utile pour les commandes longues dont la sortie n'a pas de filtre dedie.

---

### `contextcrawler proxy` -- Passthrough avec suivi

**Objectif :** Execute une commande **sans filtrage** mais enregistre l'utilisation pour le suivi.

```bash
contextcrawler proxy <commande...>
```

Utile pour le debug : comparer la sortie brute avec la sortie filtree.

---

## Cloud et bases de donnees

### `contextcrawler aws` -- AWS CLI

```bash
contextcrawler aws <service> [args...]
```

Force la sortie JSON et compresse le resultat. Supporte tous les services AWS (sts, s3, ec2, ecs, rds, cloudformation, etc.).

---

### `contextcrawler psql` -- PostgreSQL

```bash
contextcrawler psql [args...]
```

Supprime les bordures de tableaux et compresse la sortie.

---

## Stacked PRs (Graphite)

### `contextcrawler gt` -- Graphite

| Commande | Description |
|----------|-------------|
| `contextcrawler gt log` | Stack log compact |
| `contextcrawler gt submit` | Submit compact |
| `contextcrawler gt sync` | Sync compact |
| `contextcrawler gt restack` | Restack compact |
| `contextcrawler gt create` | Create compact |
| `contextcrawler gt branch` | Branch info compact |

Les sous-commandes non reconnues sont transmises directement ou detectees comme passthrough git.

---

## Analytique et suivi

### Systeme de tracking

contextcrawler enregistre chaque execution de commande dans une base SQLite :

- **Emplacement :** `~/.local/share/ctxcrl/tracking.db` (Linux), `~/Library/Application Support/contextcrawler/tracking.db` (macOS)
- **Retention :** 90 jours automatique
- **Metriques :** tokens entree/sortie, pourcentage d'economies, temps d'execution, projet

---

### `contextcrawler gain` -- Statistiques d'economies

```bash
contextcrawler gain                        # Resume global
contextcrawler gain -p                     # Filtre par projet courant
contextcrawler gain --graph                # Graphe ASCII (30 derniers jours)
contextcrawler gain --history              # Historique recent des commandes
contextcrawler gain --daily                # Ventilation jour par jour
contextcrawler gain --weekly               # Ventilation par semaine
contextcrawler gain --monthly              # Ventilation par mois
contextcrawler gain --all                  # Toutes les ventilations
contextcrawler gain --quota -t pro         # Estimation d'economies sur le quota mensuel
contextcrawler gain --failures             # Log des echecs de parsing (commandes en fallback)
contextcrawler gain --format json          # Export JSON (pour dashboards)
contextcrawler gain --format csv           # Export CSV
```

**Options :**

| Option | Court | Description |
|--------|-------|-------------|
| `--project` | `-p` | Filtrer par repertoire courant |
| `--graph` | `-g` | Graphe ASCII des 30 derniers jours |
| `--history` | `-H` | Historique recent des commandes |
| `--quota` | `-q` | Estimation d'economies sur le quota mensuel |
| `--tier` | `-t` | Tier d'abonnement : `pro`, `5x`, `20x` (defaut: `20x`) |
| `--daily` | `-d` | Ventilation quotidienne |
| `--weekly` | `-w` | Ventilation hebdomadaire |
| `--monthly` | `-m` | Ventilation mensuelle |
| `--all` | `-a` | Toutes les ventilations |
| `--format` | `-f` | Format de sortie : `text`, `json`, `csv` |
| `--failures` | `-F` | Affiche les commandes en fallback |

**Exemple de sortie :**
```
$ contextcrawler gain
contextcrawler Token Savings Summary
  Total commands:     1,247
  Total input:        2,341,000 tokens
  Total output:       468,200 tokens
  Total saved:        1,872,800 tokens (80%)
  Avg per command:    1,501 tokens saved

Top commands:
  git status    312x  -82%
  cargo test    156x  -91%
  git diff       98x  -76%
```

---

### `contextcrawler discover` -- Opportunites manquees

**Objectif :** Analyse l'historique Claude Code pour trouver les commandes qui auraient pu etre optimisees par contextcrawler.

```bash
contextcrawler discover                          # Projet courant, 30 derniers jours
contextcrawler discover --all --since 7          # Tous les projets, 7 derniers jours
contextcrawler discover -p /chemin/projet        # Filtrer par projet
contextcrawler discover --limit 20              # Max commandes par section
contextcrawler discover --format json            # Export JSON
```

**Options :**

| Option | Court | Description |
|--------|-------|-------------|
| `--project` | `-p` | Filtrer par chemin de projet |
| `--limit` | `-l` | Max commandes par section (defaut: 15) |
| `--all` | `-a` | Scanner tous les projets |
| `--since` | `-s` | Derniers N jours (defaut: 30) |
| `--format` | `-f` | Format : `text`, `json` |

---

### `contextcrawler learn` -- Apprendre des erreurs

**Objectif :** Analyse l'historique d'erreurs CLI de Claude Code pour detecter les corrections recurrentes.

```bash
contextcrawler learn                             # Projet courant
contextcrawler learn --all --since 7             # Tous les projets
contextcrawler learn --write-rules               # Generer .claude/rules/cli-corrections.md
contextcrawler learn --min-confidence 0.8        # Seuil de confiance (defaut: 0.6)
contextcrawler learn --min-occurrences 3         # Occurrences minimales (defaut: 1)
contextcrawler learn --format json               # Export JSON
```

---

### `contextcrawler cc-economics` -- Analyse economique Claude Code

**Objectif :** Compare les depenses Claude Code (via ccusage) avec les economies contextcrawler.

```bash
contextcrawler cc-economics                      # Resume
contextcrawler cc-economics --daily              # Ventilation quotidienne
contextcrawler cc-economics --weekly             # Ventilation hebdomadaire
contextcrawler cc-economics --monthly            # Ventilation mensuelle
contextcrawler cc-economics --all                # Toutes les ventilations
contextcrawler cc-economics --format json        # Export JSON
```

---

### `contextcrawler hook-audit` -- Metriques du hook

**Prerequis :** Necessite `CTXCRL_HOOK_AUDIT=1` dans l'environnement.

```bash
contextcrawler hook-audit                        # 7 derniers jours (defaut)
contextcrawler hook-audit --since 30             # 30 derniers jours
contextcrawler hook-audit --since 0              # Tout l'historique
```

---

## Systeme de hooks

### Fonctionnement

Le hook contextcrawler intercepte les commandes Bash dans Claude Code **avant leur execution** et les reecrit automatiquement en equivalent contextcrawler.

**Flux :**
```
Claude Code "git status"
    |
    v
settings.json -> PreToolUse hook
    |
    v
rtk-rewrite.sh (bash)
    |
    v
contextcrawler rewrite "git status"  ->  "contextcrawler git status"
    |
    v
Claude Code execute "contextcrawler git status"
    |
    v
Sortie filtree retournee a Claude (~10 tokens vs ~200)
```

**Points cles :**
- Claude ne voit jamais la recriture -- il recoit simplement une sortie optimisee
- Le hook est un delegateur leger (~50 lignes bash) qui appelle `contextcrawler rewrite`
- Toute la logique de recriture est dans le registre Rust (`src/discover/registry.rs`)
- Les commandes deja prefixees par `contextcrawler` passent sans modification
- Les heredocs (`<<`) ne sont pas modifies
- Les commandes non reconnues passent sans modification

### Installation

```bash
contextcrawler init -g                     # Installation recommandee (hook + contextcrawler.md)
contextcrawler init -g --auto-patch        # Non-interactif (CI/CD)
contextcrawler init -g --hook-only         # Hook seul, sans contextcrawler.md
contextcrawler init --show                 # Verifier l'installation
contextcrawler init -g --uninstall         # Desinstaller
```

### Fichiers installes

| Fichier | Description |
|---------|-------------|
| `~/.claude/hooks/rtk-rewrite.sh` | Script hook (delegue a `contextcrawler rewrite`) |
| `~/.claude/contextcrawler.md` | Instructions minimales pour le LLM |
| `~/.claude/settings.json` | Enregistrement du hook PreToolUse |

### `contextcrawler rewrite` -- Recriture de commande

Commande interne utilisee par le hook. Imprime la commande reecrite sur stdout (exit 0) ou sort avec exit 1 si aucun equivalent contextcrawler n'existe.

```bash
contextcrawler rewrite "git status"           # -> "contextcrawler git status" (exit 0)
contextcrawler rewrite "terraform plan"       # -> (exit 1, pas de recriture)
contextcrawler rewrite "contextcrawler git status"       # -> "contextcrawler git status" (exit 0, inchange)
```

### `contextcrawler verify` -- Verification d'integrite

Verifie l'integrite du hook installe via un controle SHA-256.

```bash
contextcrawler verify
```

### Commandes reecrites automatiquement

| Commande brute | Reecrite en |
|----------------|-------------|
| `git status/diff/log/add/commit/push/pull` | `contextcrawler git ...` |
| `gh pr/issue/run` | `contextcrawler gh ...` |
| `cargo test/build/clippy/check` | `contextcrawler cargo ...` |
| `cat/head/tail <fichier>` | `contextcrawler read <fichier>` |
| `rg/grep <pattern>` | `contextcrawler grep <pattern>` |
| `ls` | `contextcrawler ls` |
| `tree` | `contextcrawler tree` |
| `wc` | `contextcrawler wc` |
| `jest` | `contextcrawler jest` |
| `vitest` | `contextcrawler vitest` |
| `tsc` | `contextcrawler tsc` |
| `eslint/biome` | `contextcrawler lint` |
| `prettier` | `contextcrawler prettier` |
| `playwright` | `contextcrawler playwright` |
| `prisma` | `contextcrawler prisma` |
| `ruff check/format` | `contextcrawler ruff ...` |
| `pytest` | `contextcrawler pytest` |
| `mypy` | `contextcrawler mypy` |
| `pip list/install` | `contextcrawler pip ...` |
| `go test/build/vet` | `contextcrawler go ...` |
| `golangci-lint` | `contextcrawler golangci-lint` |
| `docker ps/images/logs` | `contextcrawler docker ...` |
| `kubectl get/logs` | `contextcrawler kubectl ...` |
| `curl` | `contextcrawler curl` |
| `pnpm list/outdated` | `contextcrawler pnpm ...` |

### Exclusion de commandes

Pour empecher certaines commandes d'etre reecrites, ajoutez-les dans `config.toml` :

```toml
[hooks]
exclude_commands = ["curl", "playwright"]
```

---

## Configuration

### Fichier de configuration

**Emplacement :** `~/.config/ctxcrl/config.toml` (Linux) ou `~/Library/Application Support/contextcrawler/config.toml` (macOS)

**Commandes :**
```bash
contextcrawler config                # Afficher la configuration actuelle
contextcrawler config --create       # Creer le fichier avec les valeurs par defaut
```

### Structure complete

```toml
[tracking]
enabled = true              # Activer/desactiver le suivi
history_days = 90           # Jours de retention (nettoyage automatique)
database_path = "/custom/path/tracking.db"  # Chemin personnalise (optionnel)

[display]
colors = true               # Sortie coloree
emoji = true                # Utiliser les emojis
max_width = 120             # Largeur maximale de sortie

[filters]
ignore_dirs = [".git", "node_modules", "target", "__pycache__", ".venv", "vendor"]
ignore_files = ["*.lock", "*.min.js", "*.min.css"]

[tee]
enabled = true              # Activer la sauvegarde de sortie brute
mode = "failures"           # "failures" (defaut), "always", ou "never"
max_files = 20              # Rotation : garder les N derniers fichiers
# directory = "/custom/tee/path"  # Chemin personnalise (optionnel)

[telemetry]
enabled = false             # Telemetrie anonyme (1 ping/jour, requiert consentement)
# consent_given = true      # Defini automatiquement par `contextcrawler init` ou `contextcrawler telemetry enable`
# consent_date = "..."      # Date du consentement (RFC 3339)

[hooks]
exclude_commands = []       # Commandes a exclure de la recriture automatique
```

### Variables d'environnement

| Variable | Description |
|----------|-------------|
| `CTXCRL_TEE_DIR` | Surcharge le repertoire tee |
| `CTXCRL_TELEMETRY_DISABLED=1` | Desactiver la telemetrie |
| `CTXCRL_HOOK_AUDIT=1` | Activer l'audit du hook |
| `SKIP_ENV_VALIDATION=1` | Desactiver la validation d'env (Next.js, etc.) |

---

## Systeme Tee

### Recuperation de sortie brute

Quand une commande echoue, contextcrawler sauvegarde automatiquement la sortie brute complete dans un fichier log. Cela permet au LLM de lire la sortie sans re-executer la commande.

**Fonctionnement :**
1. La commande echoue (exit code != 0)
2. contextcrawler sauvegarde la sortie brute dans `~/.local/share/ctxcrl/tee/`
3. Le chemin du fichier est affiche dans la sortie filtree
4. Le LLM peut lire le fichier si besoin de plus de details

**Sortie :**
```
FAILED: 2/15 tests
[full output: ~/.local/share/ctxcrl/tee/1707753600_cargo_test.log]
```

**Configuration :**

| Parametre | Defaut | Description |
|-----------|--------|-------------|
| `tee.enabled` | `true` | Activer/desactiver |
| `tee.mode` | `"failures"` | `"failures"`, `"always"`, `"never"` |
| `tee.max_files` | `20` | Rotation : garder les N derniers |
| Taille min | 500 octets | Les sorties trop courtes ne sont pas sauvegardees |
| Taille max fichier | 1 Mo | Troncature au-dela |

---

## Telemetrie

contextcrawler peut envoyer un ping anonyme une fois par jour (23h d'intervalle) pour des statistiques d'utilisation. La telemetrie est **desactivee par defaut** et requiert un consentement explicite (RGPD Art. 6, 7).

**Donnees envoyees :** hash de device (SHA-256 d'un sel aleatoire), version, OS, architecture, nombre de commandes/24h, top commandes, pourcentage d'economies.

**Responsable du traitement :** `contextcrawler AI Labs`, contact@rtk-ai.app

**Gerer la telemetrie :**
```bash
contextcrawler telemetry status     # Voir l'etat du consentement
contextcrawler telemetry enable     # Donner son consentement (prompt interactif)
contextcrawler telemetry disable    # Retirer son consentement
contextcrawler telemetry forget     # Retirer + supprimer donnees locales + demande d'effacement serveur
```

**Desactiver via variable d'environnement :**
```bash
export CTXCRL_TELEMETRY_DISABLED=1
```

Aucune donnee personnelle, aucun contenu de commande, aucun chemin de fichier n'est transmis. Conservation serveur : 12 mois max. Details : [docs/TELEMETRY.md](../TELEMETRY.md)

---

## Resume des economies par categorie

| Categorie | Commandes | Economies typiques |
|-----------|-----------|-------------------|
| **Fichiers** | ls, tree, read, find, grep, diff | 60-80% |
| **Git** | status, log, diff, show, add, commit, push, pull | 75-92% |
| **GitHub** | pr, issue, run, api | 26-87% |
| **Tests** | cargo test, vitest, playwright, pytest, go test | 90-99% |
| **Build/Lint** | cargo build, tsc, eslint, prettier, next, ruff, clippy | 70-87% |
| **Paquets** | pnpm, npm, pip, deps, prisma | 60-80% |
| **Conteneurs** | docker, kubectl | 70-80% |
| **Donnees** | json, env, log, curl, wget | 60-80% |
| **Analytique** | gain, discover, learn, cc-economics | N/A (meta) |

---

## Nombre total de commandes

contextcrawler supporte **45+ commandes** reparties en 9 categories, avec passthrough automatique pour les sous-commandes non reconnues. Cela en fait un proxy universel : il est toujours sur a utiliser en prefixe.
