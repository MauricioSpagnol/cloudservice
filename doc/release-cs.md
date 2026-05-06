# Publicar uma Release CS Coin

As releases são geradas automaticamente via GitHub Actions ao criar uma tag.
Os assets publicados são: `csd-linux-amd64-vX.Y.Z.tar.gz` e `SHA256SUMS`.

---

## Passo a passo

```bash
# 1. Certifique-se de estar na branch main com tudo commitado
git checkout main
git pull

# 2. Criar a tag (substitua X.Y.Z pela versão)
git tag v1.0.0

# 3. Fazer push da tag — isso dispara o workflow de build e release
git push origin v1.0.0
```

Após o push da tag, o workflow `.github/workflows/release.yml` executa automaticamente:

1. Compila `csd`, `cs-cli`, `cs-tx` do zero em Ubuntu 22.04
2. Empacota em `csd-linux-amd64-v1.0.0.tar.gz`
3. Gera `SHA256SUMS`
4. Publica a release no GitHub

---

## Acompanhar o build

Acesse a aba **Actions** no repositório para ver o progresso:

```
https://github.com/MauricioSpagnol/cscoin/actions
```

O build leva aproximadamente **20–40 minutos** (depende do cache do `depends/`).

---

## A tag foi criada mas o release não apareceu

**1. Verifique se o workflow rodou:**
```
https://github.com/MauricioSpagnol/cscoin/actions
```
Se aparece com ❌, clique para ver o erro e corrija.

**2. Rode o workflow manualmente pela tag existente:**

Se a tag já existe no GitHub mas o workflow falhou ou não foi disparado:

```bash
# Re-dispara o workflow para a tag já publicada
gh workflow run release.yml --repo MauricioSpagnol/cscoin --ref v1.0.0
```

**3. Se precisar recriar a tag do zero:**

```bash
# Remove a tag localmente e no GitHub
git tag -d v1.0.0
git push origin --delete v1.0.0

# Recria e faz push novamente
git tag v1.0.0
git push origin v1.0.0
```

> Só delete a tag remota se a release ainda não foi publicada,
> pois isso invalida downloads em andamento.
