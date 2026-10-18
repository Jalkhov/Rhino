# Integración continua (desactivada)

Estos flujos están escritos y listos, pero **no se ejecutan**: viven aquí en vez de en
`.github/workflows/` porque la cuenta de GitHub está bloqueada por una deuda.

Para reactivarlos, cuando la cuenta vuelva a estar operativa:

```sh
mkdir -p .github/workflows
git mv ci/ci.yml ci/db.yml .github/workflows/
```

`db.yml` necesita además el secreto `RHINO_DB_KEY` con la clave privada de firma.
Mientras tanto, el paquete de base de datos se construye y publica a mano con
`web/tools/publish-db.sh`.
