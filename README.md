# Diva Homelab

Este repositório documenta, de forma sanitizada, um homelab baseado em
Docker Compose, Komodo, Tailscale, autenticação centralizada e proxy reverso.

## Escopo

- 25 contêineres distribuídos por 15 projetos Compose.
- Catálogo público de serviços e arquitetura de recuperação.
- Backups diários de configuração e estado dos aplicativos em um bucket
  privado do Google Cloud Storage.
- Restauração manual pelo GitHub Actions, usando Tailscale e SSH.
- Mídia e arquivos compartilhados ficam fora do backup de aplicativos.

Os dados do servidor não estão neste repositório. O repositório privado
`diva-homelab-deploy` contém os workflows e scripts operacionais. Os backups
ficam criptografados com age antes de sair do servidor.

## Estrutura

- `inventory/services.yaml`: catálogo sanitizado dos serviços.
- `docs/backup-restore.md`: arquitetura, escopo e limites da recuperação.

## Segurança

Este repositório não deve conter domínios ativos, endereços Tailscale ou LAN,
usuários, senhas, tokens, chaves SSH, arquivos `.env`, dumps, certificados
privados ou backups.

Revise alterações antes de publicar. Use somente valores fictícios em exemplos.
