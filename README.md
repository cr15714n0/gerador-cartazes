# Gerador de Cartazes Promocionais

Sistema web completo para geração e impressão de cartazes de ofertas para supermercados e comércio em geral, com suporte a múltiplos formatos (A4, A4 Paisagem, 2x A5 e A3), importação de planilhas Excel e autenticação segura no servidor.

## 🔒 Segurança Reforçada (Server-Side)
- **Autenticação no Servidor**: O código do gerador (`private/app.html`) **nunca** é enviado ao navegador sem autenticação válida.
- **Proteção Anti-Brute Force**: Bloqueio de IP automático com limite de 5 tentativas a cada 15 minutos (`express-rate-limit`).
- **Cookies HttpOnly & Signed**: Proteção total contra roubo de sessão e injeção XSS.
- **Timing-Safe Protection**: Comparação de usuário e senha resistente a Timing Attacks.
- **Headers HTTP Seguros**: Protegido com `helmet` (Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options).

## ⚙️ Configuração de Usuário e Senha (Easypanel)
No painel do Easypanel, acesse o serviço do projeto e clique na aba **Ambiente (Environment)**:

| Variável | Padrão | Descrição |
|---|---|---|
| `ADMIN_USER` | `admin` | Nome de usuário de acesso |
| `ADMIN_PASSWORD` | `cartazes2026` | Senha de acesso ao sistema |
| `SESSION_SECRET` | *gerado dinamicamente* | Segredo para assinatura de cookies |

Ao salvar novas variáveis no Easypanel e clicar em **Salvar**, o painel recarrega o container com suas credenciais seguras.

## 🚀 Como Rodar Localmente (Docker)
```bash
docker build -t gerador-cartazes .
docker run -p 80:80 gerador-cartazes
```
Acesse `http://localhost`.
