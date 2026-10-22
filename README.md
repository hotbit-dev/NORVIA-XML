# nfse-bridge

Serviço externo necessário para a integração real com o Sistema Nacional NFS-e.

**Por quê:** a API de Distribuição do ADN exige autenticação mTLS com o certificado A1 da empresa.
O servidor da plataforma roda em ambiente edge, que não permite usar um certificado de cliente
diferente por requisição. Este serviço Node.js faz apenas essa conexão.

## Endpoints oficiais usados
Fonte: https://www.gov.br/nfse/pt-br/biblioteca/documentacao-tecnica/apis-prod-restrita-e-producao
e Manual dos Contribuintes – APIs do ADN (v1.0, 12/02/2026).

| Uso | Produção restrita (homologação) | Produção |
|---|---|---|
| Distribuição `GET /DFe/{NSU}` | `https://adn.producaorestrita.nfse.gov.br/contribuintes` | `https://adn.nfse.gov.br/contribuintes` |
| DANFSe `GET /{chaveAcesso}` | `https://adn.producaorestrita.nfse.gov.br/danfse` | `https://adn.nfse.gov.br/danfse` |

## Publicação (Render, Fly.io, Railway, VPS...)
1. Publique esta pasta com Node 20+ (`npm install && npm start`). HTTPS é obrigatório.
2. Variáveis de ambiente:
   - `BRIDGE_TOKEN` — valor aleatório forte (mesmo valor de `NFSE_BRIDGE_TOKEN` na plataforma).
   - `ADN_DFE_QUERY` (opcional) — query string extra para `/DFe/{NSU}`, ex. `lote=true`. Confirme no Swagger oficial.
   - `ADN_CNPJ_CONSULTA_PARAM` (opcional) — nome do parâmetro de CNPJ de consulta, se for consultar filiais com certificado da matriz.
3. Na plataforma, configure os segredos `NFSE_BRIDGE_URL` (ex. `https://meu-bridge.onrender.com`) e `NFSE_BRIDGE_TOKEN`.
4. Use **Testar conexão** na aba Certificado.

## Segurança
- Não persiste nem registra certificados, senhas ou corpos de requisição.
- Aceita apenas chamadas com `Authorization: Bearer BRIDGE_TOKEN`.
- Restrinja o acesso de rede, se possível, ao domínio da plataforma.

## Distribuição SEFAZ

O endpoint autenticado `POST /sefaz/dfe` recebe o certificado em memória e consulta um serviço permitido: `nfe`, `cte` (inclui CT-e OS e GTV-e) ou `mdfe`. As URLs estão fixadas em `sefaz.mjs`, com SOAP 1.2 e NSU decimal de 15 dígitos.

Para atualizar o Render, envie **server.mjs, sefaz.mjs e package.json na raiz do mesmo repositório**, substituindo os anteriores e incluindo o arquivo novo. Mantenha `BRIDGE_TOKEN` e os comandos `npm install` / `npm start` existentes. O Render precisa concluir o novo deploy antes de testar a busca SEFAZ.

Fontes oficiais: https://www.nfe.fazenda.gov.br/portal/webservices.aspx ; https://www.cte.fazenda.gov.br/portal/webServices.aspx ; https://dfe-portal.svrs.rs.gov.br/MDFE/Servicos .

- Distribuição depende de autorização do CNPJ e tem retenção limitada; não é recuperação de todo XML próprio emitido.
- NF-e pode chegar como resumo, aguardando liberação do XML completo. O sistema não manifesta nem confirma operações automaticamente.
- NFCom não tem distribuição nacional por NSU identificada. NFC-e não faz parte da busca.
- O aplicativo mantém cursores separados, salva antes de avançar e limita consultas a dez por execução. Ao encerrar um fluxo ou receber consumo indevido, espera uma hora antes de consultar novamente.
- Integrações SEFAZ têm testes de contrato e parsing, mas a operação real permanece pendente de atualização no Render e validação com certificado elegível.
- O DANFSe agora é gerado pelo aplicativo usando o XML; `/adn/danfse` permanece apenas por compatibilidade com versões anteriores.
