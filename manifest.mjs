// Envio de eventos de manifestação do destinatário: NF-e/CT-e via SOAP SEFAZ, NFS-e via ADN.
// Os eventos são assinados (XMLDSig RSA-SHA1) com a chave extraída do .pfx via node-forge.
import { request } from "undici";
import { XMLParser } from "fast-xml-parser";
import forge from "node-forge";

const EVENT_SERVICES = {
  nfe: { producao: "https://www1.nfe.fazenda.gov.br/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx", homologacao: "https://hom1.nfe.fazenda.gov.br/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx", ns: "http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4", op: "nfeRecepcaoEvento", dados: "nfeDadosMsg" },
  cte: { producao: "https://www1.cte.fazenda.gov.br/CTeRecepcaoEventoV4/CTeRecepcaoEventoV4.asmx", homologacao: "https://hom1.cte.fazenda.gov.br/CTeRecepcaoEventoV4/CTeRecepcaoEventoV4.asmx", ns: "http://www.portalfiscal.inf.br/cte/wsdl/CTeRecepcaoEventoV4", op: "cteRecepcaoEvento", dados: "cteDadosMsg" },
};

const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: "@", removeNSPrefix: true, parseTagValue: false, processEntities: false });
const escapeXml = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

function extractKeyCert(pfxBuffer, password) {
  const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(pfxBuffer.toString("binary")), password);
  let key = null;
  let cert = null;
  for (const safe of p12.safeContents) {
    for (const bag of safe.safeBags) {
      if ((bag.type === forge.pki.oids.pkcs8ShroudedKeyBag || bag.type === forge.pki.oids.keyBag) && !key) key = bag.key;
      if (bag.type === forge.pki.oids.certBag && bag.cert && !cert) cert = bag.cert;
    }
  }
  if (!key || !cert) throw new Error("Não foi possível extrair chave e certificado do arquivo para assinar o evento.");
  return { key, certDerB64: forge.util.encode64(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes()) };
}

const sha1B64 = (str) => { const md = forge.md.sha1.create(); md.update(str, "utf8"); return forge.util.encode64(md.digest().bytes()); };

// Assinatura enveloped do infEvento. Como o XML é gerado aqui sem espaços entre tags,
// a forma já é a canônica (C14N), então o digest/signature incidem sobre a string literal.
function signInfEvento(key, certDerB64, infXml, id) {
  const digest = sha1B64(infXml);
  const signedInfo = `<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI="#${id}"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>${digest}</DigestValue></Reference></SignedInfo>`;
  const md = forge.md.sha1.create();
  md.update(signedInfo, "utf8");
  const sig = forge.util.encode64(key.sign(md));
  return `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">${signedInfo}<SignatureValue>${sig}</SignatureValue><KeyInfo><X509Data><X509Certificate>${certDerB64}</X509Certificate></X509Data></KeyInfo></Signature>`;
}

const dhEvento = () => new Date().toLocaleString("sv-SE", { timeZone: "America/Sao_Paulo" }).replace(" ", "T") + "-03:00";

function buildEvento(source, body) {
  const { environment, cnpj, chave, code, descricao, justificativa } = body;
  const id = `ID${code}${chave}01`;
  const tpAmb = environment === "producao" ? 1 : 2;
  const just = justificativa ? `<xJust>${escapeXml(justificativa)}</xJust>` : "";
  if (source === "nfe") {
    const det = `<detEvento versao="1.00"><descEvento>${escapeXml(descricao)}</descEvento>${just}</detEvento>`;
    const inf = `<infEvento Id="${id}"><cOrgao>91</cOrgao><tpAmb>${tpAmb}</tpAmb><CNPJ>${cnpj}</CNPJ><chNFe>${chave}</chNFe><dhEvento>${dhEvento()}</dhEvento><tpEvento>${code}</tpEvento><nSeqEvento>1</nSeqEvento><verEvento>1.00</verEvento>${det}</infEvento>`;
    return { id, inf, wrap: (sig) => `<envEvento versao="1.00" xmlns="http://www.portalfiscal.inf.br/nfe"><idLote>1</idLote><evento versao="1.00">${inf}${sig}</evento></envEvento>` };
  }
  // CT-e / CT-e OS: evento 610110 Prestação do Serviço em Desacordo (layout 4.00)
  const det = `<detEvento versao="4.00"><evPrestDesacordo><descEvento>${escapeXml(descricao)}</descEvento><indDesacordoOper>1</indDesacordoOper><xObs>${escapeXml(justificativa ?? "")}</xObs></evPrestDesacordo></detEvento>`;
  const inf = `<infEvento Id="${id}"><cOrgao>${body.uf_code ?? "91"}</cOrgao><tpAmb>${tpAmb}</tpAmb><CNPJ>${cnpj}</CNPJ><chCTe>${chave}</chCTe><dhEvento>${dhEvento()}</dhEvento><tpEvento>${code}</tpEvento><nSeqEvento>1</nSeqEvento><verEvento>4.00</verEvento>${det}</infEvento>`;
  return { id, inf, wrap: (sig) => `<envEventoCTe versao="4.00" xmlns="http://www.portalfiscal.inf.br/cte"><idLote>1</idLote><eventoCTe versao="4.00">${inf}${sig}</eventoCTe></envEventoCTe>` };
}

function findNode(value, name) {
  if (!value || typeof value !== "object") return null;
  if (value[name]) return value[name];
  for (const item of Object.values(value)) {
    if (typeof item === "string" && item.includes(`<${name}`)) { const found = findNode(parser.parse(item), name); if (found) return found; }
    const found = findNode(item, name);
    if (found) return found;
  }
  return null;
}

export function parseEventResponse(xml) {
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw new Error("Resposta XML SEFAZ inválida.");
  const ret = findNode(parser.parse(xml), "retEnvEvento");
  if (!ret) throw new Error("Resposta inesperada do serviço de eventos SEFAZ.");
  const inf = ret.infEvento ?? {};
  return {
    code: String(ret.cStat ?? ""),
    message: String(ret.xMotivo ?? ""),
    event_code: String(inf.cStat ?? ""),
    event_message: String(inf.xMotivo ?? ""),
    protocol: inf.nProt ? String(inf.nProt) : null,
  };
}

export async function sefazEvent(body, dispatcher, pfxBuffer, password) {
  const service = EVENT_SERVICES[body.source];
  if (!service || !["producao", "homologacao"].includes(body.environment)) throw new Error("Serviço de evento SEFAZ inválido.");
  if (!/^\d{14}$/.test(String(body.cnpj ?? "")) || !/^\d{44}$/.test(String(body.chave ?? ""))) throw new Error("CNPJ ou chave inválidos para o evento.");
  const { key, certDerB64 } = extractKeyCert(pfxBuffer, password);
  const { id, inf, wrap } = buildEvento(body.source, body);
  const signed = wrap(signInfEvento(key, certDerB64, inf, id));
  const envelope = `<?xml version="1.0" encoding="utf-8"?><soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope"><soap12:Body><${service.op} xmlns="${service.ns}"><${service.dados}>${signed}</${service.dados}></${service.op}></soap12:Body></soap12:Envelope>`;
  const response = await request(service[body.environment], { method: "POST", dispatcher, headersTimeout: 30000, bodyTimeout: 30000, headers: { "content-type": `application/soap+xml; charset=utf-8; action="${service.ns}/${service.op}"`, accept: "application/soap+xml" }, body: envelope });
  const raw = await response.body.text();
  if (response.statusCode !== 200) throw new Error(`SEFAZ indisponível (HTTP ${response.statusCode}).`);
  const r = parseEventResponse(raw);
  const ok = r.code === "135" || r.code === "136" || r.event_code === "135" || r.event_code === "136";
  return { ok, code: r.event_code || r.code, message: r.event_message || r.message, protocol: r.protocol };
}

// Manifestação de NFS-e no ADN. O caminho do endpoint é configurado por env após conferência
// no Swagger oficial (/contribuintes/docs) — nunca assumimos uma rota não documentada.
export async function adnManifest(body, dispatcher, hosts, pfxBuffer, password) {
  const path = process.env.ADN_MANIFEST_PATH ?? "";
  if (!path) throw new Error("Manifestação de NFS-e não configurada no serviço de integração (defina ADN_MANIFEST_PATH conforme o Swagger do ADN).");
  if (!/^\d{14}$/.test(String(body.cnpj ?? "")) || !String(body.chave ?? "").replace(/\D/g, "").length) throw new Error("CNPJ ou chave inválidos para o evento.");
  const { key, certDerB64 } = extractKeyCert(pfxBuffer, password);
  const id = `ID${body.code}${String(body.chave).replace(/\D/g, "")}01`;
  const inf = `<infEvento Id="${id}"><tpAmb>${body.environment === "producao" ? 1 : 2}</tpAmb><CNPJ>${body.cnpj}</CNPJ><chNFSe>${body.chave}</chNFSe><dhEvento>${dhEvento()}</dhEvento><tpEvento>${body.code}</tpEvento><nSeqEvento>1</nSeqEvento><verEvento>1.00</verEvento><detEvento versao="1.00"><descEvento>${escapeXml(body.descricao ?? "Manifestacao do Tomador")}</descEvento></detEvento></infEvento>`;
  const signed = `<evento versao="1.00" xmlns="http://www.sped.fazenda.gov.br/nfse">${inf}${signInfEvento(key, certDerB64, inf, id)}</evento>`;
  const url = `${hosts.adn}${path.replace("{chave}", encodeURIComponent(String(body.chave)))}`;
  const r = await request(url, { method: "POST", dispatcher, headersTimeout: 30000, bodyTimeout: 30000, headers: { "content-type": "application/xml", accept: "application/json" }, body: signed });
  const text = await r.body.text();
  let json = null;
  try { json = JSON.parse(text); } catch { json = { raw: text.slice(0, 500) }; }
  const ok = r.statusCode >= 200 && r.statusCode < 300;
  return { ok, code: String(r.statusCode), message: ok ? "Evento registrado no ADN." : String(json?.Erros?.[0]?.Descricao ?? json?.raw ?? `ADN respondeu HTTP ${r.statusCode}`), protocol: json?.Protocolo ?? json?.protocolo ?? null };
}
