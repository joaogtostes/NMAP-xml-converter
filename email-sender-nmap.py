import subprocess
import os
import smtplib # Continuaremos usando smtplib, mas para localhost
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from email.utils import formatdate  # Correção: importar formatdate do email.utils
import xml.etree.ElementTree as ET
from datetime import datetime

# --- Configurações ---
NMAP_TARGETS = "192.168.56.0/24"
NMAP_ARGS = "-sS -sV -O -T5 --osscan-guess"
OUTPUT_XML_FILE = "nmap_scan_report.xml"
LOG_FILE = "nmap_email_log.txt"

# Configurações de E-mail (Simplificado para Postfix local)
# SMTP_SERVER e SMTP_PORT não são mais estritamente necessários para localhost,
# mas smtplib.SMTP('localhost') usará a porta padrão 25.
EMAIL_SENDER_ADDRESS = f'nmap-reporter@{os.uname()[1]}' # Ex: nmap-reporter@nomedasuavm
# EMAIL_SENDER_PASSWORD não é necessário para Postfix local sem autenticação
EMAIL_RECEIVER_ADDRESS = 'EMAIL@GMAIL.COM'
EMAIL_SUBJECT_PREFIX = "Relatório Nmap Scan"

# --- Funções Auxiliares (log_message, run_nmap_scan, get_element_text, parse_nmap_xml_to_html) ---
# MANTENHA ESSAS FUNÇÕES IGUAIS AO EXEMPLO ANTERIOR

def log_message(message):
    """Registra uma mensagem com timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"[{timestamp}] {message}\n"
    print(full_message.strip())
    with open(LOG_FILE, "a") as f:
        f.write(full_message)

def run_nmap_scan():
    """Executa o scan Nmap e salva o XML."""
    log_message(f"Iniciando scan Nmap em: {NMAP_TARGETS}")
    command = ["nmap"] + NMAP_ARGS.split() + ["-oX", OUTPUT_XML_FILE, NMAP_TARGETS]
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(timeout=1800)
        if process.returncode == 0:
            log_message(f"Scan Nmap concluído. XML salvo em: {OUTPUT_XML_FILE}")
            return True
        else:
            log_message(f"Erro ao executar Nmap. Código de saída: {process.returncode}")
            log_message(f"Nmap stdout: {stdout.decode(errors='ignore')}")
            log_message(f"Nmap stderr: {stderr.decode(errors='ignore')}")
            return False
    except subprocess.TimeoutExpired:
        log_message("Erro: Scan Nmap excedeu o tempo limite.")
        process.kill()
        stdout, stderr = process.communicate()
        log_message(f"Nmap stdout (timeout): {stdout.decode(errors='ignore')}")
        log_message(f"Nmap stderr (timeout): {stderr.decode(errors='ignore')}")
        return False
    except Exception as e:
        log_message(f"Exceção ao executar Nmap: {e}")
        return False

def get_element_text(element, tag_name, attribute=None, default='N/A'):
    """Obtém texto de um subelemento ou atributo de forma segura."""
    try:
        target_element = element.find(tag_name)
        if target_element is None:
            return default
        if attribute:
            return target_element.get(attribute, default)
        else:
            return target_element.text or default
    except AttributeError: # Em caso de element ser None
        return default


def parse_nmap_xml_to_html(xml_file):
    """
    Analisa o arquivo XML do Nmap e gera uma string HTML simplificada para o e-mail.
    Esta é uma versão simplificada da sua lógica JavaScript.
    (MANTENHA ESTA FUNÇÃO IGUAL AO EXEMPLO ANTERIOR, COM AS CORREÇÕES JÁ FEITAS)
    """
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        log_message(f"Erro ao parsear XML: {e}")
        return "<html><body><h1>Erro ao processar relatório Nmap</h1><p>O arquivo XML não pôde ser analisado.</p></body></html>"
    except FileNotFoundError:
        log_message(f"Arquivo XML não encontrado: {xml_file}")
        return "<html><body><h1>Erro ao processar relatório Nmap</h1><p>Arquivo XML do scan não encontrado.</p></body></html>"


    html_content = """
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; }
            .container { background-color: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            h1, h2, h3 { color: #2c3e50; }
            .scan-info, .host-section { margin-bottom: 20px; padding: 15px; border-left: 4px solid #3498db; background-color: #f9f9f9; }
            table { width: 100%; border-collapse: collapse; margin-top: 10px; }
            th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background-color: #e9ecef; }
            .port-open { color: #27ae60; font-weight: bold; }
            .port-closed { color: #e74c3c; }
            .port-filtered { color: #f39c12; }
            .status-up { background-color: #d4edda; color: #155724; padding: 3px 6px; border-radius: 3px; display: inline-block; }
            .status-down { background-color: #f8d7da; color: #721c24; padding: 3px 6px; border-radius: 3px; display: inline-block; }
            .os-info { background-color: #fff3cd; padding: 10px; border-left: 4px solid #ffeeba; margin: 10px 0; }
            .summary-box { display: inline-block; background-color: #e9ecef; border-radius: 4px; padding: 10px; margin-right: 10px; margin-bottom: 10px; min-width:150px; text-align:center;}
            .summary-box h4 { margin-top: 0; color: #495057; font-size: 0.9em;}
            .summary-box p { font-size: 1.5em; font-weight: bold; margin: 0; color: #2c3e50; }
        </style>
    </head>
    <body>
        <div class="container">
    """

    nmaprun_attrib = root.attrib
    start_time_unix = int(nmaprun_attrib.get('start', '0'))
    start_time_str = datetime.fromtimestamp(start_time_unix).strftime('%Y-%m-%d %H:%M:%S') if start_time_unix else 'N/A'

    html_content += f"<h1>Relatório do Scan Nmap</h1>"
    html_content += "<div class='scan-info'>"
    html_content += f"<h2>Informações Gerais do Scan</h2>"
    html_content += f"<p><strong>Versão Nmap:</strong> {nmaprun_attrib.get('version', 'N/A')}</p>"
    html_content += f"<p><strong>Argumentos:</strong> {nmaprun_attrib.get('args', 'N/A')}</p>"
    html_content += f"<p><strong>Data de Início:</strong> {start_time_str}</p>"
    html_content += "</div>"

    hosts_up = 0
    total_ports_found_scan = 0 # Renomeado para evitar conflito com variável local em loop
    open_ports_count_scan = 0 # Renomeado
    host_elements = root.findall('host')
    for host_elem_summary in host_elements: # Variável de loop diferente
        status_elem_summary = host_elem_summary.find('status')
        if status_elem_summary is not None and status_elem_summary.get('state') == 'up':
            hosts_up += 1
        ports_elem_summary = host_elem_summary.find('ports')
        if ports_elem_summary is not None:
            for port_elem_summary in ports_elem_summary.findall('port'):
                total_ports_found_scan +=1
                state_elem_summary = port_elem_summary.find('state')
                if state_elem_summary is not None and state_elem_summary.get('state') == 'open':
                    open_ports_count_scan +=1

    html_content += "<h2>Sumário do Scan</h2>"
    html_content += "<div>"
    html_content += f"<div class='summary-box'><h4>Hosts Escaneados</h4><p>{len(host_elements)}</p></div>"
    html_content += f"<div class='summary-box'><h4>Hosts Ativos</h4><p>{hosts_up}</p></div>"
    html_content += f"<div class='summary-box'><h4>Portas Encontradas</h4><p>{total_ports_found_scan}</p></div>"
    html_content += f"<div class='summary-box'><h4>Portas Abertas</h4><p>{open_ports_count_scan}</p></div>"
    html_content += "</div>"

    html_content += "<h2>Detalhes dos Hosts</h2>"
    if not host_elements:
        html_content += "<p>Nenhum host encontrado no scan.</p>"

    for host_detail in host_elements: # Variável de loop diferente
        html_content += "<div class='host-section'>"
        ip_address = "N/A"
        hostname = ""
        status_state = get_element_text(host_detail, 'status', 'state', 'unknown')
        status_reason = get_element_text(host_detail, 'status', 'reason', '')

        address_elements = host_detail.findall('address')
        for addr in address_elements:
            addr_type = addr.get('addrtype')
            if addr_type == 'ipv4' or addr_type == 'ipv6':
                ip_address = addr.get('addr', 'N/A')

        hostnames_element = host_detail.find('hostnames')
        if hostnames_element is not None:
            hostname_tag = hostnames_element.find('hostname')
            if hostname_tag is not None:
                hostname = hostname_tag.get('name', '')

        status_class = "status-up" if status_state == "up" else ("status-down" if status_state == "down" else "")
        html_content += f"<h3>Host: {ip_address} {f'({hostname})' if hostname else ''} <span class='{status_class}'>{status_state.upper()}</span></h3>"
        if status_reason:
             html_content += f"<p><small>Razão do status: {status_reason}</small></p>"

        os_element = host_detail.find('os')
        if os_element is not None:
            osmatch_elements = os_element.findall('osmatch')
            if osmatch_elements:
                best_match = osmatch_elements[0]
                os_name = best_match.get('name', 'N/A')
                accuracy = best_match.get('accuracy', 'N/A')
                html_content += "<div class='os-info'>"
                html_content += f"<p><strong>Sistema Operacional (Estimado):</strong> {os_name} ({accuracy}% de certeza)</p>"
                osclass_elements = best_match.findall('osclass')
                if osclass_elements:
                    os_class = osclass_elements[0]
                    html_content += "<p>"
                    if os_class.get('type'): html_content += f"<strong>Tipo:</strong> {os_class.get('type', 'N/A')} "
                    if os_class.get('vendor'): html_content += f"<strong>Fornecedor:</strong> {os_class.get('vendor', 'N/A')} "
                    if os_class.get('osfamily'): html_content += f"<strong>Família:</strong> {os_class.get('osfamily', 'N/A')}"
                    html_content += "</p>"
                html_content += "</div>"

        ports_section = host_detail.find('ports')
        if ports_section is not None:
            # Filtrar apenas portas abertas para exibição no e-mail para economizar espaço
            open_ports_list = [p for p in ports_section.findall('port') if get_element_text(p, 'state', 'state') == 'open']
            if open_ports_list:
                html_content += "<h4>Portas Abertas e Serviços:</h4>"
                html_content += "<table><tr><th>Porta</th><th>Protocolo</th><th>Estado</th><th>Serviço</th><th>Produto/Versão</th></tr>"
                for port_detail in open_ports_list: # Variável de loop diferente
                    portid = port_detail.get('portid', 'N/A')
                    protocol = port_detail.get('protocol', 'N/A')
                    state = get_element_text(port_detail, 'state', 'state', 'N/A')
                    service_elem = port_detail.find('service')
                    service_name = get_element_text(service_elem, 'name', default='N/A') if service_elem is not None else 'N/A'

                    product_version_parts = [] # Renomeado para evitar conflito
                    if service_elem is not None:
                        if service_elem.get('product'): product_version_parts.append(service_elem.get('product'))
                        if service_elem.get('version'): product_version_parts.append(service_elem.get('version'))
                        if service_elem.get('extrainfo'): product_version_parts.append(f"({service_elem.get('extrainfo')})")

                    version_str = " ".join(product_version_parts) if product_version_parts else "N/A"

                    port_class = "port-open" # Já filtramos para open
                    html_content += f"<tr><td>{portid}</td><td>{protocol}</td><td class='{port_class}'>{state}</td><td>{service_name}</td><td>{version_str}</td></tr>"
                html_content += "</table>"
            else:
                html_content += "<p>Nenhuma porta aberta encontrada para este host.</p>"
        else:
            html_content += "<p>Nenhuma informação de porta encontrada para este host.</p>" # Caso a tag <ports> esteja ausente
        html_content += "</div>"

    html_content += """
        </div>
    </body>
    </html>
    """
    return html_content


def send_email(subject, html_body, attachment_path=None):
    """Envia um e-mail usando o Postfix local."""
    log_message(f"Tentando enviar e-mail para: {EMAIL_RECEIVER_ADDRESS} via Postfix local")
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = EMAIL_SENDER_ADDRESS
        msg['To'] = EMAIL_RECEIVER_ADDRESS
        msg['Subject'] = f"{EMAIL_SUBJECT_PREFIX}: {subject} ({datetime.now().strftime('%Y-%m-%d %H:%M')})"
        # Adiciona o cabeçalho Date para melhor conformidade - CORREÇÃO AQUI
        msg['Date'] = formatdate(localtime=True)  # Usando formatdate do email.utils


        # Garante que o corpo do e-mail seja tratado como UTF-8
        msg.attach(MIMEText(html_body, 'html', 'utf-8'))

        if attachment_path and os.path.exists(attachment_path):
            try:
                with open(attachment_path, "rb") as attachment:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header(
                    "Content-Disposition",
                    f"attachment; filename= {os.path.basename(attachment_path)}",
                )
                msg.attach(part)
                log_message(f"Arquivo {attachment_path} anexado ao e-mail.")
            except Exception as e:
                log_message(f"Erro ao anexar arquivo {attachment_path}: {e}")

        # Conectar ao Postfix local (geralmente na porta 25)
        # Não é necessário login/senha se o Postfix estiver configurado para aceitar e-mails do localhost
        with smtplib.SMTP('localhost') as server: # Não precisa de porta se for a padrão (25)
            # server.set_debuglevel(1) # Descomente para debugging SMTP
            server.sendmail(EMAIL_SENDER_ADDRESS, EMAIL_RECEIVER_ADDRESS, msg.as_string())
        log_message("E-mail enfileirado com sucesso pelo Postfix local!")
        return True
    except smtplib.SMTPServerDisconnected:
        log_message("Erro: Servidor SMTP (Postfix local) desconectou inesperadamente.")
    except smtplib.SMTPRecipientsRefused:
        log_message(f"Erro: Todos os destinatários ({EMAIL_RECEIVER_ADDRESS}) foram recusados pelo Postfix. Verifique os logs do Postfix.")
    except smtplib.SMTPSenderRefused:
        log_message(f"Erro: O endereço do remetente ({EMAIL_SENDER_ADDRESS}) foi recusado pelo Postfix. Verifique a configuração do Postfix.")
    except smtplib.SMTPDataError:
        log_message("Erro: O servidor SMTP (Postfix local) recusou os dados da mensagem.")
    except smtplib.SMTPException as e:
        log_message(f"Erro SMTP (Postfix local) ao enviar e-mail: {e}")
    except ConnectionRefusedError:
        log_message("Erro: Conexão recusada ao Postfix local. O serviço Postfix está rodando e escutando na porta 25?")
    except Exception as e:
        log_message(f"Erro geral ao enviar e-mail via Postfix local: {e}")
    return False

# --- Script Principal (main) ---
# MANTENHA ESTA SEÇÃO IGUAL AO EXEMPLO ANTERIOR
if __name__ == "__main__":
    log_message("--- Iniciando Script de Scan Nmap e E-mail (via Postfix local) ---")

    if run_nmap_scan():
        if os.path.exists(OUTPUT_XML_FILE):
            log_message("Gerando corpo do e-mail em HTML...")
            email_html_body = parse_nmap_xml_to_html(OUTPUT_XML_FILE)

            try:
                tree = ET.parse(OUTPUT_XML_FILE)
                root = tree.getroot()
                hosts_up_count = sum(1 for host in root.findall('host') if host.find('status') is not None and host.find('status').get('state') == 'up')
                email_subject_details = f"{hosts_up_count} Host(s) Ativo(s) Encontrado(s)"
            except Exception as e:
                log_message(f"Erro ao determinar o número de hosts ativos para o assunto do e-mail: {e}")
                email_subject_details = "Resultado do Scan"

            if send_email(email_subject_details, email_html_body, OUTPUT_XML_FILE):
                log_message("Processo concluído com sucesso.")
            else:
                log_message("Processo concluído, mas houve falha ao enviar o e-mail via Postfix.")
        else:
            log_message(f"Arquivo XML {OUTPUT_XML_FILE} não encontrado após o scan.")
            send_email("Falha no Scan Nmap", "<html><body><h1>Falha no Scan Nmap</h1><p>O arquivo XML do scan não foi gerado ou não foi encontrado.</p></body></html>")
    else:
        log_message("Scan Nmap falhou. E-mail não será enviado.")
        send_email("Falha no Scan Nmap", "<html><body><h1>Falha no Scan Nmap</h1><p>Ocorreu um erro durante a execução do scan Nmap. Verifique os logs na VM.</p></body></html>")

    log_message("--- Script Finalizado ---")
