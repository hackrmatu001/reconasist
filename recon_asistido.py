import os
import warnings
import tempfile
import subprocess
import re
from typing import TypedDict
from dotenv import load_dotenv

# Silenciar advertencias de Python y PyTorch
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)
# Silenciar logs informativos de descarga de Hugging Face
os.environ["HF_HUB_DISABLE_SYSLOG_WARNING"] = "1"

# Importaciones estructuradas de LangChain y LangGraph
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from langgraph.graph import StateGraph, END

# Componentes del ecosistema LangChain para el motor RAG
from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma

# Cargar variables de entorno (.env)
load_dotenv()

# Inicialización del LLM (Temperatura 0 para garantizar precisión técnica)
llm = ChatGroq(
    model="llama-3.3-70b-versatile",
    temperature=0
)

# Definición de paleta de colores ANSI nativos para Linux/Kali
CYAN = "\033[1;36m"
MAGENTA = "\033[1;35m"
YELLOW = "\033[1;33m"
GREEN = "\033[1;32m"
WHITE_BOLD = "\033[1;37m"
RED = "\033[1;31m"
RESET = "\033[0m"

# 1. Definición del Estado Expandido del Grafo (Incluye contexto RAG)
class SecurityState(TypedDict):
    target: str
    recon_data: str         # Salida consolidada de Nmap y Whois/Neighbor
    analysis: str           # Mapeo lógico de vectores de ataque
    mitigation_context: str # Contexto de hardening recuperado por el RAG
    report: str             # Entregable final en formato Markdown

# 2. Nodo de Reconocimiento Avanzado (Silencioso con ip neigh)
def recon_node(state: SecurityState):
    target = state["target"].strip()
    
    # --- 2.1. EJECUCIÓN DE NMAP CON -sV USANDO ARCHIVO TEMPORAL ---
    with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".nmap") as tmp_file:
        tmp_path = tmp_file.name

    try:
        comando_nmap = f"nmap -sT -sV --version-intensity 2 -F -Pn -T4 --max-rtt-timeout 500ms -oN {tmp_path} {target}"
        
        nmap_result = subprocess.run(
            comando_nmap,
            capture_output=True,
            text=True,
            timeout=90,
            shell=True
        )
        
        if os.path.exists(tmp_path):
            with open(tmp_path, "r") as f:
                nmap_output = f.read()
            os.remove(tmp_path)
            
            if "0 hosts up" in nmap_output:
                nmap_output += "\n[!] Advertencia: El host no respondió al escaneo."
        else:
            nmap_output = f"Error: No se generó el reporte. Stderr: {nmap_result.stderr}"
            
    except subprocess.TimeoutExpired:
        if os.path.exists(tmp_path):
            with open(tmp_path, "r") as f:
                nmap_output = "--- ESCANEO INCOMPLETO (TIMEOUT) ---\n" + f.read()
            os.remove(tmp_path)
        else:
            nmap_output = "Error: El escaneo superó el tiempo límite y no se recuperaron datos."
            
    except Exception as e:
        nmap_output = f"Excepción interna al ejecutar Nmap: {str(e)}"
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    # --- 2.2. CONSULTA LOCAL/WHOIS INTELIGENTE (Uso de ip neigh nativo) ---
    is_private = (
        target.startswith("172.") or target.startswith("192.168.") or target.startswith("10.") or target.startswith("127.")
    )
    
    if is_private:
        try:
            # Reemplazo moderno e infalible de arp -n para distribuciones actuales
            arp_result = subprocess.run(
                f"ip neigh show {target}", 
                capture_output=True, 
                text=True, 
                timeout=5, 
                shell=True
            )
            info_local = arp_result.stdout.strip() if arp_result.returncode == 0 and arp_result.stdout.strip() else "No se encontraron vecinos de red activos."
            
            whois_output = (
                f"--- CONTEXTO DE RED LOCAL ---\n"
                f"El objetivo es un activo interno o contenedor Docker.\n"
                f"Información de vecinos de red (IP/MAC):\n{info_local}\n"
                f"Nota: Consultas Whois públicas omitidas para rangos RFC 1918."
            )
        except Exception:
            whois_output = "Objetivo privado en segmento local aislado. Sin registros de red pública vecinos."
    else:
        try:
            whois_result = subprocess.run(
                f"whois {target}",
                capture_output=True,
                text=True,
                timeout=20,
                shell=True
            )
            whois_output = whois_result.stdout if whois_result.returncode == 0 else f"Whois sin datos."
        except Exception as e:
            whois_output = f"No se pudo completar la consulta Whois: {str(e)}"

    consolidated_recon = (
        f"==================================================\n"
        f"DATOS TÉCNICOS RECOLECTADOS PARA: {target}\n"
        f"==================================================\n\n"
        f"### [1] ENTRADA NMAP:\n{nmap_output}\n\n"
        f"### [2] ENTRADA WHOIS / ENTIDAD:\n{whois_output}"
    )

    return {"recon_data": consolidated_recon}

# 3. Nodo de Análisis de Superficie de Ataque (Silencioso)
def analysis_node(state: SecurityState):
    prompt_template = ChatPromptTemplate.from_messages([
        ("system", (
            "Actúas como un Ingeniero Principal de Seguridad Ofensiva y analista de Threat Hunting.\n"
            "Tu objetivo es procesar la salida cruda de las herramientas de reconocimiento para mapear la superficie de ataque.\n"
            "Debes estructurar tu análisis identificando:\n"
            "- Puertos abiertos y criticidad de los servicios indexados.\n"
            "- Si el entorno es local/laboratorio o una infraestructura expuesta en Internet (basado en el Whois/ARP).\n"
            "- Identificación o sospecha de vectores de explotación comunes.\n"
            "- Correlación explícita con Técnicas de la matriz MITRE ATT&CK (ej: Reconnaissance T1595, Discovery T1046)."
        )),
        ("human", "Analiza minuciosamente el siguiente bloque de reconocimiento:\n\n{datos}")
    ])

    chain = prompt_template | llm
    response = chain.invoke({"datos": state['recon_data']})

    return {"analysis": response.content}

# 4. Nuevo Nodo RAG: Recuperación de Guías de Hardening Locales (Silencioso)
def rag_retrieval_node(state: SecurityState):
    query_busqueda = state["analysis"]
    ruta_guias = "guias_hardening.txt"
    
    # Verificación de persistencia: Si no tienes el archivo base, el script genera una plantilla rica en políticas
    if not os.path.exists(ruta_guias):
        with open(ruta_guias, "w", encoding="utf-8") as f:
            f.write(
                "Guía de Hardening FTP:\n- Deshabilitar el acceso anónimo (anonymous_enable=NO).\n- Forzar el cifrado de datos y control mediante TLS/SSL.\n- Restringir los usuarios locales a sus directorios personales (chroot_local_user=YES).\n\n"
                "Guía de Hardening SSH:\n- Deshabilitar el acceso directo al usuario root (PermitRootLogin no).\n- Forzar la autenticación exclusiva por llaves criptográficas robustas (Ed25519) deshabilitando contraseñas.\n- Cambiar el puerto por defecto (22) e implementar auditoría de intentos fallidos.\n\n"
                "Guía de Hardening HTTP Apache:\n- Ocultar la firma del servidor y la versión de software (ServerTokens ProductOnly y ServerSignature Off).\n- Implementar cabeceras de seguridad estrictas (HSTS, X-Frame-Options, Content-Security-Policy).\n- Deshabilitar módulos innecesarios y restringir accesos directos al sistema de archivos.\n\n"
                "Guía de Servicios Desconocidos / No Estándar (UPNP):\n- Aislar los servicios personalizados mediante segmentación estricta de red (VLANs) o reglas de Firewall locales.\n- Implementar rate limiting y auditoría de logs activa para detectar anomalías de tráfico."
            )

    try:
        # Ingesta y fragmentación del conocimiento local
        loader = TextLoader(ruta_guias, encoding="utf-8")
        documentos = loader.load()
        
        text_splitter = RecursiveCharacterTextSplitter(chunk_size=350, chunk_overlap=40)
        chunks = text_splitter.split_documents(documentos)
        
        # Generación de Embeddings locales mediante CPU (Portable y sin coste de API)
        embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
        vector_db = Chroma.from_documents(chunks, embeddings)
        
        # Extracción de los 2 fragmentos de texto más alineados con el análisis
        retriever = vector_db.as_retriever(search_kwargs={"k": 2})
        docs_relacionados = retriever.invoke(query_busqueda)
        
        contexto_recuperado = "\n\n".join([doc.page_content for doc in docs_relacionados])
        vector_db.delete_collection() # Limpieza de memoria
        
    except Exception as e:
        contexto_recuperado = f"Aviso: El motor RAG local no pudo recuperar guías adicionales. Detalle: {str(e)}"

    return {"mitigation_context": contexto_recuperado}

# 5. Nodo de Generación de Informe Ejecutivo (Silencioso con inyección RAG)
def report_node(state: SecurityState):
    prompt_template = ChatPromptTemplate.from_messages([
        ("system", (
            "Eres un redactor experto de informes de penetración (Pentesting) para equipos de Red Team y directivos C-Level.\n"
            "Tu tarea es transformar el análisis técnico en un informe formal estructurado rigurosamente en Markdown.\n"
            "REGLA CRÍTICA: Para la sección '4. RECOMENDACIONES DE MITIGACIÓN Y HARDENING', debes adoptar e integrar "
            "estrictamente las directivas técnicas extraídas de la base de conocimientos provista por el módulo RAG."
        )),
        ("human", (
            "### ANÁLISIS DE RIESGOS:\n{analisis}\n\n"
            "### POLÍTICAS DE HARDENING LOCALES (RAG):\n{contexto_rag}\n\n"
            "Escribe el reporte estructurado exactamente bajo el siguiente orden de títulos principales:\n"
            "1. RESUMEN EJECUTIVO\n"
            "2. ANÁLISIS DETALLADO DE LA SUPERFICIE DE ATAQUE\n"
            "3. MATRIZ DE RIESGOS Y MAPEO DE TÉCNICAS MITRE ATT&CK\n"
            "4. RECOMENDACIONES DE MITIGACIÓN Y HARDENING"
        ))
    ])

    chain = prompt_template | llm
    response = chain.invoke({
        "analisis": state['analysis'],
        "contexto_rag": state['mitigation_context']
    })

    return {"report": response.content}

# --- FUNCIÓN AUXILIAR PARA DAR ESTILO NATIVO LINUX (ANSI) ---
def print_stylized_report(markdown_text: str):
    CYAN_BG = "\033[46m\033[30m"
    MAGENTA_BG = "\033[45m\033[30m"
    RED_BG = "\033[41m\033[30m"
    GREEN_BG = "\033[42m\033[30m"
    
    lines = markdown_text.split("\n")
    color_map = {
        "RESUMEN EJECUTIVO": CYAN_BG,
        "ANÁLISIS DETALLADO DE LA SUPERFICIE DE ATAQUE": MAGENTA_BG,
        "MATRIZ DE RIESGOS Y MAPEO DE TÉCNICAS MITRE ATT&CK": RED_BG,
        "RECOMENDACIONES DE MITIGACIÓN Y HARDENING": GREEN_BG
    }

    for line in lines:
        clean_line = line.strip()
        if not clean_line:
            print("")
            continue

        is_main_header = False
        for title, bg_color in color_map.items():
            if clean_line.startswith("#") and title in clean_line:
                print(f"\n{bg_color} █████ {title} █████ {RESET}")
                is_main_header = True
                break
        
        if is_main_header:
            continue
        
        if clean_line.startswith("##") or clean_line.startswith("###"):
            print(f"{YELLOW}{clean_line}{RESET}")
            continue
            
        if clean_line.startswith("*") or clean_line.startswith("-") or clean_line.startswith("➔"):
            line_processed = re.sub(r'\*\*(.*?)\*\*', f'{WHITE_BOLD}\\1{RESET}', clean_line)
            char_to_strip = clean_line[0]
            print(f"  {GREEN}➔{RESET} {line_processed.replace(char_to_strip, '', 1).strip()}")
            continue

        print(line)

# 6. Orquestación del Grafo Agéntico (LangGraph)
workflow = StateGraph(SecurityState)

# Registrar los 4 nodos operativos
workflow.add_node("recon", recon_node)
workflow.add_node("analysis", analysis_node)
workflow.add_node("rag_retrieval", rag_retrieval_node)
workflow.add_node("report", report_node)

# Flujo secuencial lógico
workflow.set_entry_point("recon")
workflow.add_edge("recon", "analysis")
workflow.add_edge("analysis", "rag_retrieval")
workflow.add_edge("rag_retrieval", "report")
workflow.add_edge("report", END)

app = workflow.compile()

# 7. Interfaz Ejecutable de Consola
if __name__ == "__main__":
    print(f"{GREEN}" + "=" * 65)
    print(f"{WHITE_BOLD}   AGENTIC CYBERSECURITY RECON & ANALYSIS SYSTEM (RAG + LangGraph)  ")
    print(f"{GREEN}" + "=" * 65 + f"{RESET}")
    
    target_input = input(f"{WHITE_BOLD}Introduce el objetivo (Dominio o IP, ej: 192.168.1.27): {YELLOW}").strip()

    if not target_input:
        print(f"{RED}[!] Error: El objetivo no puede estar vacío.{RESET}")
        exit()

    initial_state = {
        "target": target_input,
        "recon_data": "",
        "analysis": "",
        "mitigation_context": "",
        "report": ""
    }

    print(f"\n{WHITE_BOLD}[⚙️] Inicializando motor agéntico y validando topología...{RESET}\n")
    
    final_state_accumulator = {}

    for event in app.stream(initial_state):
        final_state_accumulator.update(event)
        
        if "recon" in event:
            print(f"{CYAN}[✔ RECON COMPLETADO]{RESET} Extracción de banners e infraestructura interna finalizada.")
        elif "analysis" in event:
            print(f"{MAGENTA}[✔ ANALYSIS COMPLETADO]{RESET} Correlación de servicios y vectores lógicos lista.")
        elif "rag_retrieval" in event:
            print(f"{YELLOW}[✔ RAG PROCESADO]{RESET} Recuperación de contramedidas desde base de conocimiento local.")
        elif "report" in event:
            print(f"{GREEN}[✔ REPORT COMPLETADO]{RESET} Compilación de informe ejecutivo estructurado.")

    # Extracción segura del reporte
    reporte_final = ""
    if "report" in final_state_accumulator:
        reporte_final = final_state_accumulator["report"].get("report", "")
        
    if not reporte_final:
        final_output = app.invoke(initial_state)
        reporte_final = final_output["report"]

    # =========================================================================
    # PERSISTENCIA: Escritura dinámica absoluta en la carpeta del propio script
    # =========================================================================
    ruta_directorio_script = os.path.dirname(os.path.abspath(__file__))
    archivo_salida = os.path.join(ruta_directorio_script, "report.md")
    
    try:
        with open(archivo_salida, "w", encoding="utf-8") as f:
            f.write(reporte_final)
        print(f"\n{GREEN}[💾 ARCHIVO GUARDADO]{RESET} El reporte formal se ha escrito con éxito en: {WHITE_BOLD}{archivo_salida}")
    except Exception as e:
        print(f"\n{RED}[❌ ERROR AL GUARDAR]{RESET} No se pudo escribir el archivo {archivo_salida}: {str(e)}")

    # Despliegue estético cromático final en la terminal de Kali
    print("\n" + f"{YELLOW}" + "="*80)
    print(f"\033[43m\033[30m\033[1m               📋 INFORME DE SEGURIDAD GENERADO POR AGENTE IA                 {RESET}")
    print(f"{YELLOW}" + "="*80 + f"{RESET}\n")
    
    print_stylized_report(reporte_final)
    print("\n" + f"{YELLOW}" + "="*80 + f"{RESET}")
