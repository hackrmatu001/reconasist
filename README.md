# Agentic Cybersecurity Recon & Analysis System (RAG + LangGraph)

Este proyecto implementa un agente inteligente automatizado diseñado para la fase de **Reconocimiento y Análisis de Superficie de Ataque** en auditorías de seguridad ofensiva (Pentesting / Red Team). Utiliza **LangGraph** para la orquestación secuencial de tareas, **LangChain** para la interacción con LLMs a través de **Groq (Llama 3.3 70B)**, y un motor **RAG (Retrieval-Augmented Generation)** local para inyectar directivas de mitigación y hardening personalizadas.

## 🚀 Características Principales

* **Orquestación Agéntica (LangGraph):** Mantiene un estado expandido y controlado a través de 4 nodos operativos secuenciales (`recon` ➔ `analysis` ➔ `rag_retrieval` ➔ `report`).
* **Reconocimiento Híbrido Automatizado:** Ejecuta escaneos de servicios (`Nmap -sV`) de manera controlada y realiza consultas inteligentes locales (`ip neigh show`) o públicas (`whois`) adaptándose dinámicamente si el objetivo es un rango privado (RFC 1918) o una infraestructura expuesta.
* **Análisis de Threat Hunting:** Correlaciona los servicios detectados y los vectores potenciales directamente con las tácticas y técnicas de la matriz **MITRE ATT&CK** (ej. *Reconnaissance T1595*, *Discovery T1046*).
* **Motor RAG Local Integrado:** Genera de forma autónoma una base de conocimientos criptográfica local utilizando `Chroma` y embeddings vectoriales de `HuggingFace (all-MiniLM-L6-v2)` ejecutados 100% en CPU para buscar guías específicas de *hardening* (SSH, FTP, Apache, etc.).
* **Generación de Reportes Ejecutivos:** Compila de manera automática un reporte final formal en formato Markdown (`report.md`) adaptado tanto para directivos C-Level como para equipos técnicos de Red Team.
* **Interfaz ANSI Estilizada:** Cuenta con un renderizado nativo cromático en consola ideal para terminales Linux o Kali Linux.

---

## 📋 Arquitectura del Grafo Operativo

El flujo de trabajo es completamente determinista y estructurado:

1. **`recon` (Nodo de Reconocimiento):** Descubre puertos, banners de servicios y procedencia de red de la IP objetivo.
2. **`analysis` (Nodo de Mapeo lógico):** El LLM procesa los datos crudos y detecta vectores potenciales y alineación MITRE.
3. **`rag_retrieval` (Nodo RAG):** Busca y extrae en caliente contramedidas de la base de datos vectorial local.
4. **`report` (Nodo de Compilación):** Consolida toda la telemetría en un entregable estructurado.

---

## 🔧 Requisitos e Instalación

### 1. Requisitos del Sistema
Asegúrate de tener instaladas las herramientas nativas de red en tu sistema (especialmente si usas Kali Linux, ya vendrán integradas):
```bash
sudo apt update && sudo apt install nmap whois -y