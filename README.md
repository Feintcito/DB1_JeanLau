Universidad Nacional de Ingeniería

Facultad de ingeniería eléctrica y electrónica

Integrantes:

Melgarejo Sotelo, Alejandro Alfonso 20224508B

Aliga Fernandez, Piero Andres 20222596A

Menendez Acosta, Jose Dario 20221486H

Palacios Yarleque, Jerson Andres 20221225J

Espinoza Soncco, Emerson Aldair 20221177E

# Justificación Teórica

## Introducción

Este informe presenta la justificación teórica de la infraestructura de tecnología de la información desarrollada y completada hasta el 54-55% del "Plan de Trabajo COMPLETO" para la "Simulación Bancaria de E-commerce". Este segmento del proyecto establece una base sólida que aborda requisitos críticos de seguridad, fiabilidad, escalabilidad e integridad de datos, reflejando las soluciones implementadas en entornos financieros y transaccionales del mundo real.

## I. Fundamento Arquitectónico: Bases de Datos Heterogéneas y Sistemas Distribuidos

La decisión deliberada del proyecto de desplegar tres sistemas de gestión de bases de datos relacionales (RDBMS) distintos —SQL Server alojando AdventureWorks, MySQL gestionando Northwind y PostgreSQL soportando Wide World Importers— ejemplifica un entorno de base de datos distribuida heterogénea. Esta elección arquitectónica representa una desviación estratégica de los diseños de bases de datos monolíticas, con el objetivo de abordar diversos requisitos de manejo de datos y mejorar la resiliencia y flexibilidad general del sistema.

Esta selección de RDBMS distintos trasciende una mera demostración de capacidad técnica; refleja un imperativo estratégico para construir una capa de datos altamente flexible y resiliente. Al incorporar diferentes RDBMS, la arquitectura mitiga la dependencia del proveedor, permitiendo la selección de la base de datos más adecuada para tipos de datos específicos o requisitos de aplicación dentro de un ecosistema más amplio. Por ejemplo, SQL Server puede ser preferido para informes empresariales complejos y una integración perfecta dentro del ecosistema de Microsoft, mientras que MySQL a menudo se elige para datos transaccionales de alto volumen en aplicaciones centradas en la web debido a su amplia adopción y características de rendimiento. PostgreSQL, por el contrario, es valorado por sus características avanzadas, extensibilidad y soporte robusto para tipos de datos complejos y funciones analíticas. Esta flexibilidad inherente es indispensable para una "Simulación Bancaria de E-commerce", que puede necesitar integrar fuentes de datos dispares o adaptarse a las demandas empresariales en evolución, optimizando el rendimiento y la funcionalidad para cada caso de uso específico. Además, esta heterogeneidad arquitectónica fomenta inherentemente la resiliencia.

### Beneficios de las Bases de Datos Distribuidas Heterogéneas

La adopción de una arquitectura de base de datos distribuida heterogénea ofrece varios beneficios significativos:

Escalabilidad Mejorada: Las bases de datos distribuidas están fundamentalmente diseñadas para gestionar crecientes demandas de datos a través de la escalabilidad horizontal. Esta característica arquitectónica permite la adición de nuevos nodos o instancias de base de datos al sistema, acomodando mayores cargas de trabajo sin una degradación sustancial del rendimiento. En consecuencia, a medida que las operaciones bancarias de comercio electrónico simuladas se expanden, la infraestructura de datos subyacente puede escalar sin problemas para soportar un mayor volumen de transacciones y usuarios.

Fiabilidad y Tolerancia a Fallos Mejorados: Una ventaja central de los sistemas distribuidos radica en su capacidad para mantener la disponibilidad y funcionalidad del servicio incluso si uno o varios nodos dejan de funcionar. Los datos siguen siendo recuperables de otros nodos operativos.1 Esta redundancia inherente, a menudo lograda mediante la replicación de datos en diferentes sistemas, mejora significativamente la fiabilidad general y reduce el tiempo de recuperación ante fallos, minimizando el tiempo de inactividad para operaciones bancarias críticas.

Rendimiento Optimizado: Las bases de datos distribuidas pueden optimizarse estratégicamente para el rendimiento segregando las operaciones de lectura y escritura entre diferentes nodos o distribuyendo los patrones de acceso a los datos. Esta configuración facilita tiempos de acceso más rápidos, lo que es particularmente beneficioso para aplicaciones caracterizadas por grandes bases de usuarios o requisitos de alto rendimiento, típicos de los entornos de comercio electrónico y banca.

Adaptación a la Diversidad de Datos: El enfoque de múltiples bases de datos permite al sistema consolidar y gestionar varios modelos de datos y formas de datos que podrían no ajustarse a esquemas rígidos.2 Esta capacidad es cada vez más vital para las aplicaciones modernas que manejan datos diversos de múltiples fuentes, como datos transaccionales, perfiles de clientes y catálogos de productos. Mejora la capacidad del sistema para capturar, almacenar y analizar información de manera precisa y completa.

### Justificación para la Elección de Bases de Datos Específicas

La selección de AdventureWorks (SQL Server), Northwind (MySQL) y WideWorldImporters (PostgreSQL) es una decisión pragmática y teóricamente sólida para un proyecto de simulación y demostración. Estas son bases de datos de ejemplo ampliamente reconocidas y disponibles públicamente, cada una sirviendo como un ejemplo canónico para su respectivo DBMS. Sus esquemas establecidos y datos de ejemplo fácilmente disponibles facilitan el despliegue y las pruebas rápidas dentro del entorno simulado.

### Implementación de infraestructura de bases de datos

La idea es diseñar, implementar y documentar un entorno de pruebas basado en contenedores Docker para ejecutar tres bases de datos empresariales: SQL Server con AdventureWorks, MySQL con Northwind y PostgreSQL con WideWorldImporters. El objetivo principal es facilitar el análisis de datos mediante herramientas como Power BI, garantizando conectividad remota, integridad de datos, y una infraestructura reproducible y documentada para futuras pruebas y desarrollos.

### Septup infraestructura

1. Actualizamos el sistema

sudo apt update && sudo apt upgrade -y

Actualizamos el sistema operativo Ubuntu para poder tener las últimas versiones o parches de seguridad antes de la instalación de cualquier software.

2. Instalamos  el Docker

curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker jerson
newgrp docker

Instalamos Docker usando el script oficial

3. Instalamos herramientas adicionales

sudo apt install -y htop curl wget git nano

4. Configuración del  directorio de trabajo

mkdir ~/bases-datos ~/backups ~/scripts ~/data
cd ~/bases-datos

Se crean carpetas organizadas para alojar la configuración de Docker, respaldos, scripts y datos de carga.

5. Creamos el archivo

Archivo:

version: '3.8'
services:
  sqlserver:
    image: mcr.microsoft.com/mssql/server:2019-latest
    container_name: sqlserver
    environment:
      - ACCEPT_EULA=Y
      - SA_PASSWORD=Proyecto123!
    ports:
      - "1433:1433"
    volumes:
      - sqlserver_data:/var/opt/mssql
      - ./data:/data

  mysql:
    image: mysql:8.0
    container_name: mysql
    environment:
      - MYSQL_ROOT_PASSWORD=Proyecto123!
      - MYSQL_DATABASE=northwind
    ports:
      - "3306:3306"
    volumes:
      - mysql_data:/var/lib/mysql
      - ./data:/data

  postgres:
    image: postgres:13
    container_name: postgres
    environment:
      - POSTGRES_PASSWORD=Proyecto123!
      - POSTGRES_DB=wideworldimporters
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./data:/data

volumes:
  sqlserver_data:
  mysql_data:
  postgres_data:

### Desplegar de la base de datos

Crearemos un script de instalación automática install_databases.sh con los pasos para importar datos y crear tablas. Contiene:

Descarga de AdventureWorks

Script para Northwind (MySQL)

Script para WideWorldImporters (PostgreSQL)

Carga de datos en cada contenedor respectivo

### Verificación de cada base de datos:

SQL Server

docker exec sqlserver /opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P 'Proyecto123!' -Q "SELECT name FROM sys.databases;"

MySQL
docker exec mysql mysql -u root -p'Proyecto123!' -e "SHOW DATABASES; USE northwind; SHOW TABLES;"

PostgreSQL
docker exec postgres psql -U postgres -d wideworldimporters -c "\dt sales.*"

### Prueba de conectividad desde VM externa:

telnet 34.57.77.240 1433

telnet 34.57.77.240 3306

telnet 34.57.77.240 5432

## II. Postura de Seguridad Integral

Una postura de seguridad robusta es primordial para una simulación bancaria de comercio electrónico, lo que requiere una estrategia de defensa de múltiples capas. Este proyecto integra un Firewall de Aplicaciones Web (WAF), un sistema de Gestión de Información y Eventos de Seguridad (SIEM) y controles de seguridad de red nativos de la nube para lograr una protección integral.

### A. Firewall de Aplicaciones Web (WAF) - ModSecurity

ModSecurity se despliega como un Firewall de Aplicaciones Web (WAF), sirviendo como un intermediario crítico entre las aplicaciones web del proyecto (como Dunker, WordPress, y las diversas interfaces de gestión de bases de datos como phpMyAdmin y pgAdmin) e internet. Su función principal es filtrar, monitorear y bloquear el tráfico HTTP/S malicioso, evitando así que datos no autorizados entren o salgan de la capa de aplicación. Las soluciones WAF están diseñadas específicamente para proteger las aplicaciones web de un amplio espectro de amenazas, incluyendo la inyección SQL y el cross-site scripting (XSS), que son vectores de ataque comunes y críticos que apuntan a las aplicaciones web. Los WAF se consideran una primera línea de defensa confiable para las aplicaciones, particularmente contra las vulnerabilidades enumeradas en el OWASP Top 10.

Los beneficios de implementar ModSecurity son multifacéticos:

Monitoreo y Filtrado en Tiempo Real: ModSecurity inspecciona continuamente el tráfico web entrante en tiempo real, analizando las solicitudes y respuestas HTTP para identificar y bloquear patrones o comportamientos sospechosos que indiquen un ataque. Este mecanismo de filtrado proactivo evita que las solicitudes maliciosas lleguen a la aplicación web o a sus bases de datos subyacentes, actuando como un punto de estrangulamiento crítico para los ataques a la capa de aplicación.

Reglas OWASP Personalizables: ModSecurity utiliza conjuntos de reglas predefinidos, especialmente el OWASP Core Rule Set, y ofrece amplias capacidades de personalización. Esta flexibilidad permite una protección adaptada contra amenazas conocidas y emergentes, mitigando específicamente los ataques de inyección y validando la entrada del usuario para prevenir vulnerabilidades, lo que se alinea con las mejores prácticas establecidas para la seguridad de las aplicaciones web.

Parcheo Virtual y Mitigación de Día Cero: Una ventaja teórica significativa de un WAF como ModSecurity es su capacidad para proporcionar un "parche virtual". Esto significa que puede ofrecer protección o mitigación inicial contra vulnerabilidades recién descubiertas (día cero) incluso antes de que los proveedores de software publiquen parches oficiales. Al aplicar reglas específicas, el WAF puede detectar y bloquear intentos de explotación dirigidos a fallos sin parchear, reduciendo sustancialmente la ventana de exposición y protegiendo el sistema de nuevas amenazas, lo cual es primordial en una simulación bancaria donde la integridad de los datos es crítica.

Registro y Auditoría: El sistema mantiene registros detallados de las amenazas detectadas y las actividades bloqueadas. Estos registros proporcionan datos cruciales para el análisis forense, la respuesta a incidentes y la auditoría de cumplimiento, sirviendo como un registro invaluable de los intentos de ataque y la efectividad del WAF.

### B. Gestión de Información y Eventos de Seguridad (SIEM) - Wazuh

Wazuh SIEM sirve como piedra angular de la postura de seguridad del proyecto, proporcionando visibilidad integral y detección de amenazas en tiempo real en todo el entorno de TI. Agrega datos de eventos de seguridad de diversas fuentes, incluida la máquina virtual de la base de datos (VM1) y la máquina virtual del cliente web/WAF (VM2), lo que permite una visión holística de la seguridad. Las herramientas SIEM integran las capacidades de Gestión de Eventos de Seguridad (SEM) y Gestión de Información de Seguridad (SIM) para construir una representación en tiempo real de posibles amenazas.

Los beneficios de implementar Wazuh como solución SIEM incluyen:

Visibilidad Mejorada y Centralización de Datos: Wazuh centraliza y normaliza los datos de registro de varios hosts (VM1, VM2), sistemas operativos, aplicaciones y dispositivos de red. Esta vista unificada proporciona una comprensión holística de los eventos de seguridad en toda la infraestructura, lo que facilita la percepción del "panorama general” e identifica amenazas sutiles que de otro modo podrían pasarse por alto en registros aislados.

Respuesta Rápida a Incidentes y Precisión en la Detección de Amenazas: Al analizar conjuntos de datos extensos y correlacionar eventos en diferentes sistemas, Wazuh puede detectar amenazas sutiles y anomalías que de otro modo pasarían desapercibidas. Sus capacidades de alerta en tiempo real reducen significativamente el tiempo necesario para identificar y responder a incidentes de seguridad, minimizando su impacto potencial y permitiendo una intervención proactiva. Específicamente, el monitoreo de bases de datos permite alertas sobre patrones de acceso de usuarios sospechosos y anomalías.

Informes de Cumplimiento: Wazuh agiliza el complejo proceso de adherirse a los estándares de cumplimiento normativo (por ejemplo, PCI DSS, HIPAA, GDPR) al automatizar la recopilación de registros, la normalización y la generación de informes. Esto proporciona evidencia auditable de los controles de seguridad y el manejo de incidentes, lo cual es crucial para una simulación bancaria.

Búsqueda Proactiva de Amenazas: Más allá de las alertas reactivas, Wazuh permite a los equipos de seguridad buscar amenazas de forma proactiva aprovechando los datos históricos y la inteligencia de amenazas. Esto fortalece la postura de seguridad general al identificar vulnerabilidades y posibles vectores de ataque antes de que puedan ser explotados.

Soporte Multi-Entorno: Wazuh está diseñado para salvaguardar los activos de datos en entornos locales, virtualizados, en contenedores y basados en la nube, lo que lo hace ideal para la configuración distribuida e híbrida del proyecto. Su despliegue basado en agentes permite un monitoreo profundo de las VM individuales.

#### Instalar Wazuh SIEM

Instalación de Wazuh ALL-in-One

Se instaló la solución Wazuh All-in-One en una máquina virtual (VM2) siguiendo estos pasos:

Preparación del sistema:

sudo apt update

sudo sysctl -w vm.max_map_count=262144

Instalación:

curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh

sudo bash ./wazuh-install.sh -a

Verificación de la instalación: Se confirmaron los estados de los servicios principales de Wazuh:

sudo systemctl status wazuh-manager

sudo systemctl status wazuh-indexer

sudo systemctl status wazuh-dashboard

Configuración de reglas personalizadas para bases de datos:

Se crearon reglas de detección específicas para SQL Server, MySQL y PostgreSQL, además de una regla general para SQL Injection. Estas reglas se configuraron en el archivo /var/ossec/etc/rules/database_rules.xml.

<group name="database,attack,">

<rule id="100001" level="10">

<if_matched_sid>100000</if_matched_sid>

<frequency>15</frequency>

<timeframe>60</timeframe>

<description>SQL Server: Conexiones masivas detectadas (AdventureWorks)</description>

<group>sqlserver,attack,</group>

</rule>

<rule id="100000" level="3">

<match>sqlserver|mssql|1433</match>

<description>SQL Server: Conexión detectada</description>

<group>sqlserver,connection,</group>

</rule>

<rule id="100011" level="10">

<if_matched_sid>100010</if_matched_sid>

<frequency>15</frequency>

<timeframe>60</timeframe>

<description>MySQL: Conexiones masivas detectadas (Northwind)</description>

<group>mysql,attack,</group>

</rule>

<rule id="100010" level="3">

<match>mysql|3306</match>

<description>MySQL: Conexión detectada</description>

<group>mysql,connection,</group>

</rule>

<rule id="100021" level="10">

<if_matched_sid>100020</if_matched_sid>

<frequency>15</frequency>

<timeframe>60</timeframe>

<description>PostgreSQL: Conexiones masivas detectadas (WideWorldImporters)</description>

<group>postgresql,attack,</group>

</rule>

<rule id="100020" level="3">

<match>postgres|postgresql|5432</match>

<description>PostgreSQL: Conexión detectada</description>

<group>postgresql,connection,</group>

</rule>

<rule id="100030" level="12">

<match>union select|drop table|insert into|delete from|exec|script</match>

<description>ALERTA CRÍTICA: Posible intento de SQL Injection detectado</description>

<group>sql_injection,attack,</group>

</rule>

</group>

Instalación y configuración del agente Wazuh en VM1:

Se instaló y configuró un agente de Wazuh en una máquina virtual separada (VM1), designada para albergar las bases de datos.

En VM2 (Manager):

Se agregó un nuevo agente (vm1-databases) con la IP 34.57.77.240 utilizando

sudo /var/ossec/bin/manage_agents.

Se generó y copió la clave de agente.

En VM1 (Agente):

Se importó la clave del agente utilizando

sudo /var/ossec/bin/agent-auth -m 34.60.51.165.

Se habilitó e inició el servicio del agente:

sudo systemctl enable wazuh-agent

sudo systemctl start wazuh-agent

En caso de problemas: Se verificó y ajustó la configuración del servidor en /var/ossec/etc/ossec.conf para apuntar a la IP correcta del Manager (<server>34.60.51.165</server>).

Verificación de VM2: Se confirmo la conexión del agente con

sudo /var/ossec/bin/agent_control -l

Visualización de alertas en el dashboard de Wazuh

Para permitir la visualización de los logs de la VM1 en el Dashboard de Wazuh, se realizaron los siguientes ajustes:

Se habilitó el módulo de análisis de logs en /var/ossec/etc/ossec.conf añadiendo una entrada para Apache logs como ejemplo:

<localfile>

<log_format>apache</log_format>

<location>/var/log/apache2/access.log</location>

</localfile>

Se recargó el manager de Wazuh para aplicar los cambios:

sudo systemctl restart wazuh-manager

Posteriormente, las alertas generadas por la VM1 se comenzaron a visualizar no solo en la consola, sino también el Dashboard web de Wazuh.

Reglas de detección personalizadas (SQL Injection)

Para una detección más robusta de SQL Injection, se añadió una regla específica en el archivo /var/ossec/etc/rules/local_rules.xml:

<group name="local,syslog,sshd,">

<rule id="100031" level="12">

<match>union select|drop table|insert into|delete from|exec|script</match>

<description>ALERTA CRÍTICA: Posible intento de SQL Injection detectado</description>

<group>sql_injection,attack,</group>

</rule>

</group>

Dashboard de Wazuh

Simulación de ataque de SQL Injection desde Kali Linux

Se realizó un ataque simulado de SQL Injection desde una máquina Kali Linux hacia la VM1, apuntando a una base de datos MySQL.

Credenciales de las bases de datos utilizadas:

Acceso manual a MySQL:

mysql --ssl --ssl-verify-server-cert=0 -h 34.57.77.240 -P 3306 -u root -p

Consulta maliciosa inyectada:

SELECT * FROM customers WHERE contact_name = 'a' OR '1'='1';

Detección del ataque por Wazuh

El ataque de SQL Injection fue exitosamente detectado por Wazuh:

En el archivo de alertas: Las alertas fueron visibles al buscar en los logs:

sudo tail -n 100 /var/ossec/logs/alerts/alerts.json | grep -i "sql"

En el Dashboard de Wazuh: se Visualizaron multiples alertas con la siguiente información:

Mensaje: ALERTA CRÍTICA: Posible intento de SQL Injection detectado

Rule ID: 100030

Level: 12

Agent: tools-server (se refiere al agente en VM1)

Activación del módulo SCA (Security Configuration Assessment)

Se activó el módulo Security Configuration Assessment (SCA) en el archivo /var/ossec/etc/ossec.conf para realizar evaluaciones de seguridad:

<sca>

<enabled>yes</enabled>

<scan_on_start>yes</scan_on_start>

<interval>12h</interval>

<skip_nfs>yes</skip_nfs>

</sca>

Políticas disponibles: Se verificó la existencia de políticas de SCA en sudo ls /var/ossec/ruleset/sca/, encontrando cis_debian11.yml. Esta política alinea indirectamente con estándares como PCI DSS, HIPAA y NIST.

Visualización de informes: Los informes de evaluación de políticas (resultados PASSED / FAILED) son accesibles en el Dashboard de Wazuh a través de Modules > Security Configuration Assessment (SCA), seleccionando el agente vm1-databases. Los reportes pueden ser exportados.

### C. Seguridad de Red en la Nube (Reglas de Firewall de GCP)

Las reglas de firewall de Google Cloud Platform (GCP) son fundamentales para establecer un perímetro de seguridad de red robusto para el entorno simulado. Gobiernan el flujo de todo el tráfico entrante (ingreso) y saliente (egreso) hacia y desde las instancias de máquinas virtuales (VM1 para bases de datos, VM2 para herramientas) dentro de la red de Virtual Private Cloud (VPC).

La configuración específica de estas reglas se ha diseñado para adherirse al principio de menor privilegio, permitiendo únicamente el tráfico esencial para el funcionamiento del sistema. Como se evidencia en la implementación, se han establecido reglas de entrada que permiten la comunicación con puertos clave como tcp:80, 443, 1433, 3306, 5432 y 8080/9000 para diferentes destinos y tipos de aplicaciones, asegurando así la operatividad de las bases de datos y servicios web mientras se mantiene un perímetro seguro. Estas configuraciones permiten la conectividad necesaria para las diferentes bases de datos como SQL Server (puerto 1433), MySQL (puerto 3306) y PostgreSQL (puerto 5432), como se detalla en la sección de conexión a la base de datos.

Filtrado de Tráfico y Aplicación de Políticas (Menor Privilegio): Las reglas de firewall permiten un control preciso sobre los protocolos y puertos abiertos, y los rangos de IP de origen permitidos.18 Esto se adhiere estrictamente al principio de menor privilegio, asegurando que solo las rutas de comunicación absolutamente necesarias (por ejemplo, puertos de base de datos 1433, 3306, 5432; puertos web 80, 443; puerto SSH 22) estén expuestas a internet o permitidas entre VMs. Este control granular reduce significativamente la superficie de ataque al minimizar los posibles puntos de entrada para actores maliciosos.

Segmentación y Contención de Red: Al aplicar reglas a instancias específicas o grupos de instancias utilizando etiquetas de red (por ejemplo, database-server, tools-server como se define en Terraform), la arquitectura implementa la segmentación de red. Esto crea zonas lógicas aisladas dentro de la VPC, lo que limita el impacto potencial de una brecha de seguridad. Si un segmento (por ejemplo, VM2) se ve comprometido, los límites de segmentación actúan como barreras, impidiendo que los atacantes se muevan fácilmente lateralmente a otras partes críticas de la red (por ejemplo, VM1 con bases de datos), conteniendo así el "radio de explosión" de cualquier incidente de seguridad.

Registro para Auditoría e Integración con SIEM: Las reglas de firewall de GCP pueden configurarse para registrar todos los datos de tráfico relevantes, abarcando tanto las conexiones permitidas como las denegadas. Estos registros son cruciales para fines de auditoría, proporcionando un registro detallado de la actividad de la red. Además, estos registros pueden integrarse con el sistema Wazuh SIEM para mejorar las capacidades de detección y respuesta en tiempo real, permitiendo la correlación de eventos de red con registros de aplicaciones y sistemas.

### D. Enmascaramiento de datos (Data Masking )

Para reforzar la privacidad y cumplir con las normativas de protección de datos, el proyecto incorpora técnicas de enmascaramiento de datos. El enmascaramiento de datos es el proceso de ocultar datos originales (sensibles) con datos modificados pero estructuralmente similares. Esto es crucial en entornos de prueba, desarrollo o incluso en ciertas vistas de producción donde no se requiere el acceso a la información sensible real, pero sí la funcionalidad de la aplicación. Esta técnica protege la información confidencial, como nombres de clientes o correos electrónicos, sin afectar la utilidad de la base de datos para pruebas o análisis.

Se ha implementado el enmascaramiento de datos en las bases de datos utilizadas en el proyecto. Por ejemplo, en el entorno de MySQL, se realizó el enmascaramiento de datos en la base de datos

northwind en el servidor, donde campos como contact_name y email se muestran como contact_name_masked y email_masked, respectivamente, revelando solo una parte de la información original o reemplazándola con caracteres genéricos, como se puede observar en las tablas de customers_masked.

De manera similar, en PostgreSQL, se ha configurado el enmascaramiento de datos para la base de datos wideworldimporters. Esto incluye la creación de políticas y funciones, como

mask_phone, que permiten ofuscar números de teléfono y otros datos sensibles en las vistas públicas de los clientes, garantizando que la información sensible no sea expuesta directamente. Estas implementaciones aseguran que, aunque se utilicen datos realistas para la simulación, la confidencialidad de la información esté protegida mediante la alteración de datos sensibles en conjuntos de datos no productivos.

Se realiza el data masking al northwind en el servidor

Enmascaramiento de datos en PostgreSQL

La implementación de las reglas de firewall de GCP es fundamental para establecer un perímetro de seguridad de red robusto, que encarna el principio de "menor privilegio" en la capa de red. Al definir explícitamente las reglas de entrada y salida basadas en protocolos, puertos y rangos de IP de origen/destino, el sistema reduce significativamente su superficie de ataque. En lugar de dejar los puertos abiertos por defecto, solo se permiten los canales de comunicación absolutamente necesarios. Esto minimiza los puntos de entrada para posibles atacantes, lo que dificulta que descubran y exploten vulnerabilidades, reduciendo así el perfil de riesgo general de la infraestructura.

## III. Gestión y Eficiencia Operativa

La gestión eficaz y la eficiencia operativa son fundamentales para mantener la salud, el rendimiento y la usabilidad de cualquier infraestructura de TI compleja, particularmente en un entorno bancario simulado. Este proyecto aprovecha una combinación de herramientas especializadas de interfaz gráfica de usuario (GUI) para database management y una potente plataforma de inteligencia de negocios para el análisis de datos.

### Inteligencia de Negocios (Power BI)

La Inteligencia de Negocios (BI) es el proceso sistemático de recopilar y analizar datos para apoyar la toma de decisiones estratégicas y diarias dentro de las organizaciones. Los sistemas de BI son los principales responsables de la elaboración de informes, el procesamiento analítico en línea (OLAP), el análisis y los paneles de control, con un enfoque en la comprensión de los datos y la obtención de información relevante para las decisiones empresariales. Típicamente, este proceso implica la recopilación de datos de la empresa en un almacén de datos u otro repositorio y la utilización de herramientas especializadas para el análisis.

Power BI es un robusto servicio de análisis de negocios que mejora significativamente las capacidades de análisis de datos a través de su interfaz fácil de usar y sus potentes características. Permite a los usuarios visualizar datos, crear informes interactivos y compartir conocimientos entre equipos, facilitando decisiones empresariales rápidas e informadas.

Los beneficios de Power BI en este contexto incluyen:

Visualización y Creación de Informes de Datos: Power BI permite la creación de paneles atractivos e interactivos que proporcionan información en tiempo real. Admite una amplia variedad de elementos visuales, como gráficos, diagramas y mapas, para mostrar datos complejos de forma clara, lo que facilita que una audiencia más amplia comprenda la información clave.

Fácil Conexión a Fuentes de Datos: Power BI puede conectarse a una diversa gama de fuentes de datos, incluyendo Excel, bases de datos SQL (como las de VM1), y servicios en la nube. Esta extensa compatibilidad con fuentes de datos garantiza que todos los datos relevantes del entorno de bases de datos heterogéneas puedan integrarse para un análisis exhaustivo.

Análisis de Datos en Tiempo Real: La plataforma admite paneles en vivo que rastrean métricas importantes en tiempo real, lo que permite una toma de decisiones rápida. Los programas de actualización automática garantizan que los datos permanezcan actualizados.

Herramientas Analíticas Avanzadas: Power BI incorpora potentes Expresiones de Análisis de Datos (DAX) para cálculos complejos y gestión de datos, junto con funciones de IA integradas para análisis predictivos y una exploración de datos más profunda.

Toma de Decisiones Mejorada: Al transformar los datos brutos en inteligencia procesable, Power BI capacita a las organizaciones para tomar decisiones basadas en datos que apoyan el crecimiento y la eficiencia. Descubre patrones y tendencias importantes en diversas áreas, incluyendo ventas, servicio al cliente y seguridad.

## IV. Automatización e Infraestructura como Código (IaC)

La automatización y la Infraestructura como Código (IaC) son principios fundamentales en las operaciones de TI modernas, que mejoran significativamente la eficiencia, la coherencia y la fiabilidad en el despliegue y la gestión de entornos complejos. Este proyecto aprovecha Docker Compose para el despliegue de bases de datos en contenedores y Terraform para el aprovisionamiento de infraestructura, encarnando estos principios.

### A. Docker Compose para el Despliegue de Bases de Datos

Docker Compose es una herramienta diseñada específicamente para definir y ejecutar aplicaciones Docker multicontenedor, proporcionando una experiencia de desarrollo y despliegue optimizada y eficiente. Simplifica el control de toda una pila de aplicaciones al permitir que los servicios, redes y volúmenes se configuren en un único archivo YAML, que luego puede desplegarse con un solo comando. Este enfoque es aplicable en varios entornos, incluyendo producción, staging, desarrollo y pruebas.

Los beneficios de utilizar Docker Compose para el despliegue de bases de datos incluyen:

Eficiencia y Gestión Simplificada: Docker Compose automatiza el despliegue y la gestión de aplicaciones en contenedores, reduciendo la intervención manual y la sobrecarga operativa. Simplifica el proceso de iniciar, detener, reconstruir y ver el estado de los servicios.

Portabilidad y Consistencia: La contenerización aísla las aplicaciones y sus dependencias, asegurando entornos consistentes en las diferentes etapas de desarrollo y despliegue. Esto minimiza los problemas de "funciona en mi máquina" y la desviación de la configuración.

Escalabilidad y Resiliencia: Si bien Docker Compose en sí mismo no es una herramienta de orquestación completa como Docker Swarm o Kubernetes, facilita la definición de aplicaciones multicontenedor escalables. La orquestación de contenedores, en general, ofrece capacidades de conmutación por error automatizada y auto-reparación, lo que garantiza una alta disponibilidad.

Descubrimiento de Servicios y Equilibrio de Carga: Las herramientas de orquestación, a menudo utilizadas junto con Compose para despliegues más grandes, proporcionan mecanismos para que los contenedores se encuentren y se comuniquen entre sí sin problemas, y distribuyen el tráfico entrante entre múltiples instancias para optimizar el rendimiento.

Optimización de Recursos: Las herramientas de orquestación de contenedores optimizan el uso de recursos al programar contenedores en los nodos disponibles en función de los requisitos de recursos, maximizando la eficiencia y potencialmente reduciendo los costos.

### B. Terraform para el Aprovisionamiento de Infraestructura

Terraform es una herramienta pionera de Infraestructura como Código (IaC) que codifica las API en archivos de configuración declarativos. En lugar de configurar manualmente la infraestructura o depender únicamente de las interfaces de los proveedores de la nube, Terraform permite definir y aprovisionar la infraestructura del centro de datos utilizando un enfoque basado en código.

Las ventajas de implementar IaC con Terraform son numerosas:

Compatibilidad Agnosticismo de Plataforma: La naturaleza agnóstica del proveedor de Terraform le permite funcionar en todos los principales proveedores de la nube (Azure, AWS, Google Cloud), así como en soluciones locales.36 Esta flexibilidad lo convierte en un ajuste ideal para entornos híbridos y multinube, lo que permite la gestión de diversas infraestructuras con un conjunto coherente de herramientas y procesos.

Configuración Declarativa: Terraform utiliza un lenguaje declarativo, lo que significa que los ingenieros describen el estado final deseado de la infraestructura, y Terraform determina los pasos necesarios para lograr ese estado. Esto contrasta con las herramientas imperativas que requieren instrucciones explícitas paso a paso, lo que hace que las configuraciones sean más fáciles de entender, mantener y escalar.

Gestión de Estado Integrada: Terraform mantiene un "archivo de estado" para rastrear la infraestructura desplegada y su evolución a lo largo del tiempo. Esta característica permite la detección de la desviación de la configuración, permite planificar cambios antes de aplicarlos y evita actualizaciones conflictivas, actuando como una salvaguarda crítica para la gestión de múltiples entornos o la colaboración entre equipos.

Módulos Reutilizables: Terraform facilita el empaquetado de código en "módulos" reutilizables, que son bloques de construcción para múltiples recursos que se utilizan juntos. Estos módulos se pueden aplicar de forma consistente en diferentes entornos modificando solo las variables de entrada, lo que reduce la duplicación y aumenta la coherencia en los despliegues.

Despliegues Más Rápidos y Consistencia Mejorada: IaC con Terraform reduce significativamente el tiempo dedicado a tareas repetitivas, lo que permite desplegar la infraestructura en segundos en lugar de horas. Al definir la infraestructura a través de código versionado, los entornos se vuelven predecibles y repetibles, lo que garantiza la coherencia, ya sea que se despliegue en desarrollo, staging o producción.

Seguridad y Cumplimiento Mejorados: IaC reduce el riesgo al eliminar las configuraciones manuales, que son una fuente importante de vulnerabilidades de seguridad.37 También se integra con sistemas de control de versiones, lo que permite rastrear cambios, revertir si es necesario y trabajar en colaboración.

Integración con Herramientas CI/CD: La integración de Terraform con las principales herramientas de Integración Continua/Despliegue Continuo (CI/CD) automatiza el proceso de prueba y despliegue de cambios de infraestructura, lo que lleva a despliegues más rápidos y fiables.

La ventaja estratégica de la Infraestructura como Código para la reproducibilidad y la coherencia es profunda. Terraform permite la definición de infraestructura componentes, como máquinas virtuales y reglas de firewall, como código versionado. Esta capacidad permite despliegues altamente repetibles en varios entornos —desarrollo, pruebas y producción—, lo cual es crucial para mantener un entorno simulado complejo donde la coherencia es primordial. Este enfoque minimiza la desviación de la configuración, donde los entornos divergen sutilmente con el tiempo, y reduce significativamente el error humano inherente al aprovisionamiento manual. Además, facilita la gestión colaborativa de la infraestructura, ya que los cambios pueden rastrearse, revisarse y revertirse si es necesario, mucho como el código de la aplicación. La naturaleza declarativa de Terraform garantiza que el estado deseado de la infraestructura se logre, mientras que el uso de módulos promueve la reutilización y la estandarización de los componentes de la infraestructura, lo que lleva a sistemas más predecibles y fiables. Este enfoque sistemático garantiza que la infraestructura subyacente para la simulación bancaria de comercio electrónico no solo sea robusta, sino que también se aprovisione y gestione de forma coherente, apoyando la integridad y la seguridad de todo el ciclo de vida del sistema.

# Conexión a la base de datos

Para poder conectarnos a las diferentes bases de datos se tuvo que configurar algunas reglas en el firewall.

## ADVENTUREWORKS (SQL SERVER)

Server: 34.57.77.240,1433

Database: AdventureWorks2019

Usuario: sa

Password: Proyecto123!

Tablas principales:

Sales.Customer

Production.Product

Sales.SalesOrderHeader

## NORTHWIND (MySQL)

Server: 34.57.77.240

Port: 3306

Database: northwind

Usuario: root

Password: Proyecto123!

Tablas principales:

customers

Products

Orders

## WIDEWORLDIMPORTERS(PostgreSQL)

Server: 34.57.77.240

Port: 5432

Database: wideworldimporters

Usuario: postgres

Password: Proyecto123!

Tablas principales:

sales.customers

warehouse.stock_items

sales.orders

# Pasos para la conexión a las diferentes bases de datos con el Power BI

Debido a la heterogeneidad de las bases de datos se procede a detallar los requisitos para realizar la conexión idónea con cada uno.

## SQL Server con Power BI

Se procede a detallar una secuencia de pasos para realizar la conexión.

Realizar click en el apartado de SQL server

Se nos abrirá un recuadro donde tendremos que completar la información necesaria ojo debe seleccionar la opción “DirectQuery” con esto estaremos en constante conexión a la base de dato en lugar de usar una carga fija de datos.

Con esto estaríamos conectando a la base de datos.

Seleccionamos las tablas con las que trabajaremos.

Lo ideal es darle a “Transformar datos” para darle una primera limpieza a posibles datos “null” o en blanco.

Esto queda a elección del editor de datos.

Click en la opción cerrar y aplicar

Estructura de la base de datos.

Diseño del Dashboard

## Conclusión

El proyecto de Simulación Bancaria de E-commerce, en su estado actual de 54-55% de completitud, demuestra una infraestructura de TI meticulosamente diseñada, teóricamente justificada por su adhesión a los principios de sistemas distribuidos, seguridad por capas, eficiencia operativa y automatización integral. Las elecciones arquitectónicas realizadas hasta este punto abordan colectivamente los requisitos centrales de un entorno robusto, seguro y escalable para transacciones financieras.

La adopción de un panorama de bases de datos heterogéneo, que comprende SQL Server, MySQL y PostgreSQL, no es simplemente un ejercicio técnico, sino una decisión estratégica para construir una capa de datos flexible y resiliente. Este enfoque se adapta a diversas necesidades de manejo de datos, optimiza el rendimiento para cargas de trabajo especializadas y proporciona inherentemente redundancia arquitectónica contra vulnerabilidades específicas de la tecnología. Esta previsión también posiciona el sistema para una futura adaptabilidad, permitiendo una integración perfecta de nuevos paradigmas de datos a medida que evolucionan los requisitos de inteligencia de negocios e IA.

La postura de seguridad se fortalece mediante una defensa de múltiples capas. ModSecurity, como Firewall de Aplicaciones Web, proporciona una protección crucial a nivel de aplicación, filtrando el tráfico malicioso y ofreciendo capacidades de parcheo virtual contra vulnerabilidades de día cero. Wazuh SIEM centraliza y correlaciona los eventos de seguridad de toda la infraestructura, transformando los registros brutos en inteligencia de amenazas procesable para una respuesta rápida a incidentes y una búsqueda proactiva de amenazas. Complementando esto, las reglas de Firewall de GCP establecen un perímetro de red robusto, aplicando el principio de menor privilegio y permitiendo la segmentación de la red para contener posibles brechas.

La eficiencia operativa se mejora al proporcionar herramientas GUI especializadas —phpMyAdmin, pgAdmin y Azure Data Studio— para la gestión de bases de datos. Esto satisface las diversas preferencias de los usuarios y optimiza los flujos de trabajo para cada tipo de base de datos. La integración de Power BI garantiza que los datos brutos se transformen en información procesable, lo que permite la toma de decisiones basada en datos en toda la organización y conecta la infraestructura técnica directamente con el valor empresarial.

Finalmente, la dependencia del proyecto de Docker Compose para el despliegue de bases de datos en contenedores y de Terraform para la Infraestructura como Código subraya un compromiso con la automatización. Estas herramientas garantizan que la infraestructura se aprovisiona de forma coherente, sea altamente reproducible y se gestione de forma eficiente en diversos entornos. Esto minimiza el error humano, acelera los ciclos de despliegue y apoya el desarrollo colaborativo de la infraestructura, todo ello fundamental para mantener la integridad y la escalabilidad de un sistema bancario simulado complejo.

En síntesis, la arquitectura implementada hasta este 54-55% del proyecto representa un enfoque holístico y teóricamente sólido para construir un entorno de TI seguro, escalable y operativamente eficiente, capaz de satisfacer las exigentes demandas de una simulación bancaria de comercio electrónico y proporcionar una base robusta para futuras expansiones y adaptaciones.
