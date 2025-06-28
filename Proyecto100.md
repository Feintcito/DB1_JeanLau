# 🚀 Plan 45% Restante - Semana 2 (Completar al 100%)

## 🎯 **OBJETIVO: De 55% → 100% en 5 días**

**Prerrequisitos:** Tener funcionando el 55% de la Semana 1:
- ✅ 3 Bases de datos (AdventureWorks, Northwind, WideWorldImporters)
- ✅ Clientes web (phpMyAdmin, pgAdmin, Azure Data Studio)
- ✅ SIEM básico (Wazuh)
- ✅ WAF básico (ModSecurity)
- ✅ Power BI conectado

---

## 📅 **DISTRIBUCIÓN SEMANAL:**

### **🌟 DÍA 1 (LUNES): Data Masking + Encryption (10%)**
### **🌟 DÍA 2 (MARTES): Oracle Cloud Integration (10%)**
### **🌟 DÍA 3 (MIÉRCOLES): SIEM Avanzado + Triggers (10%)**
### **🌟 DÍA 4 (JUEVES): Penetration Testing + Bunker DB (10%)**
### **🌟 DÍA 5 (VIERNES): Terraform Completo + Deployment (5%)**

---

## 🛡️ **DÍA 1 (LUNES): DATA MASKING + ENCRYPTION (10%)**

### **👤 Persona 1 (Jerson): TDE + Always Encrypted (SQL Server)**
**Tiempo:** 6 horas
**VM:** VM1 (Bases de datos)

#### **Implementar Transparent Data Encryption (TDE):**
```sql
-- Conectar a SQL Server
docker exec -it sqlserver /opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P 'Proyecto123!'

-- Crear Database Master Key
USE master;
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'ProyectoTDE2024!';

-- Crear certificado para TDE
CREATE CERTIFICATE AdventureWorksTDE
WITH SUBJECT = 'AdventureWorks TDE Certificate';

-- Respaldar certificado (CRÍTICO)
BACKUP CERTIFICATE AdventureWorksTDE
TO FILE = '/var/opt/mssql/backup/AdventureWorksTDE.cer'
WITH PRIVATE KEY (
    FILE = '/var/opt/mssql/backup/AdventureWorksTDE.pvk',
    ENCRYPTION BY PASSWORD = 'CertificateBackup2024!'
);

-- Crear Database Encryption Key
USE AdventureWorks2019;
CREATE DATABASE ENCRYPTION KEY
WITH ALGORITHM = AES_256
ENCRYPTION BY SERVER CERTIFICATE AdventureWorksTDE;

-- Habilitar TDE
ALTER DATABASE AdventureWorks2019
SET ENCRYPTION ON;

-- Verificar estado de encriptación
SELECT 
    DB_NAME(database_id) AS DatabaseName,
    encryption_state,
    encryption_state_desc,
    percent_complete
FROM sys.dm_database_encryption_keys;
```

#### **Implementar Always Encrypted:**
```sql
-- Crear Column Master Key
CREATE COLUMN MASTER KEY [CMK_Auto1]
WITH (
    KEY_STORE_PROVIDER_NAME = N'MSSQL_CERTIFICATE_STORE',
    KEY_PATH = N'CurrentUser/My/AdventureWorksTDE'
);

-- Crear Column Encryption Key
CREATE COLUMN ENCRYPTION KEY [CEK_Auto1]
WITH VALUES (
    COLUMN_MASTER_KEY = [CMK_Auto1],
    ALGORITHM = 'RSA_OAEP',
    ENCRYPTED_VALUE = 0x016E000001630075007200720065006E00740075007300650072002F006D0079002F00640062006500630065006300320065003500370065003300320034003600340038003900
);

-- Encriptar columnas sensibles
ALTER TABLE Sales.Customer
ADD CustomerEmail NVARCHAR(50) 
ENCRYPTED WITH (
    COLUMN_ENCRYPTION_KEY = [CEK_Auto1],
    ENCRYPTION_TYPE = Deterministic,
    ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256'
);

-- Insertar datos encriptados de prueba
INSERT INTO Sales.Customer (CustomerEmail) VALUES 
('john.doe@adventure-works.com'),
('jane.smith@adventure-works.com'),
('bob.johnson@adventure-works.com');
```

### **👤 Persona 2 (Piero): Dynamic Data Masking (MySQL + PostgreSQL)**
**Tiempo:** 6 horas
**VM:** VM1 + VM2

#### **MySQL Dynamic Data Masking:**
```sql
-- Conectar a MySQL
docker exec -it mysql mysql -u root -p'Proyecto123!' northwind

-- Crear usuario con permisos limitados
CREATE USER 'analyst'@'%' IDENTIFIED BY 'AnalystPassword123!';
GRANT SELECT ON northwind.* TO 'analyst'@'%';

-- Crear vista con datos enmascarados
CREATE VIEW customers_masked AS
SELECT 
    customer_id,
    company_name,
    CONCAT(LEFT(contact_name, 2), '***') AS contact_name_masked,
    CONCAT('***@', SUBSTRING_INDEX(contact_name, '@', -1)) AS email_masked,
    city,
    CASE 
        WHEN country IN ('USA', 'Canada', 'Mexico') THEN country 
        ELSE 'Other' 
    END AS country_masked
FROM customers;

-- Verificar enmascaramiento
SELECT * FROM customers_masked;
```

#### **PostgreSQL Row Level Security:**
```sql
-- Conectar a PostgreSQL
docker exec -it postgres psql -U postgres -d wideworldimporters

-- Habilitar RLS
ALTER TABLE sales.customers ENABLE ROW LEVEL SECURITY;

-- Crear política de seguridad por región
CREATE POLICY customer_region_policy ON sales.customers
FOR SELECT
TO PUBLIC
USING (country = current_setting('app.current_user_region', true));

-- Crear usuarios por región
CREATE USER usa_user WITH PASSWORD 'USAUser123!';
CREATE USER intl_user WITH PASSWORD 'IntlUser123!';

-- Configurar sesión por región
-- Para USA: SET app.current_user_region = 'United States';
-- Para International: SET app.current_user_region = 'Other';

-- Función de enmascaramiento de datos
CREATE OR REPLACE FUNCTION mask_phone(phone_number TEXT)
RETURNS TEXT AS $$
BEGIN
    IF LENGTH(phone_number) > 4 THEN
        RETURN CONCAT('***-***-', RIGHT(phone_number, 4));
    ELSE
        RETURN '***-***-****';
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Vista con datos enmascarados
CREATE VIEW customers_public AS
SELECT 
    customer_id,
    customer_name,
    mask_phone(phone_number) AS phone_masked,
    city,
    country
FROM sales.customers;
```

### **📤 Entregables Día 1:**
- [ ] TDE habilitado en SQL Server
- [ ] Always Encrypted configurado
- [ ] Dynamic Data Masking en MySQL
- [ ] Row Level Security en PostgreSQL
- [ ] Usuarios con permisos diferenciados
- [ ] Documentación de políticas de privacidad

---

## ☁️ **DÍA 2 (MARTES): ORACLE CLOUD INTEGRATION (10%)**

### **👤 Persona 3 (Emerson): Oracle Cloud Setup + Migration**
**Tiempo:** 8 horas
**Objetivo:** Migrar una BD a Oracle Cloud y configurar hybrid cloud

#### **Setup Oracle Cloud Free Tier:**
```bash
# 1. Crear cuenta Oracle Cloud (gratuita)
# https://cloud.oracle.com/free

# 2. Crear Autonomous Database
# - Ir a Oracle Cloud Console
# - Database → Autonomous Database → Create
# - Compartment: Default
# - Display Name: AdventureWorksOracle
# - Database Name: ADVWORKS
# - Workload Type: Transaction Processing
# - Deployment Type: Shared Infrastructure
# - Admin Password: OracleAdventure123!

# 3. Descargar Wallet de conexión
# - Database → AdventureWorksOracle → DB Connection
# - Download Wallet → Password: WalletPass123!

# 4. Instalar Oracle Instant Client en VM1
wget https://download.oracle.com/otn_software/linux/instantclient/218000/instantclient-basic-linux.x64-21.8.0.0.0dbru.zip
unzip instantclient-basic-linux.x64-21.8.0.0.0dbru.zip
sudo mv instantclient_21_8 /opt/oracle/
echo 'export LD_LIBRARY_PATH=/opt/oracle/instantclient_21_8:$LD_LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc
```

#### **Migrar datos AdventureWorks a Oracle:**
```sql
-- Script de migración SQL Server → Oracle
-- Crear tablas en Oracle Cloud

-- Conectar a Oracle via SQL Developer Web
-- URL: https://[autonomous-db-url]/ords/sql-developer

CREATE TABLE customers_oracle (
    customer_id NUMBER PRIMARY KEY,
    company_name VARCHAR2(100),
    contact_name VARCHAR2(50),
    territory_id NUMBER,
    account_number VARCHAR2(10),
    created_date DATE DEFAULT SYSDATE
);

CREATE TABLE products_oracle (
    product_id NUMBER PRIMARY KEY,
    product_name VARCHAR2(100),
    category VARCHAR2(50),
    standard_cost NUMBER(10,2),
    list_price NUMBER(10,2),
    created_date DATE DEFAULT SYSDATE
);

CREATE TABLE sales_orders_oracle (
    order_id NUMBER PRIMARY KEY,
    customer_id NUMBER,
    order_date DATE,
    due_date DATE,
    ship_date DATE,
    total_due NUMBER(12,2),
    FOREIGN KEY (customer_id) REFERENCES customers_oracle(customer_id)
);

-- Insertar datos de prueba
INSERT INTO customers_oracle VALUES (1, 'Adventure Works Cycles', 'John Smith', 1, 'AW00000001', SYSDATE);
INSERT INTO products_oracle VALUES (1, 'Mountain Bike', 'Bikes', 500.00, 750.00, SYSDATE);
INSERT INTO sales_orders_oracle VALUES (1, 1, SYSDATE, SYSDATE+7, NULL, 750.00);

COMMIT;
```

#### **Configurar Hybrid Cloud con Oracle:**
```bash
# Instalar Oracle Database Gateway en VM1
sudo apt install -y sqlplus oracle-instantclient-sqlplus

# Configurar tnsnames.ora
mkdir -p ~/oracle/network/admin
cat > ~/oracle/network/admin/tnsnames.ora << 'EOF'
ADVWORKS_HIGH = (description= (retry_count=20)(retry_delay=3)(address=(protocol=tcps)(port=1522)(host=adb.us-ashburn-1.oraclecloud.com))(connect_data=(service_name=ADVWORKS_high.adb.oraclecloud.com))(security=(ssl_server_cert_dn="CN=adb.us-ashburn-1.oraclecloud.com, OU=Oracle BMCS US, O=Oracle Corporation, L=Redwood City, ST=California, C=US")))
EOF

# Configurar variables de entorno
export TNS_ADMIN=~/oracle/network/admin
export ORACLE_HOME=/opt/oracle/instantclient_21_8

# Probar conexión
sqlplus admin/OracleAdventure123!@ADVWORKS_HIGH
```

### **👤 Persona 4 (Jose): Oracle Integration con Power BI**
**Tiempo:** 4 horas
**Objetivo:** Conectar Power BI a Oracle Cloud

#### **Configurar conexión Power BI → Oracle:**
```
# En Power BI Desktop:
1. Obtener datos → Oracle Database
2. Servidor: [oracle-cloud-host]:1522/[service_name]
3. Usuario: admin
4. Password: OracleAdventure123!
5. Opciones avanzadas: 
   - SID/Service Name: ADVWORKS_high.adb.oraclecloud.com

# Crear dashboard Oracle:
- Conectar a customers_oracle
- Crear gráficos de ventas por territorio
- Comparar datos Oracle vs SQL Server
- Dashboard híbrido (on-premise + cloud)
```

### **📤 Entregables Día 2:**
- [ ] Oracle Cloud Autonomous Database funcionando
- [ ] Migración de datos AdventureWorks → Oracle
- [ ] Conexión híbrida (on-premise + cloud)
- [ ] Power BI conectado a Oracle Cloud
- [ ] Dashboard comparativo multi-cloud

---

## 🔍 **DÍA 3 (MIÉRCOLES): SIEM AVANZADO + TRIGGERS (10%)**

### **👤 Persona 3 (Emerson): Wazuh Avanzado + Database Triggers**
**Tiempo:** 8 horas

#### **Configurar triggers de auditoría en las BDs:**

**SQL Server Triggers:**
```sql
-- Trigger de auditoría para cambios en customers
USE AdventureWorks2019;

CREATE TRIGGER tr_customer_audit
ON Sales.Customer
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    DECLARE @action VARCHAR(10)
    DECLARE @user VARCHAR(50) = SYSTEM_USER
    DECLARE @timestamp DATETIME = GETDATE()
    
    IF EXISTS(SELECT * FROM inserted) AND EXISTS(SELECT * FROM deleted)
        SET @action = 'UPDATE'
    ELSE IF EXISTS(SELECT * FROM inserted)
        SET @action = 'INSERT'
    ELSE
        SET @action = 'DELETE'
    
    -- Log a archivo para Wazuh
    EXEC xp_cmdshell 'echo "SQL_AUDIT: ' + @action + ' on Sales.Customer by ' + @user + ' at ' + CAST(@timestamp AS VARCHAR) + '" >> C:\temp\sql_audit.log'
END;

-- Trigger para detectar accesos fuera de horario
CREATE TRIGGER tr_after_hours_access
ON Sales.Customer
AFTER SELECT
AS
BEGIN
    DECLARE @current_hour INT = DATEPART(HOUR, GETDATE())
    
    IF @current_hour < 6 OR @current_hour > 22
    BEGIN
        EXEC xp_cmdshell 'echo "SECURITY_ALERT: After hours database access detected at ' + CAST(GETDATE() AS VARCHAR) + '" >> C:\temp\security_alerts.log'
    END
END;
```

**MySQL Triggers:**
```sql
-- Conectar a MySQL Northwind
USE northwind;

-- Crear tabla de auditoría
CREATE TABLE audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    table_name VARCHAR(50),
    action_type VARCHAR(10),
    user_name VARCHAR(50),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    old_values JSON,
    new_values JSON
);

-- Trigger para auditar cambios en customers
DELIMITER $$
CREATE TRIGGER tr_customers_audit
AFTER UPDATE ON customers
FOR EACH ROW
BEGIN
    INSERT INTO audit_log (table_name, action_type, user_name, old_values, new_values)
    VALUES (
        'customers',
        'UPDATE',
        USER(),
        JSON_OBJECT(
            'customer_id', OLD.customer_id,
            'company_name', OLD.company_name,
            'contact_name', OLD.contact_name
        ),
        JSON_OBJECT(
            'customer_id', NEW.customer_id,
            'company_name', NEW.company_name,
            'contact_name', NEW.contact_name
        )
    );
    
    -- Log para Wazuh
    SELECT CONCAT('MYSQL_AUDIT: UPDATE on customers by ', USER(), ' at ', NOW()) 
    INTO OUTFILE '/tmp/mysql_audit.log';
END$$
DELIMITER ;
```

**PostgreSQL Triggers:**
```sql
-- Conectar a PostgreSQL WideWorldImporters
\c wideworldimporters

-- Crear función de auditoría
CREATE OR REPLACE FUNCTION audit_function()
RETURNS TRIGGER AS $$
BEGIN
    -- Log para Wazuh
    RAISE NOTICE 'POSTGRES_AUDIT: % on %.% by % at %', 
        TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME, 
        current_user, current_timestamp;
    
    -- Escribir a archivo log
    PERFORM pg_file_write('/tmp/postgres_audit.log', 
        format('POSTGRES_AUDIT: %s on %s.%s by %s at %s%s',
            TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME,
            current_user, current_timestamp, chr(10)),
        true);
    
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- Aplicar trigger a tabla customers
CREATE TRIGGER tr_customers_audit
    AFTER INSERT OR UPDATE OR DELETE ON sales.customers
    FOR EACH ROW EXECUTE FUNCTION audit_function();
```

#### **Configurar Wazuh para monitorear logs de BDs:**
```bash
# Configurar Wazuh para leer logs de BD
sudo nano /var/ossec/etc/ossec.conf

# Agregar monitoreo de logs específicos
<localfile>
    <log_format>syslog</log_format>
    <location>/tmp/sql_audit.log</location>
</localfile>

<localfile>
    <log_format>syslog</log_format>
    <location>/tmp/mysql_audit.log</location>
</localfile>

<localfile>
    <log_format>syslog</log_format>
    <location>/tmp/postgres_audit.log</location>
</localfile>

# Reglas avanzadas para análisis de comportamiento
sudo nano /var/ossec/etc/rules/advanced_database_rules.xml
```

**Reglas Wazuh avanzadas:**
```xml
<group name="database,advanced_monitoring">

  <!-- Análisis de comportamiento: Accesos anómalos -->
  <rule id="200001" level="8">
    <if_matched_sid>100000,100010,100020</if_matched_sid>
    <time>02:00-06:00</time>
    <description>Base de datos: Acceso fuera de horario laboral detectado</description>
    <group>after_hours,suspicious</group>
  </rule>

  <!-- Detección de cambios masivos -->
  <rule id="200002" level="12">
    <match>UPDATE|DELETE</match>
    <if_matched_sid>200001</if_matched_sid>
    <frequency>50</frequency>
    <timeframe>300</timeframe>
    <description>CRÍTICO: Operaciones masivas de modificación detectadas</description>
    <group>data_manipulation,attack</group>
  </rule>

  <!-- Detección de escalada de privilegios -->
  <rule id="200003" level="15">
    <match>GRANT|ALTER USER|CREATE USER</match>
    <description>ALERTA MÁXIMA: Intento de escalada de privilegios detectado</description>
    <group>privilege_escalation,critical</group>
  </rule>

  <!-- Análisis de patrones de consulta -->
  <rule id="200004" level="10">
    <match>SELECT.*FROM.*WHERE.*=.*OR.*=</match>
    <description>Patrón de consulta sospechoso detectado (posible SQL injection)</description>
    <group>sql_injection,pattern_analysis</group>
  </rule>

  <!-- Monitoreo de usuarios administradores -->
  <rule id="200005" level="7">
    <match>sa|root|postgres</match>
    <if_matched_sid>100000,100010,100020</if_matched_sid>
    <description>Acceso con cuenta administrativa detectado</description>
    <group>admin_access,monitoring</group>
  </rule>

</group>
```

#### **Configurar alertas automáticas:**
```bash
# Configurar notificaciones por email
sudo nano /var/ossec/etc/ossec.conf

<global>
    <email_notification>yes</email_notification>
    <smtp_server>smtp.gmail.com</smtp_server>
    <email_from>wazuh@proyecto.com</email_from>
    <email_to>admin@proyecto.com</email_to>
</global>

<email_alerts>
    <email_to>security@proyecto.com</email_to>
    <level>12</level>
    <group>attack,critical</group>
</email_alerts>

# Configurar webhook para Slack
sudo nano /var/ossec/integrations/slack.py

# Script para webhook de Slack
#!/usr/bin/env python3
import sys
import json
import requests

def send_slack_alert(alert_data):
    webhook_url = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
    
    message = {
        "text": f"🚨 ALERTA WAZUH: {alert_data['rule']['description']}",
        "attachments": [{
            "color": "danger",
            "fields": [
                {"title": "Nivel", "value": alert_data['rule']['level'], "short": True},
                {"title": "Fuente", "value": alert_data['agent']['name'], "short": True},
                {"title": "Timestamp", "value": alert_data['timestamp'], "short": False}
            ]
        }]
    }
    
    requests.post(webhook_url, data=json.dumps(message))

if __name__ == "__main__":
    alert_json = sys.stdin.read()
    alert_data = json.loads(alert_json)
    send_slack_alert(alert_data)
```

### **📤 Entregables Día 3:**
- [ ] Triggers de auditoría en las 3 BDs
- [ ] Wazuh monitoreando logs de aplicación
- [ ] Reglas avanzadas de detección de comportamiento
- [ ] Alertas automáticas (email + Slack)
- [ ] Dashboard de análisis de patrones

---

## 🔓 **DÍA 4 (JUEVES): PENETRATION TESTING + BUNKER DB (10%)**

### **👤 Persona 4 (Jose): Penetration Testing Framework**
**Tiempo:** 8 horas

#### **Setup entorno de pentesting:**
```bash
# Instalar herramientas de pentesting en VM2
sudo apt update
sudo apt install -y nmap sqlmap hydra metasploit-framework

# Crear VM3 para "atacante" (simulación)
gcloud compute instances create attacker-vm \
    --zone=us-central1-a \
    --machine-type=e2-medium \
    --image-family=kali-linux \
    --image-project=kali-linux-cloud \
    --boot-disk-size=50GB \
    --tags=attacker-vm
```

#### **Configurar Bunker Database (WordPress vulnerable):**
```bash
# En VM1 - Crear WordPress con BD vulnerable
cd ~/bases-datos
mkdir wordpress-bunker
cd wordpress-bunker

# Docker Compose para WordPress vulnerable
cat > docker-compose-bunker.yml << 'EOF'
version: '3.8'
services:
  wordpress-bunker:
    image: wordpress:5.0  # Versión vulnerable
    container_name: wordpress-bunker
    ports:
      - "8080:80"
    environment:
      - WORDPRESS_DB_HOST=mysql-bunker
      - WORDPRESS_DB_USER=root
      - WORDPRESS_DB_PASSWORD=VulnerablePass123!
      - WORDPRESS_DB_NAME=wordpress_bunker
    volumes:
      - wordpress_data:/var/www/html
    depends_on:
      - mysql-bunker

  mysql-bunker:
    image: mysql:5.7  # Versión con vulnerabilidades conocidas
    container_name: mysql-bunker
    environment:
      - MYSQL_ROOT_PASSWORD=VulnerablePass123!
      - MYSQL_DATABASE=wordpress_bunker
      - MYSQL_USER=wpuser
      - MYSQL_PASSWORD=wppass123
    ports:
      - "3307:3306"
    volumes:
      - mysql_bunker_data:/var/lib/mysql
    command: --skip-grant-tables --general-log=1 --general-log-file=/var/lib/mysql/general.log

volumes:
  wordpress_data:
  mysql_bunker_data:
EOF

# Iniciar entorno vulnerable
docker-compose -f docker-compose-bunker.yml up -d

# Configurar WordPress con vulnerabilidades
sleep 60
curl -X POST http://34.57.77.240:8080/wp-admin/install.php \
    -d "weblog_title=Bunker Site" \
    -d "user_name=admin" \
    -d "admin_password=admin123" \
    -d "admin_email=admin@bunker.com" \
    -d "Submit=Install WordPress"
```

#### **Scripts de penetration testing:**
```bash
# Script 1: Escaneo de vulnerabilidades
cat > ~/pentesting/vulnerability_scan.sh << 'EOF'
#!/bin/bash

TARGET_IP="34.57.77.240"
echo "🔍 Iniciando escaneo de vulnerabilidades..."

# Escaneo de puertos
echo "📡 Escaneando puertos..."
nmap -sS -O -sV $TARGET_IP > nmap_results.txt

# Escaneo específico de bases de datos
echo "🗄️ Escaneando servicios de BD..."
nmap -p 1433,3306,5432 --script=ms-sql-info,mysql-info,pgsql-brute $TARGET_IP

# Escaneo web básico
echo "🌐 Escaneando servicios web..."
nmap -p 80,443,8080 --script=http-enum,http-vuln* $TARGET_IP

# SQL Injection testing con sqlmap
echo "💉 Probando SQL Injection..."
sqlmap -u "http://$TARGET_IP:8080/wp-login.php" --forms --batch --level=3 --risk=2

# Fuerza bruta MySQL Bunker
echo "🔓 Probando fuerza bruta MySQL..."
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://$TARGET_IP:3307

echo "✅ Escaneo completado. Revisar archivos de resultados."
EOF

chmod +x ~/pentesting/vulnerability_scan.sh
```

#### **Simulación de ataques:**
```bash
# Script 2: Simulación de ataques controlados
cat > ~/pentesting/attack_simulation.sh << 'EOF'
#!/bin/bash

TARGET_IP="34.57.77.240"
echo "⚔️ Iniciando simulación de ataques controlados..."

# Ataque 1: SQL Injection en WordPress
echo "💉 Simulando SQL Injection..."
curl -X POST "http://$TARGET_IP:8080/wp-login.php" \
    -d "log=admin' UNION SELECT 1,2,3,4,5--" \
    -d "pwd=password"

# Ataque 2: Conexiones masivas (DDoS simulation)
echo "🌊 Simulando DDoS..."
for i in {1..100}; do
    mysql -h $TARGET_IP -P 3307 -u root -e "SELECT 1;" &
done
wait

# Ataque 3: Intentos de login por fuerza bruta
echo "🔓 Simulando fuerza bruta..."
for pass in admin password 123456 admin123; do
    mysql -h $TARGET_IP -P 3307 -u root -p$pass -e "SELECT USER();" 2>/dev/null
done

# Ataque 4: Acceso fuera de horario (si es de noche)
current_hour=$(date +%H)
if [ $current_hour -lt 6 ] || [ $current_hour -gt 22 ]; then
    echo "🌙 Simulando acceso fuera de horario..."
    mysql -h $TARGET_IP -P 3306 -u root -p'Proyecto123!' -e "SELECT * FROM northwind.customers LIMIT 5;"
fi

echo "✅ Simulación de ataques completada."
EOF

chmod +x ~/pentesting/attack_simulation.sh
```

### **👤 Persona 5 (Alejandro): Análisis de Resultados + Remediación**
**Tiempo:** 4 horas

#### **Dashboard de pentesting en Power BI:**
```
# Crear dashboard de análisis de seguridad:
1. Conectar a logs de Wazuh
2. Visualizar:
   - Intentos de ataque por hora
   - Tipos de ataques detectados
   - Fuentes de ataques (IPs)
   - Efectividad de contramedidas

# Métricas clave:
- MTTR (Mean Time To Response)
- False Positive Rate
- Attack Success Rate
- System Availability
```

#### **Report de vulnerabilidades:**
```markdown
# REPORTE DE PENETRATION TESTING

## Vulnerabilidades Identificadas:
1. **WordPress Bunker (CRÍTICO)**
   - Versión vulnerable 5.0
   - Credenciales débiles
   - SQL Injection posible

2. **MySQL Bunker (ALTO)**
   - Sin autenticación (--skip-grant-tables)
   - Logs expuestos
   - Puerto alternativo expuesto

3. **Configuraciones (MEDIO)**
   - Puertos de BD expuestos públicamente
   - Credenciales en texto plano

## Remediaciones Implementadas:
1. WAF bloqueando SQL injection
2. SIEM detectando conexiones masivas
3. Rate limiting en firewalls
4. Monitoreo de accesos anómalos
```

### **📤 Entregables Día 4:**
- [ ] Bunker Database (WordPress vulnerable) funcionando
- [ ] Suite de pentesting configurada
- [ ] Simulación de ataques ejecutada
- [ ] SIEM detectando y alertando sobre ataques
- [ ] WAF bloqueando intentos maliciosos
- [ ] Reporte de vulnerabilidades y remediaciones

---

## ⚙️ **DÍA 5 (VIERNES): TERRAFORM COMPLETO + DEPLOYMENT (5%)**

### **👤 Persona 4 (Jose): Terraform Infrastructure as Code**
**Tiempo:** 6 horas

#### **Terraform completo para replicar TODO:**
```hcl
# main.tf - Infraestructura completa
terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
  }
}

# Variables
variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region"
  type        = string
  default     = "us-central1"
}

# Networks
resource "google_compute_network" "secure_network" {
  name                    = "secure-database-network"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "database_subnet" {
  name          = "database-subnet"
  ip_cidr_range = "10.1.0.0/24"
  region        = var.region
  network       = google_compute_network.secure_network.id
}

resource "google_compute_subnetwork" "tools_subnet" {
  name          = "tools-subnet"
  ip_cidr_range = "10.2.0.0/24"
  region        = var.region
  network       = google_compute_network.secure_network.id
}

# Firewall Rules
resource "google_compute_firewall" "database_firewall" {
  name    = "allow-database-secure"
  network = google_compute_network.secure_network.name

  allow {
    protocol = "tcp"
    ports    = ["22", "1433", "3306", "5432"]
  }

  source_ranges = ["10.0.0.0/8"]
  target_tags   = ["database-server"]
}

resource "google_compute_firewall" "web_firewall" {
  name    = "allow-web-secure"
  network = google_compute_network.secure_network.name

  allow {
    protocol = "tcp"
    ports    = ["22", "80", "443", "8080"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["web-server"]
}

# Database VM with startup script
resource "google_compute_instance" "database_vm" {
  name         = "database-server-prod"
  machine_type = "e2-standard-4"
  zone         = "${var.region}-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
      size  = 150
      type  = "pd-ssd"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.database_subnet.id
    access_config {}
  }

  metadata_startup_script = file("${path.module}/scripts/database_setup.sh")

  tags = ["database-server"]
}

# Tools VM with startup script
resource "google_compute_instance" "tools_vm" {
  name         = "tools-server-prod"
  machine_type = "e2-standard-4"
  zone         = "${var.region}-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
      size  = 100
      type  = "pd-ssd"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.tools_subnet.id
    access_config {}
  }

  metadata_startup_script = file("${path.module}/scripts/tools_setup.sh")

  tags = ["web-server", "tools-server"]
}

# Cloud SQL for production (encrypted)
resource "google_sql_database_instance" "production_mysql" {
  name             = "production-mysql-encrypted"
  database_version = "MYSQL_8_0"
  region           = var.region

  settings {
    tier = "db-f1-micro"
    
    backup_configuration {
      enabled = true
      start_time = "03:00"
    }
    
    ip_configuration {
      require_ssl = true
    }
    
    database_flags {
      name  = "general_log"
      value = "on"
    }
  }

  deletion_protection = false
}

# Outputs
output "database_vm_ip" {
  value = google_compute_instance.database_vm.network_interface[0].access_config[0].nat_ip
}

output "tools_vm_ip" {
  value = google_compute_instance.tools_vm.network_interface[0].access_config[0].nat_ip
}

output "cloud_sql_ip" {
  value = google_sql_database_instance.production_mysql.ip_address[0].ip_address
}
```

#### **Scripts de configuración automática:**
```bash
# scripts/database_setup.sh
#!/bin/bash
set -e

# Instalar Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
usermod -aG docker $(whoami)

# Descargar configuración del proyecto
git clone https://github.com/tu-usuario/proyecto-seguridad-bd.git /opt/proyecto
cd /opt/proyecto

# Ejecutar configuración automática
chmod +x install_databases.sh
./install_databases.sh

# Configurar monitoreo
systemctl enable docker
systemctl start docker

# Log de completado
echo "Database setup completed at $(date)" >> /var/log/setup.log
```

```bash
# scripts/tools_setup.sh
#!/bin/bash
set -e

# Instalar Apache + PHP
apt update
apt install -y apache2 php libapache2-mod-php php-mysql php-pgsql

# Instalar Wazuh
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
bash ./wazuh-install.sh -a

# Instalar ModSecurity
apt install -y libapache2-mod-security2
a2enmod security2

# Configurar servicios
systemctl enable apache2
systemctl enable wazuh-manager

# Log de completado
echo "Tools setup completed at $(date)" >> /var/log/setup.log
```

#### **Pipeline de deployment automatizado:**
```yaml
# .github/workflows/deploy.yml
name: Deploy Infrastructure

on:
  push:
    branches: [ main ]

jobs:
  deploy:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Setup Terraform
      uses: hashicorp/setup-terraform@v1
      
    - name: Terraform Init
      run: terraform init
      
    - name: Terraform Plan
      run: terraform plan
      
    - name: Terraform Apply
      run: terraform apply -auto-approve
      
    - name: Run Security Tests
      run: |
        # Esperar que la infraestructura esté lista
        sleep 300
        
        # Ejecutar tests de seguridad automatizados
        python3 security_tests.py
```

### **📤 Entregables Día 5:**
- [ ] Terraform scripts para infraestructura completa
- [ ] Deployment automatizado funcionando
- [ ] Pipeline CI/CD configurado
- [ ] Scripts de configuración automatizada
- [ ] Documentación de deployment

---

## 🎯 **RESUMEN FINAL - 100% COMPLETADO:**

### **✅ Semana 1 (55%):**
- 3 Bases de datos funcionando
- Clientes web configurados
- SIEM básico (Wazuh)
- WAF básico (ModSecurity)
- Power BI dashboards

### **✅ Semana 2 (45%):**
- Data masking y encriptación avanzada
- Integración Oracle Cloud (hybrid)
- SIEM avanzado con triggers y ML
- Penetration testing completo
- Bunker database para pruebas
- Terraform Infrastructure as Code
- Pipeline de deployment automatizado

### **🏆 CAPACIDADES FINALES:**
- **Seguridad:** TDE, Always Encrypted, RLS, Dynamic Data Masking
- **Monitoreo:** SIEM con ML, triggers de auditoría, alertas automáticas
- **Cloud:** Híbrido on-premise + Oracle Cloud
- **Pentesting:** Vulnerabilidades identificadas y remediadas
- **Automatización:** Terraform + CI/CD para reproducir todo
- **BI:** Dashboards multi-cloud con análisis de seguridad

**¡PROYECTO 100% COMPLETADO Y LISTO PARA PRODUCCIÓN!** 🚀