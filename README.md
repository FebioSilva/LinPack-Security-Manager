# 🧠 LinPack – A Way to Manage Vulnerable Linux Packages More Efficiently

LinPack is a semantic-based system designed to identify and monitor vulnerabilities in Linux environments. It analyzes actions recorded by the Debian package manager (`dpkg.log`) and cross-references them with public vulnerability databases, such as the NVD. The result is a **knowledge graph** that enables intelligent, visual exploration of a system’s security posture.s

> Final BSc Project at Instituto Superior de Engenharia de Lisboa (ISEL), 2025.  
> Authors: Bruno Raposo, Fábio Silva  
> Supervisors: Cátia Vaz, Bruno Lourenço

---

## ❓ Why LinPack?

The **Directive (EU) 2022/2555 (NIS 2)** requires all Member States to ensure a high level of cybersecurity by promoting the adoption of technologies capable of detecting and preventing cyber threats early and efficiently. It encourages the development of **automated or semi-automated solutions** for identifying vulnerabilities and minimizing exposure.

Despite this directive, **most current vulnerability detection strategies still rely on manual analysis or static tools**, which limits their efficiency and prolongs system exposure to threats. This creates a clear need for smarter, more adaptive solutions.

To address this gap, we developed **LinPack** — a semantic-based system for identifying and monitoring vulnerabilities in Linux environments.

LinPack collects data about installed packages and known security vulnerabilities, and then organizes it into a **knowledge graph**. This allows for:

- **Intuitive and visual exploration** of a system's security posture;
- **Faster identification of at-risk packages**;
- **Improved monitoring** of evolving vulnerabilities.

## System stores this structured information in a triple store, a type of **non-relational database**, enabling advanced semantic queries and flexible data management.

## 📸 System Architecture

![System Architecture](/resources/system_architecture.png)

---

## ✨ Features

- Extracts and parses installed packages from `dpkg.log`
- Automatically fetches CVEs from [NVD API](https://nvd.nist.gov/)
- Models data using two ontologies (CVEs and DPKG logs)
- Stores triples in a **Knowledge Graph** using Virtuoso
- Supports semantic queries via SPARQL
- Modular Python-based architecture

---

## 🛠 Tech Stack

- **Language:** Python
- **Semantic Technologies:** RDF, OWL, Turtle, SPARQL
- **Triple Store:** OpenLink Virtuoso
- **APIs:** National Vulnerability Database (NVD)
- **Others:** Docker, SPARQLWrapper

---

## 📂 Project Structure

| Path/Folder                                                                             | Description                                         |
| --------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `code/`                                                                                 | Source code directory                               |
| &nbsp;&nbsp;&nbsp;&nbsp;`app/`                                                          | Application logic and processing                    |
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`js/main.js`                            | Main JavaScript file for the web interface          |
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`js/proxy.js`                           | JavaScript proxy for requests to Virtuoso DB        |
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`index.html`                            | Main HTML file for the web interface                |
| &nbsp;&nbsp;&nbsp;&nbsp;`log/`                                                          | Log processing module                               |
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`log.py`                                | Extracts, converts and uploads logs to Virtuoso DB  |
| &nbsp;&nbsp;&nbsp;&nbsp;`nvd/`                                                          | NVD processing module                               |
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`nvd.py`                                | Extracts, converts and uploads CVEs to Virtuoso DB  |
| &nbsp;&nbsp;&nbsp;&nbsp;`dbOperations.py`                                               | Handles DB operations for inserting into Virtuoso   |
| `resources/`                                                                            | Resources directory                                 |
| &nbsp;&nbsp;&nbsp;&nbsp;`ontologies/`                                                   | Ontology definitions                                |
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`linpack_ontology.ttl`                  | Main ontology (imports CVE and DPKG log ontologies) |
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`cveOntology/cve.ttl`                   | CVE ontology (extended from UCO)                    |
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`logOntology/log.event.ontology_v2.ttl` | DPKG log ontology (v2)                              |
| &nbsp;&nbsp;&nbsp;&nbsp;`dpkg.log`                                                      | Sample dataset of DPKG logs                         |
| `Final_Project.pdf`                                                                     | Final project report                                |

---

# 🚀 Getting Started

## ✅ Prerequisites

- Python
- Docker (to run Virtuoso)
- SPARQLWrapper

---

## 📦 1. Setting up Virtuoso

```bash
docker pull openlink/virtuoso-opensource-7
docker run -d -p 8890:8890 --name virtuoso openlink/virtuoso-opensource-7
docker exec -it virtuoso bash
```

After running the container, access Virtuoso at `http://localhost:8890` with default credentials (`dba`/`dba`).

- Go to the **"Linked Data"** tab → **"Quad Store Upload"**  
  → Upload `linpack_ontology.ttl` and name it: `http://localhost:8890/linpack`

- Set up SPARQL user permissions:

  - Go to **"System Admin"** → **"User Accounts"**
  - Edit user `SPARQL` and check **all "Read" and "Write"** permissions
  - Save changes

- Set default RDF permissions:
  - Go to **"Database"** → **"Interactive SQL"**
  - Execute the following SQL command:

```sql
DB.DBA.RDF_DEFAULT_USER_PERMS_SET ('nobody', 7);
```

---

## 📥 2. Cloning the Repository and Setting Up the Environment

```bash
git clone https://github.com/FebioSilva/LinPack-Security-Manager.git
cd LinPack-Security-Manager/code
pip install SPARQLWrapper
cd app
npm install
```

---

## 🐍 3. Running the Python Scripts to Populate Virtuoso DB

```bash
cd ../log
python log.py
cd ../nvd
python nvd.py
```

### ✅ Testing the Setup

To verify that everything is working, run this example query in Virtuoso's SPARQL UI:

- Go to **"Linked Data"** → **"SPARQL"**
- Paste the following queries and execute it:

```sparql
PREFIX : <http://purl.org/cyber/cve#>
SELECT ?cve ?description ?score
WHERE {
  ?cve a :CVE ;
       :description ?description ;
       :base_score ?score .
}
LIMIT 10

```

```sparql
SELECT ?event ?action ?timestamp ?package
WHERE {
  ?event a :ActionEvent ;
         :action ?action ;
         :timestamp ?timestamp ;
         :has_package ?package .
}
LIMIT 10
```

If successful, this will return a list of CVEs for the first query and a list of packages for the second query, confirming that the data has been correctly uploaded to Virtuoso.

---

## 🌐 4. Running the Web Interface (basic prototype)

```bash
cd ../app/js
node proxy.js
```

Now open `index.html` in your browser to access LinPack's web interface. The app connects to Virtuoso and allows you to explore the knowledge graph of vulnerabilities and packages.

---

## 🗺️ Roadmap / TODO

- Improve web application, to allow filtering and searching of vulnerabilities by adding more advanced SPARQL queries for deeper insights.
- Implement LLM's for advanced processing of data
- Make LinkPack available as a web service instead of a local application, allowing users to access it via a web interface without needing to run the backend locally.

---

## 🤝 Contributing

This is a BSc final project. Contributions are welcome for educational or experimental purposes. Feel free to open issues.
