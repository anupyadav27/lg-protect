# Project Overview

## lg-protect

This repository contains tools and scripts for compliance checks, inventory management, and cloud security posture management (CSPM). The project is structured to provide a comprehensive solution for evaluating and maintaining security and compliance in cloud environments.

---

## Folder Structure

### core-engine/
This folder contains the core logic for compliance checks and simulations.
- **compliance_checks.csv**: CSV file containing compliance check data.
- **compliance_checks.json**: JSON file containing compliance check data.
- **converter_csv-json.py**: Script to convert compliance data between CSV and JSON formats.
- **simulation_results.ipynb**: Jupyter notebook for simulating compliance scenarios.
- **compliance_rules/**: Contains JSON files defining various compliance rules.

### inventory/
This folder contains inventory-related data and scripts.
- **aws service region wise.xlsx**: Excel file listing AWS services by region.
- **inventory_collection v7.py**: Python script for collecting inventory data.
- **Service and function.xlsx**: Excel file detailing services and functions.

### cspm/
This folder contains tools for Cloud Security Posture Management.
- **package.json**: Configuration file for CSPM platform.
- **README.md**: Documentation for CSPM platform.
- **cspm-platform/**: Contains CSPM platform-specific scripts and configurations.

### opa_evaluation_engine/
This folder contains the Open Policy Agent (OPA) evaluation engine.
- **config/**: Configuration files for OPA.
- **data/**: Data files used by OPA.
- **evaluations/**: Scripts for evaluating policies.
- **input_builder/**: Scripts for building input data for OPA.
- **opa/**: Core OPA engine files.

---

## Purpose

The purpose of this repository is to:
1. Automate compliance checks for cloud environments.
2. Manage and analyze inventory data.
3. Provide tools for evaluating and improving cloud security posture.
4. Enable policy evaluation using Open Policy Agent (OPA).

---

## Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/anupyadav27/lg-protect.git
   ```
2. Navigate to the desired folder to explore its contents.
3. Refer to individual README files in subfolders for detailed instructions.

---

## Contributions

Contributions are welcome! Please fork the repository and submit a pull request for any improvements or new features.