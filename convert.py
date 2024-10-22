import json
import csv
from datetime import datetime

# Charger les données depuis le fichier JSON
with open('output_all_years_1.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# Nom du fichier CSV de sortie
output_csv_file = 'cve_data_analysis_other_years.csv'

# Ouvrir un fichier CSV pour écrire les données
with open(output_csv_file, mode='w', newline='', encoding='utf-8') as csvfile:
    csv_writer = csv.writer(csvfile)
    
    # Écrire l'en-tête du fichier CSV
    csv_writer.writerow(['cve-id', 'published_date', 'updated_date', 'os_name_versions', 'matadonnées_conformitie', 'patch_availability', 'date_de_patch'])
    
    # Traiter chaque entrée CVE dans le fichier JSON
    for cve in data:
        # Extraire les informations de base
        cve_id = cve.get('cve_id', 'N/A')
        published_date = cve.get('published', 'N/A')
        updated_date = cve.get('last_modified', 'N/A')
        
        # Récupérer les noms et versions des OS
        os_names = cve.get('os_name', [])
        os_versions = cve.get('os_version', [])
        os_name_versions = ', '.join([f"{name} {version}" for name, version in zip(os_names, os_versions)]) if os_names and os_versions else 'N/A'
        
        # Vérifier la conformité des métadonnées
        exploit_metrics = cve.get('exploitability_metrics', {})
        matadonnées_conformitie = 1  # Par défaut, tout est conforme
        if exploit_metrics:
            for metric in ['AV', 'AC', 'PR', 'UI', 'S']:
                metric_info = exploit_metrics.get(metric, {})
                if metric_info.get('assessment') == 'Inappropriate':
                    matadonnées_conformitie = 0  # Non conforme si une métrique est "Inappropriate"
                    break
        
        # Vérifier la disponibilité du patch
        patch_availability = 'Yes' if cve.get('patch_available', False) else 'No'
        patch_date = cve.get('patch', {}).get('last_update', 'N/A') if cve.get('patch_available', False) else 'N/A'
        
        # Écrire les données dans le fichier CSV
        csv_writer.writerow([cve_id, published_date, updated_date, os_name_versions, matadonnées_conformitie, patch_availability, patch_date])

print(f"Le fichier CSV a été généré sous le nom {output_csv_file}")
