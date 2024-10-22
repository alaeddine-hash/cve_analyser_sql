import json
import csv

# Charger les données depuis le fichier JSON
with open('output_2024_test_v4_latest.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# Nom du fichier CSV de sortie
output_csv_file = 'output_2024_test_v4_latest.csv'

# Ouvrir un fichier CSV pour écrire les données
with open(output_csv_file, mode='w', newline='', encoding='utf-8') as csvfile:
    csv_writer = csv.writer(csvfile)
    
    # Écrire l'en-tête du fichier CSV
    csv_writer.writerow([
    'cve-id', 'published_date', 'updated_date', 'cvss_score', 
    'vendor_name', 'os_name_versions', 'os_version_specified', 
    'Other_Environment_Restrictions', 'matadonnées_conformitie', 
    'patch_availability', 'lien_vers_le_patch', 'patch_date',  # Add comma here
    'mitigation_measures', 'Metigation_availability'
    ])

    
    # Traiter chaque entrée CVE dans le fichier JSON
    for cve in data:
        # Extraire les informations de base
        cve_id = cve.get('cve_id', 'N/A')
        cvss_score = cve.get('cvss_score_v3', 'N/A')
        published_date = cve.get('published', 'N/A')
        updated_date = cve.get('last_modified', 'N/A')
        vendor_name = cve.get('vendor_name', 'N/A')
        
        # Récupérer les noms et versions des OS
        os_names = cve.get('os_name', [])
        os_versions = cve.get('os_version', [])
        os_name_versions = ', '.join([f"{name} {version}" for name, version in zip(os_names, os_versions)]) if os_names and os_versions else 'N/A'

        # Vérifier si les versions OS sont spécifiées et différentes de 'All' ou 'All versions'
        os_version_specified = 'No'
        if os_versions and any(version.lower() not in ['all', 'all versions'] for version in os_versions):
            os_version_specified = 'Yes'
        
        # Vérifier si un contexte d'exploitation est présent
        exploitation_context = cve.get('exploitation_context', {})
        other_environment_restrictions = 'Yes' if exploitation_context else 'No'
        
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
        patch_info = cve.get('patch', {})
        patch_link = patch_info.get('release_link', 'N/A') if patch_availability == 'Yes' else 'N/A'
        patch_date = cve.get('patch', {}).get('last_update', 'N/A') if cve.get('patch_available', False) else 'N/A'

        # Vérifier la disponibilité des mesures d'atténuation
        mitigation_measures = cve.get('mitigation_measures', None)
        mitigation_availability = 'Yes' if mitigation_measures else 'No'
        if mitigation_measures is None:
            mitigation_measures = 'N/A'
        
        # Écrire les données dans le fichier CSV
        csv_writer.writerow([
            cve_id, published_date, updated_date, cvss_score, 
            vendor_name, os_name_versions, os_version_specified, 
            other_environment_restrictions, matadonnées_conformitie, 
            patch_availability, patch_link, patch_date,
            mitigation_measures, mitigation_availability
        ])

print(f"Le fichier CSV a été généré sous le nom {output_csv_file}")
