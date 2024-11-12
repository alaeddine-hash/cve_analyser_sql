import json
import csv
from collections import defaultdict

def determine_impact_level(score):
    """
    Détermine le niveau d'impact basé sur le score CVSS.
    """
    try:
        score = float(score)
    except (ValueError, TypeError):
        return 'N/A'
    
    if score == 0.0:
        return 'None'
    elif 0.1 <= score <= 3.9:
        return 'Low'
    elif 4.0 <= score <= 6.9:
        return 'Medium'
    elif 7.0 <= score <= 8.9:
        return 'High'
    elif 9.0 <= score <= 10.0:
        return 'Critical'
    else:
        return 'N/A'

# Charger les données depuis le fichier JSON
with open('cve_output_06_11.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# Nom des fichiers CSV de sortie
output_csv_file = 'cve_output_06_11_impact_2.csv'
vendor_distribution_file = 'vendor_distribution_2.csv'
vendor_impact_distribution_file = 'vendor_impact_distribution_2.csv'  # Nouveau fichier

# Structures pour collecter les statistiques des fournisseurs
vendor_stats = defaultdict(lambda: {'cve_count': 0, 'patch_available': 0, 'patch_not_available': 0})
vendor_impact_stats = defaultdict(lambda: defaultdict(int))  # Nouvelle structure

# Ouvrir un fichier CSV pour écrire les données CVE avec 'impact_level'
with open(output_csv_file, mode='w', newline='', encoding='utf-8') as csvfile:
    csv_writer = csv.writer(csvfile)
    
    # Écrire l'en-tête du fichier CSV avec 'impact_level'
    csv_writer.writerow([
        'cve-id', 'published_date', 'updated_date', 'cvss_score', 'cvss_vector_v3',
        'vulnerability_component_name', 'vulnerability_component_version', 'vulnerability_component_type',
        'vendor_name', 'os_name_versions', 'os_version_specified','generated_cvss_vector','generated_cvss_score', 
        'Other_Environment_Restrictions', 'matadonnées_conformitie', 
        'patch_availability', 'lien_vers_le_patch', 'patch_date',  # Ajout de la virgule ici
        'mitigation_measures', 'Mitigation_availability', 'impact_level'  # Ajout de 'impact_level'
    ])
    
    # Traiter chaque entrée CVE dans le fichier JSON
    for cve in data:
        # Extraire les informations de base
        cve_id = cve.get('cve_id', 'N/A')
        cvss_score = cve.get('cvss_score_v3', 'N/A')
        cvss_vector_v3 = cve.get('cvss_vector_v3', 'N/A')
        published_date = cve.get('published', 'N/A')
        updated_date = cve.get('last_modified', 'N/A')
        vendor_name = cve.get('vendor_name', 'N/A')

        # Mettre à jour les statistiques des fournisseurs
        vendor_stats[vendor_name]['cve_count'] += 1
        if cve.get('patch_available', False):
            vendor_stats[vendor_name]['patch_available'] += 1
        else:
            vendor_stats[vendor_name]['patch_not_available'] += 1

        vulnerability_component_name = cve.get('vulnerability_component_name', [])
        vulnerability_component_version = cve.get('vulnerability_component_version', [])
        vulnerability_component_type = cve.get('vulnerability_component_type', 'N/A')
        generated_cvss_vector = cve.get('generated_cvss_vector', 'N/A')
        generated_cvss_score = cve.get('generated_cvss_score', 'N/A')
        
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
        
        # Déterminer le niveau d'impact
        if cvss_score != '0.00' and cvss_score != 'N/A':
            impact_level = determine_impact_level(cvss_score)
        else:
            impact_level = determine_impact_level(generated_cvss_score)
        
        # Mettre à jour les statistiques d'impact par fournisseur
        vendor_impact_stats[vendor_name][impact_level] += 1
        
        # Écrire les données dans le fichier CSV, y compris 'impact_level'
        csv_writer.writerow([
            cve_id, published_date, updated_date, cvss_score, cvss_vector_v3,
            vulnerability_component_name, vulnerability_component_version, vulnerability_component_type,
            vendor_name, os_name_versions, os_version_specified, generated_cvss_vector, generated_cvss_score,
            other_environment_restrictions, matadonnées_conformitie, 
            patch_availability, patch_link, patch_date,
            mitigation_measures, mitigation_availability, impact_level  # Ajout de 'impact_level'
        ])

print(f"Le fichier CSV avec les impacts a été généré sous le nom {output_csv_file}")

# Maintenant, écrire les statistiques des fournisseurs dans un autre fichier CSV
with open(vendor_distribution_file, mode='w', newline='', encoding='utf-8') as vendor_csvfile:
    vendor_writer = csv.writer(vendor_csvfile)
    
    # Écrire l'en-tête du fichier CSV des statistiques des fournisseurs
    vendor_writer.writerow([
        'vendor_name', 'cve_count', 'patch_available', 'patch_not_available', 'patch_available_percentage'
    ])
    
    # Écrire les données pour chaque fournisseur
    for vendor, stats in vendor_stats.items():
        cve_count = stats['cve_count']
        patch_available = stats['patch_available']
        patch_not_available = stats['patch_not_available']
        # Calculer le pourcentage de patches disponibles
        if cve_count > 0:
            patch_available_percentage = (patch_available / cve_count) * 100
            patch_available_percentage = f"{patch_available_percentage:.2f}%"
        else:
            patch_available_percentage = 'N/A'
        
        vendor_writer.writerow([
            vendor, cve_count, patch_available, patch_not_available, patch_available_percentage
        ])

print(f"Le fichier CSV des statistiques des fournisseurs a été généré sous le nom {vendor_distribution_file}")

# Maintenant, écrire les statistiques d'impact par fournisseur dans un autre fichier CSV
with open(vendor_impact_distribution_file, mode='w', newline='', encoding='utf-8') as vendor_impact_csvfile:
    vendor_impact_writer = csv.writer(vendor_impact_csvfile)
    
    # Déterminer tous les niveaux d'impact présents
    all_impact_levels = set()
    for impacts in vendor_impact_stats.values():
        all_impact_levels.update(impacts.keys())
    all_impact_levels = sorted(all_impact_levels, key=lambda x: ['None', 'Low', 'Medium', 'High', 'Critical', 'N/A'].index(x) if x in ['None', 'Low', 'Medium', 'High', 'Critical', 'N/A'] else 999)
    
    # Écrire l'en-tête du fichier CSV des statistiques d'impact par fournisseur
    header = ['vendor_name'] + [f'impact_{level}' for level in all_impact_levels]
    vendor_impact_writer.writerow(header)
    
    # Écrire les données pour chaque fournisseur
    for vendor, impacts in vendor_impact_stats.items():
        row = [vendor]
        for level in all_impact_levels:
            row.append(impacts.get(level, 0))
        vendor_impact_writer.writerow(row)

print(f"Le fichier CSV des statistiques d'impact par fournisseur a été généré sous le nom {vendor_impact_distribution_file}")
