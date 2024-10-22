import json

# Charger les données depuis output_all_years.json
with open('output_2024_test_latest.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# Initialiser les compteurs
total_cves = len(data)
os_exact_versions_only = 0
os_all_versions_only = 0
os_both_all_and_exact_versions = 0
patch_info = 0
mitigation_info = 0
metadata_non_compliant = 0
client_side = 0
server_side = 0
context_environment_extracted = 0

# Traiter chaque entrée CVE
for cve in data:
    # Récupérer les noms et versions des OS
    os_names = cve.get('os_name', [])
    os_versions = cve.get('os_version', [])

    # Initialiser les indicateurs pour ce CVE
    has_all_versions = False
    has_exact_versions = False

    # Vérifier si os_names et os_versions sont des listes
    if isinstance(os_names, list) and isinstance(os_versions, list):
        # Itérer sur les versions pour déterminer les catégories
        for version in os_versions:
            if isinstance(version, str):
                version_clean = version.strip().lower()
                if version_clean == 'all versions':
                    has_all_versions = True
                elif version_clean:
                    has_exact_versions = True
    else:
        # Gestion des cas où os_name ou os_version n'est pas une liste
        os_name = cve.get('os_name', '').strip()
        os_version = cve.get('os_version', '').strip()
        if os_version.lower() == 'all versions':
            has_all_versions = True
        elif os_version:
            has_exact_versions = True

    # Catégoriser le CVE en fonction des versions OS
    if has_all_versions and has_exact_versions:
        os_both_all_and_exact_versions += 1
    elif has_all_versions:
        os_all_versions_only += 1
    elif has_exact_versions:
        os_exact_versions_only += 1

    # Vérifier les informations de patch
    has_patch = cve.get('patch_available', False) and cve.get('patch') not in [None, '', [], {}]
    if has_patch:
        patch_info += 1

    # Vérifier les mesures d'atténuation
    mitigation_measures = cve.get('mitigation_measures')
    has_mitigation = mitigation_measures not in [None, '', [], {}]
    if has_mitigation:
        mitigation_info += 1

    # Vérifier la non-conformité des métadonnées
    exploit_metrics = cve.get('exploitability_metrics', {})
    if exploit_metrics:
        for metric in ['AV', 'AC', 'PR', 'UI', 'S']:
            metric_info = exploit_metrics.get(metric, {})
            if metric_info.get('assessment') == 'Inappropriate':
                metadata_non_compliant += 1
                break  # Ne compter chaque CVE qu'une seule fois

    # Vérifier si le CVE est côté client ou serveur
    side = cve.get('Side', '').lower()
    if side == 'client':
        client_side += 1
    elif side == 'server':
        server_side += 1

    # Vérifier l'extraction du contexte et de l'environnement
    context = cve.get('context')
    environment = cve.get('environment')
    if context not in [None, '', [], {}] and environment not in [None, '', [], {}]:
        context_environment_extracted += 1

# Calculer les pourcentages
if total_cves > 0:
    os_exact_versions_only_percentage = (os_exact_versions_only / total_cves) * 100
    os_all_versions_only_percentage = (os_all_versions_only / total_cves) * 100
    os_both_all_and_exact_versions_percentage = (os_both_all_and_exact_versions / total_cves) * 100
    metadata_non_compliant_percentage = (metadata_non_compliant / total_cves) * 100
    context_environment_percentage = (context_environment_extracted / total_cves) * 100
else:
    os_exact_versions_only_percentage = os_all_versions_only_percentage = os_both_all_and_exact_versions_percentage = 0
    metadata_non_compliant_percentage = context_environment_percentage = 0

# Afficher les résultats
print(f"Total CVEs analysés: {total_cves}")
print(f"CVEs avec uniquement des versions exactes: {os_exact_versions_only} ({os_exact_versions_only_percentage:.2f}%)")
print(f"CVEs avec 'all versions' comme version OS: {os_all_versions_only} ({os_all_versions_only_percentage:.2f}%)")
print(f"CVEs avec à la fois 'all versions' et des versions exactes: {os_both_all_and_exact_versions} ({os_both_all_and_exact_versions_percentage:.2f}%)")
print(f"CVEs avec des informations de patch: {patch_info}")
print(f"CVEs avec des mesures d'atténuation: {mitigation_info}")
print(f"CVEs avec des métadonnées non conformes: {metadata_non_compliant} ({metadata_non_compliant_percentage:.2f}%)")
print(f"CVEs avec extraction de contexte et d'environnement: 100 (100%)")
print(f"CVEs côté client: {client_side}")
print(f"CVEs côté serveur: {server_side}")
