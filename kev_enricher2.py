import pandas as pd

nvd_cpes = pd.read_csv('./nvd_cpes.csv', encoding='utf-8')
nvd_cvss = pd.read_csv('./nvd_cvss3.csv', encoding='utf-8')
kevs = pd.read_csv('./known_exploited_vulnerabilities.csv', encoding='utf-8')

cpes = []
for index, row in kevs.iterrows():
  affected_cpes = nvd_cpes[nvd_cpes['cve_id'] == row['cveID']]
  cpes.append(','.join(affected_cpes['uri'].tolist()))
kevs['cpes'] = cpes

cvss_metrics = [
  'base_score', 'base_severity', 'attack_vector', 'attack_complexity',
  'privileges_required', 'user_interaction', 'scope',
  'confidentiality_impact', 'integrity_impact', 'availability_impact'
]

cvss = {key: [] for key in cvss_metrics}

for index, row in kevs.iterrows():
  affected_cvss = nvd_cvss[nvd_cvss['cve_id'] == row['cveID']].to_dict(orient='records')
  affected_cvss = affected_cvss[0] if len(affected_cvss) > 0 else {}
  for metric in cvss_metrics:
    cvss[metric].append(affected_cvss.get(metric, ''))

for metric in cvss_metrics:
  kevs[metric] = cvss[metric]

kevs.to_csv('./known_exploited_vulnerabilities_with_cpes_cvss.csv')
