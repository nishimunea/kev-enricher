import pandas as pd

nvds = pd.read_csv('./nvd_cpes.csv', encoding='utf-8')
kevs = pd.read_csv('./known_exploited_vulnerabilities.csv', encoding='utf-8')

cpes = []
for index, row in kevs.iterrows():
  affected_cpes = nvds[nvds['cve_id'] == row['cveID']]
  cpes.append(','.join(affected_cpes['uri'].tolist()))

kevs['cpes'] = cpes

kevs.to_csv('./known_exploited_vulnerabilities_with_cpes.csv')
