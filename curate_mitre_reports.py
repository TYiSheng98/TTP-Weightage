from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning
import os
import json
import requests

REPORTS_DIRECTORY = r'C:\Users\YISHENG\Documents\MITRE_REPORT\mitre_nav_reports'
ACTORS_OUTPUT_FILEPATH = r'C:\Users\YISHENG\Documents\MITRE_REPORT\family_actors.json'


def filter_software(software_soup, software_id, malware_family):
    # check if malware
    for header in software_soup.select('span.h5'):
        if header.text == 'Type':
            software_type = header.next_sibling.strip()
            break

    if software_type != ': MALWARE':
        print(f'{software_id} {malware_family} is not a malware')
        return 0
    try:

        # check if enterprise
        if software_soup.select_one('table.techniques-used').select_one('tbody td').text.strip() != 'Enterprise':
            print(f'{software_id} {malware_family} is not a Enterprise Software')
            return 0
    except Exception:
        pass

    return 1


def download_report(software_id, malware_family):
    report_link = f'https://attack.mitre.org/software/{software_id}/{software_id}-enterprise-layer.json'
    filename = report_link.split('/')[-1].replace(' ', '_')
    r = requests.get(report_link, stream=True, verify=False)

    if not r.ok:
        print(f'Failed to download report for {software_id} {malware_family}')
        return 0

    # check if enterprise report
    if r.ok:
        print(f'Downloading report for {software_id} {malware_family}')
        with open(os.path.join(REPORTS_DIRECTORY, filename), 'wb') as outfile:
            for chunk in r.iter_content(chunk_size=1024 * 8):
                if chunk:
                    outfile.write(chunk)
                    outfile.flush()
                    os.fsync(outfile.fileno())

    return 1


def obtain_actors(software_soup, family_actors, software_id, malware_family):
    family_actors[software_id] = {
        'family': malware_family,
        'actors': []
    }
    
    print(f'Obtaining actors for {software_id} {malware_family}.')
    tables = software_soup.select('table.table-alternate')
    if tables:
        for actor_table in tables:
            # check if table is actor table
            if actor_table.select_one('th').text == 'ID':
                for row in actor_table.select('tbody tr'):
                    cells = row.select('a')
                    actor_name = cells[1].text
                    family_actors[software_id]['actors'].append(actor_name)


def main():
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    family_actors = {}
    softwares_soup = BeautifulSoup(requests.get('https://attack.mitre.org/software/', stream=True, verify=False).content, 'html.parser')

    for software_row in softwares_soup.select('tbody tr'):
        software_id = software_row.select_one('a').text.strip()
        software_soup = BeautifulSoup(requests.get(f'https://attack.mitre.org/software/{software_id}/', stream=True, verify=False).content, 'html.parser')
        malware_family = software_soup.select_one('h1').text.strip()

        # filter for Enterprise Malwares
        if not filter_software(software_soup, software_id, malware_family):
            continue

        if not download_report(software_id, malware_family):
            pass

        obtain_actors(software_soup, family_actors, software_id, malware_family)

    with open(ACTORS_OUTPUT_FILEPATH, 'w') as outfile:
        json.dump(family_actors, outfile)

    return 0
        

if __name__ == '__main__':
    main()
