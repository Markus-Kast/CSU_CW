import re

def parse_log_file(file_path):
    results = []  
    with open(file_path, 'r') as file:
        content = file.read()

    host_blocks = content.split('-------------------------------------------------')

    for block in host_blocks:
        block = block.strip()
        if not block:
            continue  
        host_info = {}
        cves = []

        lines = block.splitlines()
        for line in lines:
            line = line.strip()
            if line.startswith('[*] port:'):
                host_info['port'] = int(line.split(': ')[1])  
            elif line.startswith('[+] protocol:'):
                host_info['protocol'] = line.split(': ')[1]
            elif line.startswith('[+] service:'):
                host_info['service'] = line.split(': ')[1]
            elif line.startswith('[+] product:'):
                host_info['product'] = line.split(': ')[1]
            elif line.startswith('[+] version:'):
                host_info['version'] = line.split(': ')[1]
            elif line.startswith('[-]'):
                cve_info = re.findall(r'id: (\S+)\s+cvss_v2: (\S+)\s+cvss_v3: (\S+)', line)
                if cve_info:
                    cves.append({
                        'id': cve_info[0][0],
                    })

        results.append({
            'port': host_info.get('port'),
            'protocol': host_info.get('protocol'),
            'service': host_info.get('service'),
            'product': host_info.get('product'),
            'version': host_info.get('version'),
            'cves': cves
        })

    return results  
