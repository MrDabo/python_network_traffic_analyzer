import os
import json
from pathlib import Path

def analyse_traffic(traffic: dict):
    traffic_dict = {
        'records': len(traffic.get('records')) if traffic.get('records') else 0 ,
        'protocols': {
            'tcp': {
                'count': 0,
                'packets': 0,
                'bytes': 0
            },
            'udp':{
                'count': 0,
                'packets': 0,
                'bytes': 0
            }
        },
        'blocked': 0,
        'allowed': 0,
        'total_bytes': 0,
        'total_packets': 0,
        'hb_ip': '',
        'hb': 0,
        'large_trafic': [],
        'repeated_blocked connections': []
    }
    blocked = []
    if traffic.get('records') is None and not len(traffic.get('records')): return traffic_dict
    for record in traffic.get('records'):
        protocol = record['protocol'].lower()
        if traffic_dict['protocols'].get(protocol) is None:
            traffic_dict['protocols'].update({protocol: {
                    'count': 0,
                    'packets': 0,
                    'bytes': 0
                }}) 
        traffic_dict['protocols'][protocol]['count'] += 1
        traffic_dict['protocols'][protocol]['bytes'] += record['bytes'] 
        traffic_dict['total_bytes'] += record['bytes'] 
        traffic_dict['protocols'][protocol]['packets'] += record['packets'] 
        traffic_dict['total_packets'] += record['packets'] 
        if record['action'] == 'allowed':
            traffic_dict['allowed'] += 1
        else:
            traffic_dict['blocked'] += 1 
            blocked.append(record)
        if record['bytes'] > traffic_dict['hb']:
            traffic_dict['hb'] = record['bytes']
            traffic_dict['hb_ip'] = record['src_ip']
    for record in blocked:
        count = len(filter(lambda x: x['src_ip'] == record['src_ip'] and x['dst_ip'] == record['dst_ip'], blocked))
        if count > 2:
            is_in = False
            for x in traffic_dict['repeated_blocked connections']:
                if x['src_ip'] == record['src_ip'] and x['dst_ip'] == record['dst_ip']:
                        is_in = True

            traffic_dict['repeated_blocked connections'].append(record) if is_in is not True else None
    return traffic_dict

def format_byte(byte):
    rem_byte = byte % 1028
    kilobbyte = byte // 1028
    megabyte = byte // (1028 * 1028)
    gigabyte = byte // (1028 * 1028 * 1028)
    if gigabyte:
        return round(gigabyte + ((megabyte * 1028 * 1028)/( 1028 * 1028 * 1028)) * 100, 1)
    elif megabyte:
        return round(megabyte + ((kilobbyte * 1028)/( 1028 * 1028)) * 100, 1)
    else: 
        return round(kilobbyte + ((rem_byte)/( 1028)) * 100, 1)
        

def main():
    title = 'Network Traffic Analyser'
    print('='*20)
    print(f'Python {title}')
    print('='*20)
    while True: 
        network = Path(input('Enter a network to analyse: '))
        if not network.exists():
            print('Network not found')
        elif network.is_dir():
            print('Plese enter a file not a directory')
        elif network.suffix != '.json':
            print('This network only accepts json files')
        else: break
    with open(str(network)) as networkfile:
        network_dict = json.load(networkfile)
        analysed_traffic = analyse_traffic(network_dict)
        print(title)
        print('Analysis report - OfficeNet')
        print('Traffic records', end='\t')
        print('Traffic recorded traffic')
        print(analysed_traffic['records'], end='\t')
        print(format_byte(analysed_traffic['total_bytes']))
        print()
        print('TCP records', end='\t')
        print('Blocked records')
        print(analysed_traffic['protocols']['tcp']['count'], end='\t')
        print(analysed_traffic['blocked'])
        

        print('No records to show')
    
if __name__=='__main__':
    main()