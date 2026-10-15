import os
import json
from pathlib import Path

def analyse_trafic(traffic: dict):
    traffic_dict = {
        'records': 0,
        'protocols': {
            'tcp': 0,
            'udp': 0
        },
        'blocked': 0,
        'total_recorded_traffic': 0
    }
    if traffic.get('records') is not None and len(traffic.get('records')): return {}
    for record in traffic.get('records'):
        pass

def main():
    print('='*20)
    print('Python Network Traffic Analyser')
    print('='*20)
    while True: 
        network = Path(input('Enter a network to analyse: '))
        if not network.exists():
            print('Network not found')
        elif network.is_dir():
            print('Plese enter a file not a directory')
        elif network.suffix is not '.json':
            print('This network only accepts json files')
        else: break
    with open(str(network)) as networkfile:
        network_dict = json.load(networkfile)
        

        print('No records to show')
    


if __name__=='__main__'():
    main()