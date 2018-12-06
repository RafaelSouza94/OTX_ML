from OTXv2 import OTXv2
from pandas.io.json import json_normalize
from time import ctime
import json
import os.path
import pandas as pd
import matplotlib.pyplot as plt


otx = OTXv2("API_KEY")

def main():

    print("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n")
    print("\tAlienvault Open Threat Exchange Machine Learning Experiments\n")
    print("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n")
    
    print("Loading pulses. . .\n")
    
    if os.path.exists("./pulses.json"):
        pulses = load_file()
    else:
        pulses = download_pulses()

    indicators = []

    for i in range(0, len(pulses)):
        indicators.append(json_normalize(pulses[i]["indicators"])) 

    choice = 0    
       
    print("Number of pulses: {}\n".format(len(pulses)))
	
    while choice != 9:
        print("Choose an option:\n")
        print("1 - Update")
        print("2 - Plot indicators")
        print("9 - Quit\n")
        
        choice = int(input('> '))
    
        if choice == 1:
            result = update_check()
            if result:
                pulses = result
                for i in range(0, len(pulses)):
                    indicators.append(json_normalize(pulses[i]["indicators"]))  
        if choice == 2:
            plot_indicator_types(indicators)


def load_file():
    print("Opening pulses file. . .\n")
    with open('pulses.json', encoding='utf-8') as json_data:
        pulses = json.load(json_data)
    return pulses


def download_pulses():
    print("Downloading pulses and writing to file, will take a while. . .\n")
    pulses = otx.getall()
    print("Downloaded, writing. . .\n")
    with open('pulses.json', 'w', encoding='utf-8') as f:
        json.dump(pulses, f, ensure_ascii=False)
    with open('last_update.txt', 'w') as f:
        f.write(ctime())
    return pulses


def update_check():
    print("Checking for last update. . .")
    if os.path.exists('./last_update.txt'):      
        with open('last_update.txt', 'r') as f:
            print("Last update was {}\n".format(f.read()))
        update = input("Do you want to update the file (y/n)? ")
        if update == "y":
            pulses = download_pulses()
            with open('last_update.txt', 'w') as f:
                f.write(ctime())
            return pulses
        else:
            return
    else:
        print("Update file not found, creating one with current time. . .\n")
        with open('last_update.txt', 'w') as f:
            f.write(ctime())
        return

def plot_indicator_types(indicators): 

    print("Plotting indicators. . .")
    
    count_sum = pd.Series([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], index=['domain', 'hostname', 'FileHash-SHA1', 
                          'FileHash-SHA256', 'IPv4', 'IPv6', 'email', 'URL', 'URI', 'FileHash-MD5',
                          'FileHash-PEHASH', 'CIDR', 'FilePath', 'Mutex', 'CVE', 'FileHash-IMPHASH', 'YARA'])
    count_holder = pd.Series([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], index=['domain', 'hostname', 'FileHash-SHA1', 
                          'FileHash-SHA256', 'IPv4', 'IPv6', 'email', 'URL', 'URI', 'FileHash-MD5',
                          'FileHash-PEHASH', 'CIDR', 'FilePath', 'Mutex', 'CVE', 'FileHash-IMPHASH', 'YARA'])
    
    
    try:
        for dt in indicators:
            count = dt['type'].value_counts()
            count_holder = count_holder.add(count, fill_value=0)
            count_sum = count_sum.add(count_holder)
    except KeyError:
        pass

    print("Total:\n{}\n".format(count_sum))
    count_sum.plot.pie(figsize=(10, 10))
    plt.show()

    return


if __name__ == '__main__':
    main()
    

    
    
    

