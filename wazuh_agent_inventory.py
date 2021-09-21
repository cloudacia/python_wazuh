import json
import requests
import urllib3
import pandas as pd
import subprocess
import os
from datetime import date
from requests.auth import HTTPBasicAuth


CONFIG_FILE = ""
DATE = date.today()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def open_config_file(arg1):
    """Open the configuration file where API's access credentials are stored."""
    filename = arg1
    file = open(filename, 'r')
    data_json = json.load(file)
    file.close()

    return data_json


data_auth = open_config_file(CONFIG_FILE)

WAZUH_API_USER = ""
WAZUH_API_PASSWORD = ""
WAZUH_API_URL = ""
WAZUH_API_ENDPOINT = "agents"

FOREMAN_USER = ""
FOREMAN_PASSWORD = ""
FOREMAN_URL = ""
FOREMAN_ENDPOINT = ""

PPT_FOREMAN_USER = ""
PPT_FOREMAN_PASSWORD = ""
PPT_FOREMAN_URL = ""
PPT_FOREMAN_ENDPOINT = ""

PROVISION_1_USER = ""
PROVISION_1_PASSWORD = ""
PROVISION_1_URL = ""
PROVISION_1_ENDPOINT = ""


def get_hosts(arg1, arg2, arg3, arg4):
    """Get the list of servers registered on the Foreman system."""
    target_api = arg1
    end_point = arg2
    username = arg3
    password = arg4
    hosts_list = list()
    response = requests.get(target_api+end_point,
                            auth=HTTPBasicAuth(
                                username,
                                password),
                            verify=False
                            )

    json_response = response.json()
    json_results = json_response['results']
    for host in json_results:
        name = host['name']
        hosts_list.append(name)
    return hosts_list


def get_agents(arg1, arg2, arg3, arg4):
    """Get the list of agents registered on the Wazuh Manager."""
    target_api = arg1
    end_point = arg2
    username = arg3
    password = arg4
    item_list = list()
    response = requests.get(target_api+"/"+end_point,
                            auth=HTTPBasicAuth(
                                username,
                                password),
                            verify=False
                            )

    json_response = response.json()
    agent_list = json_response['data']['items']

    for agent in agent_list:
        name = agent['name']
        item_list.append(name)
    return item_list


def get_exceptions(lst1, lst2):
    """Return the host where agents are not registered on the Wazuh Manager."""
    agents_list = lst1
    hosts_list = lst2
    item_list = list()
    for h in hosts_list:
        if h not in agents_list:
            item_list.append(h)
        else:
            continue
    return item_list


def save_to_csv(arg1):
    """Save the data into a CSV file."""
    dataframe = arg1
    output = subprocess.run(['pwd'], stdout=subprocess.PIPE, check=True)
    output = output.stdout.decode('utf-8')
    output = output.replace('\n', '')
    string = output + '/' + 'wazuh_agents_report_{0}.csv'.format(DATE)
    string = string.replace('-', '_')
    string = string.replace('.', '_')
    os.chdir(output)
    dataframe.to_csv(string)


if __name__ == "__main__":
    print('Fetching the list of servers registered in {0}'.format(
                                                                FOREMAN_URL
                                                                ))
    foreman_hosts = get_hosts(FOREMAN_URL,
                              FOREMAN_ENDPOINT,
                              FOREMAN_USER,
                              FOREMAN_PASSWORD)

    print('Fetching the list of servers registered in {0}'.format(
                                                                PPT_FOREMAN_URL
                                                                ))
    ppt_foreman_hosts = get_hosts(PPT_FOREMAN_URL,
                                  PPT_FOREMAN_ENDPOINT,
                                  PPT_FOREMAN_USER,
                                  PPT_FOREMAN_PASSWORD)

    print('Fetching the list of servers registered in {0}'.format(
                                                                PROVISION_1_URL
                                                                ))
    provision_1_hosts = get_hosts(PROVISION_1_URL,
                                  PROVISION_1_ENDPOINT,
                                  PROVISION_1_USER,
                                  PROVISION_1_PASSWORD)

    print('Fetching the list of agents registered in {0}'.format(
                                                                WAZUH_API_URL
                                                                ))
    wazuh_agents = get_agents(WAZUH_API_URL,
                              WAZUH_API_ENDPOINT,
                              WAZUH_API_USER,
                              WAZUH_API_PASSWORD)

    exception_list = list()

    foreman_exceptions = get_exceptions(wazuh_agents, foreman_hosts)
    if not foreman_exceptions:
        print('No exception found in {0}'.format(FOREMAN_URL))
    else:
        foreman_df = pd.DataFrame({FOREMAN_URL: foreman_exceptions})
        exception_list.append(foreman_df)

    ppt_foreman_exceptions = get_exceptions(wazuh_agents, ppt_foreman_hosts)
    if not ppt_foreman_exceptions:
        print('No exception found in {0}'.format(PPT_FOREMAN_URL))
    else:
        ppt_foreman_df = pd.DataFrame({PPT_FOREMAN_URL: ppt_foreman_exceptions})
        exception_list.append(ppt_foreman_df)

    provision_1_exceptions = get_exceptions(wazuh_agents, provision_1_hosts)
    if not provision_1_exceptions:
        print('No exception found in {0}'.format(PROVISION_1_URL))
    else:
        provision_1_df = pd.DataFrame({PROVISION_1_URL: provision_1_exceptions})
        exception_list.append(provision_1_df)

    if not exception_list:
        print('No exception found')
        exit(0)
    else:
        final_df = pd.concat(exception_list)
        final_df = final_df.reset_index(drop=True)
        print('Generating report in CSV formart...')
        save_to_csv(final_df)
        print(final_df)
