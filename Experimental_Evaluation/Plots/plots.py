import numpy as np
import matplotlib.pyplot as plt
import os

OBTAIN_COINS = 'OBTAIN_COINS_RESULTS'
TRANSFER_MONEY = 'TRANSFER_MONEY_RESULTS'
CLIENT_LEDGER = 'CLIENT_LEDGER_RESULTS'
GLOBAL_LEDGER = 'GLOBAL_LEDGER_RESULTS'
MINE = 'MINE_RESULTS'
TRANSFER_MONEY_WITH_PRIVACY = 'TRANSFER_MONEY_WITH_PRIVACY_RESULTS'


# OBTAIN_USER_NOT_SUBMITTED_TRANSACTIONS = 'OBTAIN_USER_NOT_SUBMITTED_TRANSACTIONS_RESULTS'


def extract_values(dir_results):
    results_replica = []
    for directory in os.listdir(dir_results):
        subdir = os.path.join(dir_results, directory)
        replica = float(directory.split('_')[1])
        sum_results = 0
        size = 0
        for root, dir, files in os.walk(subdir):
            for file in files:
                file_dir = os.path.join(subdir, file)
                times = np.array(np.genfromtxt(file_dir, delimiter='\t', dtype='str')[:, 1]).astype(float)
                sum_results = sum_results + np.sum(times)
                size = size + len(times)
        avg = float(sum_results / size)
        results_replica.append([replica, avg])
    res = np.array(results_replica)
    res.sort(axis=0)
    return res


def ops_latency_per_num_replicas():

    obtain_coins = extract_values(OBTAIN_COINS)
    transfer_money = extract_values(TRANSFER_MONEY)
    client_ledger = extract_values(GLOBAL_LEDGER)
    global_ledger = extract_values(CLIENT_LEDGER)
    mine = extract_values(MINE)
    transfer_money_with_privacy = extract_values(TRANSFER_MONEY_WITH_PRIVACY)
    # obtain_user_not_submitted_transactions = extract_values(OBTAIN_USER_NOT_SUBMITTED_TRANSACTIONS)
    plt.xlabel("Number of Replicas")
    plt.ylabel("Latency (ms)")
    plt.plot(obtain_coins[:, 0], obtain_coins[:, 1])
    plt.plot(transfer_money[:, 0], transfer_money[:, 1])
    plt.plot(client_ledger[:, 0], client_ledger[:, 1])
    plt.plot(global_ledger[:, 0], global_ledger[:, 1])
    plt.plot(mine[:, 0], mine[:, 1])
    plt.legend(["OBTAIN_COINS", "TRANSFER_MONEY", "GLOBAL_LEDGER", "CLIENT_LEDGER", "MINE"])
    plt.savefig('ops_latency_num_replicas.png')
    # plt.plot(obtain_user_not_submitted_transactions[:, 0], obtain_user_not_submitted_transactions[:, 1])
    plt.show()


ops_latency_per_num_replicas()
