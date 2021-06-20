import numpy as np
import matplotlib.pyplot as plt
import os

OBTAIN_COINS = 'OBTAIN_COINS_RESULTS'
TRANSFER_MONEY = 'TRANSFER_MONEY_RESULTS'
CLIENT_LEDGER = 'CLIENT_LEDGER_RESULTS'
GLOBAL_LEDGER = 'GLOBAL_LEDGER_RESULTS'
MINE = 'MINE_RESULTS'
TRANSFER_MONEY_WITH_PRIVACY = 'TRANSFER_MONEY_WITH_PRIVACY_RESULTS'
MINING_FULL_OPERATION = 'MINING_FULL_OPERATION_RESULTS'
MINING_PROOF_OF_WORK = 'MINING_PROOF_OF_WORK_RESULTS'


# OBTAIN_USER_NOT_SUBMITTED_TRANSACTIONS = 'OBTAIN_USER_NOT_SUBMITTED_TRANSACTIONS_RESULTS'


def extract_values(dir_results):
    results_x_y_latency = []
    results_x_y_throughput = []
    res = []
    for directory in os.listdir(dir_results):
        subdir = os.path.join(dir_results, directory)
        x_variable = float(directory.split('_')[1])
        total_time = 0
        num_ops = 0
        for root, dir, files in os.walk(subdir):
            for file in files:
                file_dir = os.path.join(subdir, file)
                times = np.array(np.genfromtxt(file_dir, delimiter='\t', dtype='str')[:, 1]).astype(float)
                total_time = total_time + np.sum(times)
                num_ops = num_ops + len(times)
        avg = float(total_time) / float(num_ops)
        throughput = float(num_ops)/float(total_time)
        results_x_y_latency.append([x_variable, avg])
        results_x_y_throughput.append(([x_variable, throughput]))
        #print([x_variable, avg, total_time, throughput])

    res_latency = np.array(results_x_y_latency)
    res_latency = res_latency[res_latency[:, 0].argsort()]
    res_throughput = np.array(results_x_y_throughput)
    res_throughput = res_throughput[res_throughput[:, 0].argsort()]

    return res_latency, res_throughput


def ops_latency_throughput_per_num_replicas():
    obtain_coins_latency, obtain_coins_throughput = extract_values(OBTAIN_COINS)
    transfer_money_latency, transfer_money_throughput = extract_values(TRANSFER_MONEY)
    client_ledger_latency, client_ledger_throughput = extract_values(CLIENT_LEDGER)
    global_ledger_latency, global_ledger_throughput = extract_values(GLOBAL_LEDGER)
    mine_latency, mine_throughput = extract_values(MINE)
    transfer_money_with_privacy_latency, transfer_money_with_privacy_throughput = extract_values(
        TRANSFER_MONEY_WITH_PRIVACY)
    plt.xlabel("Number of Replicas")
    plt.ylabel("Latency (ms)")
    plt.plot(obtain_coins_latency[:, 0], obtain_coins_latency[:, 1])
    plt.plot(transfer_money_latency[:, 0], transfer_money_latency[:, 1])
    plt.plot(client_ledger_latency[:, 0], client_ledger_latency[:, 1])
    plt.plot(global_ledger_latency[:, 0], global_ledger_latency[:, 1])
    plt.plot(mine_latency[:, 0], mine_latency[:, 1])
    plt.plot(transfer_money_with_privacy_latency[:, 0], transfer_money_with_privacy_latency[:, 1])
    plt.legend(["OBTAIN_COINS", "TRANSFER_MONEY", "CLIENT_LEDGER", "GLOBAL_LEDGER", "MINE"])
    plt.savefig('ops_latency_num_replicas.png')
    plt.show()

    plt.xlabel("Number of Replicas")
    plt.ylabel("Throughput (ms)")
    plt.plot(obtain_coins_throughput[:, 0], obtain_coins_throughput[:, 1])
    plt.plot(transfer_money_throughput[:, 0], transfer_money_throughput[:, 1])
    plt.plot(client_ledger_throughput[:, 0], client_ledger_throughput[:, 1])
    plt.plot(global_ledger_throughput[:, 0], global_ledger_throughput[:, 1])
    plt.plot(mine_throughput[:, 0], mine_throughput[:, 1])
    plt.plot(transfer_money_with_privacy_throughput[:, 0], transfer_money_with_privacy_throughput[:, 1])
    plt.legend(["OBTAIN_COINS", "TRANSFER_MONEY", "CLIENT_LEDGER", "GLOBAL_LEDGER", "MINE"])
    plt.savefig('ops_throughput_num_replicas.png')
    plt.show()


def mining_latency_throughput_plt():  # varying number of transactions in block and analysing mining time and full operation time
    mining_proof_of_work_latency, mining_proof_of_work_throughput = extract_values(MINING_PROOF_OF_WORK)
    mining_full_operation_latency, mining_full_operation_throughput, = extract_values(MINING_FULL_OPERATION)
    plt.xlabel("Size of block")
    plt.ylabel("Latency (ms)")
    plt.plot(mining_proof_of_work_latency[:, 0], mining_proof_of_work_latency[:, 1])
    plt.plot(mining_full_operation_latency[:, 0], mining_full_operation_latency[:, 1])
    plt.legend(["mining_proof_of_work_latency", "mining_full_operation_latency"])
    plt.savefig('mining_latency_per_block_size.png')
    plt.show()

    plt.xlabel("Size of block")
    plt.ylabel("Throughput (ops/s)")
    plt.plot(mining_proof_of_work_throughput[:, 0], mining_proof_of_work_throughput[:, 1])
    plt.plot(mining_full_operation_throughput[:, 0], mining_full_operation_throughput[:, 1])
    plt.legend(["mining_proof_of_work_throughput", "mining_full_operation_throughput"])
    plt.savefig('mining_throughput_per_block_size.png')
    #plt.plot(obtain_user_not_submitted_transactions[:, 0], obtain_user_not_submitted_transactions[:, 1])
    plt.show()


#ops_latency_throughput_per_num_replicas()
mining_latency_throughput_plt()
