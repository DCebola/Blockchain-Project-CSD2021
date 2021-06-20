import numpy as np
import matplotlib.pyplot as plt
import os

OBTAIN_COINS = 'OBTAIN_COINS_RESULTS'
TRANSFER_MONEY = 'TRANSFER_MONEY_RESULTS'
CLIENT_LEDGER = 'CLIENT_LEDGER_RESULTS'
GLOBAL_LEDGER = 'GLOBAL_LEDGER_RESULTS'
MINE = 'MINE_RESULTS'
TRANSFER_MONEY_WITH_PRIVACY = 'TRANSFER_MONEY_WITH_PRIVACY_RESULTS'
MINING_PROOF_OF_WORK = 'MINING_PROOF_OF_WORK_RESULTS'


def extract_mining_values(dir_results):
    results_x_y_latency_full = []
    results_x_y_throughput_full = []
    results_x_y_latency_proof = []
    results_x_y_throughput_proof = []

    for directory in os.listdir(dir_results):
        subdir = os.path.join(dir_results, directory)
        x_variable = float(directory.split('_')[1])
        total_time_full_op = 0
        total_time_proof_op = 0
        num_ops_full = 0
        num_ops_proof = 0
        for root, dir, files in os.walk(subdir):
            for file in files:
                file_dir = os.path.join(subdir, file)
                file_res = np.array(np.genfromtxt(file_dir, delimiter='\t', dtype='str'))
                mining_full_op = np.array(file_res[np.where(file_res[:, 0] == 'MINE_TRANSACTIONS')][:, 1]).astype(float)
                mining_proof_op = np.array(
                    file_res[np.where(file_res[:, 0] == 'MINE_TRANSACTIONS_PROOF_OF_WORK')][:, 1]).astype(float)
                total_time_proof_op = total_time_proof_op + np.sum(mining_proof_op)
                total_time_full_op = total_time_full_op + np.sum(mining_full_op)
                num_ops_proof = num_ops_proof + len(mining_proof_op)
                num_ops_full = num_ops_full + len(mining_full_op)
        avg_proof_ops = float(total_time_proof_op / num_ops_proof)
        throughput_proof_ops = float(num_ops_proof / total_time_proof_op)
        avg_full_ops = float(total_time_full_op / num_ops_full)
        throughput_full_ops = float(num_ops_full / total_time_full_op)

        results_x_y_latency_proof.append([x_variable, avg_proof_ops])
        results_x_y_throughput_proof.append(([x_variable, throughput_proof_ops]))

        results_x_y_latency_full.append([x_variable, avg_full_ops])
        results_x_y_throughput_full.append([x_variable, throughput_full_ops])

    res_latency_proof = np.array(results_x_y_latency_proof)
    res_latency_proof = res_latency_proof[res_latency_proof[:, 0].argsort()]
    res_throughput_proof = np.array(results_x_y_throughput_proof)
    res_throughput_proof = res_throughput_proof[res_throughput_proof[:, 0].argsort()]

    res_latency_full = np.array(results_x_y_latency_full)
    res_latency_full = res_latency_full[res_latency_full[:, 0].argsort()]
    res_throughput_full = np.array(results_x_y_throughput_full)
    res_throughput_full = res_throughput_full[res_throughput_full[:, 0].argsort()]

    return res_latency_proof, res_latency_full, res_throughput_proof, res_throughput_full


def mining_latency_throughput_plt():
    latency_proof, latency_full, throughput_proof, throughput_full = extract_mining_values(MINING_PROOF_OF_WORK)
    plt.xlabel("Size of blocks")
    plt.ylabel("Latency (ms)")
    plt.plot(latency_proof[:, 0], latency_proof[:, 1])
    plt.plot(latency_full[:, 0], latency_full[:, 1])
    plt.legend(["Proof", "Full op"])
    plt.savefig('mining_latency_size_block.png')
    plt.show()

    plt.xlabel("Size of blocks")
    plt.ylabel("Throughput (s)")
    plt.plot(throughput_proof[:, 0], throughput_proof[:, 1])
    plt.plot(throughput_full[:, 0], throughput_full[:, 1])
    plt.legend(["Proof", "Full op"])
    plt.savefig('mining_throughput_size_block.png')
    plt.show()


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
        avg = float(total_time / num_ops)
        throughput = float(num_ops / total_time)
        results_x_y_latency.append([x_variable, avg])
        results_x_y_throughput.append(([x_variable, throughput]))
        # print([x_variable, avg, total_time, throughput])

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


ops_latency_throughput_per_num_replicas()
mining_latency_throughput_plt()
