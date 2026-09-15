import networkx as nx
from community import community_louvain
from datetime import timedelta

def depcomm_group_logs(logs, time_window_seconds=60):
    n = len(logs)
    G = nx.Graph()
    for i in range(n):
        G.add_node(i)

    for i in range(n):
        for j in range(i + 1, n):
            log_i, log_j = logs[i], logs[j]
            ts_i, ts_j = log_i.get("ts"), log_j.get("ts")
            eid_i, eid_j = log_i.get("event_id"), log_j.get("event_id")

            # temporal link within default window
            if ts_i and ts_j:
                delta = abs((ts_i - ts_j).total_seconds())
                if delta > time_window_seconds:
                    continue  # skip far-apart logs

            # correlate by event id or process
            proc_i = log_i.get("process") or ""
            proc_j = log_j.get("process") or ""
            user_i = log_i.get("user") or ""
            user_j = log_j.get("user") or ""

            if eid_i == eid_j and eid_i is not None:
                G.add_edge(i, j)
            elif proc_i and proc_i == proc_j:
                G.add_edge(i, j)
            elif user_i and user_i == user_j:
                G.add_edge(i, j)
            elif ts_i and ts_j and abs((ts_i - ts_j).total_seconds()) < time_window_seconds:
                G.add_edge(i, j)

    # group correlated logs
    partition = community_louvain.best_partition(G)
    groups = {}
    for idx, group_id in partition.items():
        groups.setdefault(group_id, []).append(logs[idx])

    return list(groups.values())
