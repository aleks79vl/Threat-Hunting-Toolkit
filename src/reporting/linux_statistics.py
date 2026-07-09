from collections import Counter


def generate_linux_statistics(events: list) -> dict:
    action_counter = Counter()
    status_counter = Counter()
    user_counter = Counter()
    source_ip_counter = Counter()

    for event in events:
        if event.action:
            action_counter[event.action] += 1

        if event.status:
            status_counter[event.status] += 1

        if event.user:
            user_counter[event.user] += 1

        if event.source_ip:
            source_ip_counter[event.source_ip] += 1

    return {
        "total_events": len(events),
        "actions": dict(action_counter),
        "statuses": dict(status_counter),
        "users": dict(user_counter),
        "source_ips": dict(source_ip_counter),
    }